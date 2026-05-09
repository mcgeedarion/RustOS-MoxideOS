//! Pipe subsystem — pipe(2) / pipe2(2) and the backing ring-buffer object.
//!
//! ## Architecture
//!
//! Each pipe is a 64 KiB ring buffer stored behind an
//! `Arc<Mutex<PipeInner>>`.  Both ends (read fd and write fd) hold a clone
//! of the same Arc, so they share one buffer regardless of which process
//! holds which end after a fork.
//!
//! Backing fd numbers are allocated from a reserved range starting at
//! `PIPE_FD_BASE` (0x8000_0000).  This keeps them well clear of VFS fds,
//! devfs fds, and socket fds, so `is_pipe(bfd)` is a single range check.
//!
//! ## Backing-fd lifetime
//!
//! Two bfds are allocated per pipe: an even one (read end) and an odd one
//! (write end = read_bfd + 1).  Both are keys in PIPE_TABLE pointing at the
//! *same* Arc<Mutex<PipeInner>>.  Closing one end removes only *that* key;
//! the peer's key (and Arc clone) stays until the peer is closed.  The
//! PipeInner is freed when the last Arc clone is dropped, i.e. when both
//! ends have been closed by all holders.
//!
//! ## Refcounting (dup / fork)
//!
//! PipeInner.read_open / write_open count how many process-local fds point
//! at each end across all processes.  `pipe_dup(bfd)` increments the
//! appropriate counter; `sys_close_pipe(bfd)` decrements it.  When
//! write_open reaches zero the read end sees EOF; when read_open reaches
//! zero the write end receives SIGPIPE.
//!
//! ## Blocking
//!
//! Blocking reads/writes spin-yield until data/space is available or the
//! peer closes its end.  A TODO marks the spot to replace this with a
//! proper wait-queue once the scheduler exposes one.
//!
//! ## POSIX guarantees
//!
//! - Writes ≤ PIPE_BUF (4096) are atomic: the mutex is held for the
//!   entire write so no other writer can interleave.
//! - `pipe_write` delivers SIGPIPE + returns -EPIPE when all readers
//!   have closed.
//! - `pipe_read` returns 0 (EOF) when all writers have closed and the
//!   buffer is empty.
//! - `pipe2` honours O_CLOEXEC and O_NONBLOCK.

extern crate alloc;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use spin::Mutex;
use core::sync::atomic::{AtomicUsize, Ordering};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Capacity of every pipe's ring buffer (bytes).
pub const PIPE_BUF_SIZE: usize = 65536;

/// Atomic write-size guarantee (POSIX PIPE_BUF).
pub const PIPE_BUF: usize = 4096;

/// Backing fd range reserved for pipe ends.  Read end = even, write end = odd.
/// 0x8000_0000 is far above any VFS / devfs / socket fd.
const PIPE_FD_BASE: usize = 0x8000_0000;

/// Linux errno values used internally.
const EAGAIN: isize = -11;
const EPIPE:  isize = -32;
const EFAULT: isize = -14;
const EMFILE: isize = -24;

/// SIGPIPE signal number.
const SIGPIPE: u32 = 13;

// ── Ring-buffer ───────────────────────────────────────────────────────────────

struct PipeInner {
    buf:         alloc::vec::Vec<u8>,
    head:        usize,   // next read position
    len:         usize,   // bytes currently in the buffer
    write_open:  u32,     // number of open write-end fds (>0 means writers exist)
    read_open:   u32,     // number of open read-end fds  (>0 means readers exist)
    nonblocking: bool,    // O_NONBLOCK set on either end
}

impl PipeInner {
    fn new(nonblocking: bool) -> Self {
        PipeInner {
            buf: alloc::vec![0u8; PIPE_BUF_SIZE],
            head: 0,
            len: 0,
            write_open: 1,
            read_open: 1,
            nonblocking,
        }
    }

    #[inline] fn capacity(&self) -> usize { self.buf.len() }
    #[inline] fn space(&self)    -> usize { self.capacity() - self.len }
    #[inline] fn is_empty(&self) -> bool  { self.len == 0 }
    #[inline] fn is_full(&self)  -> bool  { self.len == self.capacity() }

    /// Copy up to `dst.len()` bytes out of the ring, returning how many were read.
    fn read_bytes(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.len);
        for i in 0..n {
            dst[i] = self.buf[(self.head + i) % self.capacity()];
        }
        self.head = (self.head + n) % self.capacity();
        self.len  -= n;
        n
    }

    /// Copy `src` into the ring.  Caller must ensure `src.len() <= self.space()`.
    fn write_bytes(&mut self, src: &[u8]) {
        let cap  = self.capacity();
        let tail = (self.head + self.len) % cap;
        for (i, &b) in src.iter().enumerate() {
            self.buf[(tail + i) % cap] = b;
        }
        self.len += src.len();
    }
}

// ── Pipe table: backing_fd → Arc<Mutex<PipeInner>> ───────────────────────────
//
// Both the read end (even fd) and the write end (odd fd = read_fd + 1)
// resolve to the *same* Arc.  We store one entry per end so that
// `is_pipe(bfd)` is just a BTreeMap lookup.

struct PipeTable {
    map: BTreeMap<usize, Arc<Mutex<PipeInner>>>,
}

impl PipeTable {
    const fn new() -> Self { PipeTable { map: BTreeMap::new() } }
    fn get(&self, bfd: usize) -> Option<Arc<Mutex<PipeInner>>> {
        self.map.get(&bfd).cloned()
    }
    fn insert(&mut self, bfd: usize, pipe: Arc<Mutex<PipeInner>>) {
        self.map.insert(bfd, pipe);
    }
    fn remove(&mut self, bfd: usize) -> bool {
        self.map.remove(&bfd).is_some()
    }
    fn contains(&self, bfd: usize) -> bool {
        self.map.contains_key(&bfd)
    }
}

static PIPE_TABLE: Mutex<PipeTable> = Mutex::new(PipeTable::new());

/// Monotonically increasing counter.  Each call to `alloc_pipe_fds` bumps
/// it by 2 (one pair).  Values are offsets from PIPE_FD_BASE.
static NEXT_PIPE_FD: AtomicUsize = AtomicUsize::new(0);

/// Allocate a (read_bfd, write_bfd) pair from the pipe backing-fd namespace.
fn alloc_pipe_fds() -> (usize, usize) {
    let off = NEXT_PIPE_FD.fetch_add(2, Ordering::Relaxed);
    let read_bfd  = PIPE_FD_BASE + off;
    let write_bfd = PIPE_FD_BASE + off + 1;
    (read_bfd, write_bfd)
}

// ── Public predicate ──────────────────────────────────────────────────────────

/// Return `true` if `bfd` is a pipe backing fd (either read or write end).
#[inline]
pub fn is_pipe(bfd: usize) -> bool {
    // Fast path: all pipe bfds are >= PIPE_FD_BASE.
    if bfd < PIPE_FD_BASE { return false; }
    PIPE_TABLE.lock().contains(bfd)
}

// ── Dup ──────────────────────────────────────────────────────────────────────

/// Called by `sys_dup`, `sys_dup2`, and the fork fd-table copy whenever a
/// pipe-end fd is duplicated or inherited into a new process.
///
/// Increments `read_open` (even bfd = read end) or `write_open` (odd bfd =
/// write end) in the shared `PipeInner` so that the last `close()` of *any*
/// fd pointing at that end is what finally signals EOF or SIGPIPE to the peer.
///
/// A no-op if `bfd` is not in the pipe table (safe to call unconditionally).
pub fn pipe_dup(bfd: usize) {
    if bfd < PIPE_FD_BASE { return; }
    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None    => return,
    };
    let mut inner = pipe.lock();
    if bfd & 1 == 0 {
        inner.read_open  = inner.read_open.saturating_add(1);
    } else {
        inner.write_open = inner.write_open.saturating_add(1);
    }
}

// ── Read / write ──────────────────────────────────────────────────────────────

/// Read up to `buf.len()` bytes from the read end of a pipe.
///
/// Blocking behaviour:
///   - If the buffer is empty and writers exist → yield-loop until data arrives.
///   - If the buffer is empty and all writers are closed → return 0 (EOF).
///   - O_NONBLOCK + empty buffer → return -EAGAIN.
///
/// `bfd` must be the *read* end (even fd).  Passing the write end returns
/// -EBADF (-9).
pub fn pipe_read(bfd: usize, buf: &mut [u8]) -> isize {
    if buf.is_empty() { return 0; }

    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None    => return -9, // EBADF
    };

    // Read end is even; write end is odd.
    if bfd & 1 != 0 { return -9; } // wrong end

    loop {
        {
            let mut inner = pipe.lock();
            if !inner.is_empty() {
                let n = inner.read_bytes(buf);
                return n as isize;
            }
            // Buffer empty.
            if inner.write_open == 0 {
                // All writers gone — EOF.
                return 0;
            }
            if inner.nonblocking {
                return EAGAIN;
            }
        }
        // TODO: block on a wait-queue; for now yield-spin.
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

/// Write `buf` to the write end of a pipe.
///
/// Blocking behaviour:
///   - If the buffer is full and readers exist → yield-loop.
///   - If all readers are closed → deliver SIGPIPE + return -EPIPE.
///   - O_NONBLOCK + full buffer → return -EAGAIN.
///
/// Writes ≤ PIPE_BUF are atomic (the mutex is held for the full write).
/// Writes > PIPE_BUF may be split across multiple lock acquisitions.
pub fn pipe_write(bfd: usize, buf: &[u8]) -> isize {
    if buf.is_empty() { return 0; }

    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None    => return -9, // EBADF
    };

    // Write end is odd.
    if bfd & 1 == 0 { return -9; } // wrong end

    let pid = crate::proc::scheduler::current_pid();
    let mut written = 0usize;
    let mut remaining = buf;

    while !remaining.is_empty() {
        // For writes ≤ PIPE_BUF we must not split — hold the lock the whole time.
        let atomic = remaining.len() <= PIPE_BUF;

        loop {
            {
                let mut inner = pipe.lock();

                if inner.read_open == 0 {
                    // Broken pipe.
                    crate::proc::signal::send_signal(pid, SIGPIPE);
                    return if written == 0 { EPIPE } else { written as isize };
                }

                let space = inner.space();
                if space == 0 {
                    if inner.nonblocking {
                        return if written == 0 { EAGAIN } else { written as isize };
                    }
                    // Release lock and yield.
                } else if atomic {
                    // Entire chunk fits (or we wait until it does).
                    if space >= remaining.len() {
                        inner.write_bytes(remaining);
                        written += remaining.len();
                        remaining = &[];
                        break;
                    }
                    // Not enough space yet — yield and retry.
                } else {
                    // Non-atomic: write as much as fits now.
                    let chunk = remaining.len().min(space);
                    inner.write_bytes(&remaining[..chunk]);
                    written    += chunk;
                    remaining   = &remaining[chunk..];
                    break; // re-enter outer loop for the rest
                }
            }
            // Yield while holding nothing.
            crate::proc::scheduler::schedule();
            core::hint::spin_loop();
        }
    }

    written as isize
}

// ── Close ─────────────────────────────────────────────────────────────────────

/// Called by `close_backing` when a pipe-end fd is closed.
///
/// ## What this does
///
/// 1. Decrements `read_open` or `write_open` in the shared `PipeInner`.
/// 2. Removes only *this* bfd's entry from `PIPE_TABLE`, so the bfd can no
///    longer be used for reads/writes.
/// 3. The peer bfd's entry remains intact.  The peer's Arc clone of PipeInner
///    keeps the buffer alive; the peer will see EOF (read end) or SIGPIPE
///    (write end) only once the relevant refcount reaches zero.
/// 4. The PipeInner (and its 64 KiB buffer) is freed only when the last Arc
///    clone is dropped, i.e. when both bfd entries have been removed.
///
/// This is a no-op if `bfd` is not in the table.
pub fn sys_close_pipe(bfd: usize) {
    // Clone the Arc out of the table under the table lock, then drop the
    // table lock before taking the inner lock to avoid lock-order issues.
    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None    => return,
    };

    // Decrement the refcount for this end.
    {
        let mut inner = pipe.lock();
        if bfd & 1 == 0 {
            // Read end.
            inner.read_open = inner.read_open.saturating_sub(1);
        } else {
            // Write end.
            inner.write_open = inner.write_open.saturating_sub(1);
        }
    }

    // Remove only this end's entry from the table.
    // The peer's entry (and Arc clone) stays until the peer is closed.
    PIPE_TABLE.lock().remove(bfd);

    // `pipe` (the local Arc clone obtained above) is dropped here.
    // If this was the last clone (strong_count goes to 0), PipeInner is freed.
    // Otherwise the peer's clone keeps it alive.
}

// ── sys_pipe / sys_pipe2 ──────────────────────────────────────────────────────

/// Create a pipe and return the read/write fd pair in the array at `pipefd_va`.
///
/// `pipefd_va` must point to a user-space `int[2]`:  pipefd[0] = read end,
/// pipefd[1] = write end.
///
/// NR 22.
pub fn sys_pipe(pipefd_va: usize) -> isize {
    sys_pipe2(pipefd_va, 0)
}

/// Like `sys_pipe` but honours `flags`:
///   O_CLOEXEC  (0o2000000) — set FD_CLOEXEC on both ends.
///   O_NONBLOCK (0o4000)    — set O_NONBLOCK on both ends.
///   O_DIRECT   (0o40000)   — accepted but treated as advisory (ring buf is
///                            already in-kernel, so O_DIRECT has no meaning).
///
/// NR 293.
pub fn sys_pipe2(pipefd_va: usize, flags: u32) -> isize {
    use crate::uaccess::{copy_to_user, validate_user_ptr};
    use crate::fs::process_fd::proc_fd_install;

    const O_CLOEXEC:  u32 = 0o2000000;
    const O_NONBLOCK: u32 = 0o4000;
    const EINVAL: isize   = -22;

    if flags & !(O_CLOEXEC | O_NONBLOCK | 0o40000) != 0 {
        return EINVAL;
    }
    if !validate_user_ptr(pipefd_va, 8) { return EFAULT; }

    let nonblocking = flags & O_NONBLOCK != 0;
    let cloexec     = flags & O_CLOEXEC  != 0;

    // Allocate the shared pipe object.
    let pipe = Arc::new(Mutex::new(PipeInner::new(nonblocking)));

    // Allocate two backing fds.
    let (read_bfd, write_bfd) = alloc_pipe_fds();

    // Register both ends — they share the *same* Arc.
    {
        let mut tbl = PIPE_TABLE.lock();
        tbl.insert(read_bfd,  Arc::clone(&pipe));
        tbl.insert(write_bfd, Arc::clone(&pipe));
    }

    // Install into the process fd table.
    let pid = crate::proc::scheduler::current_pid();

    // Read end: O_RDONLY (0).  Write end: O_WRONLY (1).
    let rd_flags = if cloexec { O_CLOEXEC } else { 0 };
    let wr_flags = 1 | if cloexec { O_CLOEXEC } else { 0 };

    // Check RLIMIT_NOFILE before installing.
    {
        use crate::fs::process_fd::proc_fd_list;
        let open_count = proc_fd_list(pid).len();
        let (soft, _) = crate::proc::rlimit::getrlimit_for(pid, 7 /* RLIMIT_NOFILE */);
        if (open_count + 2) as u64 > soft {
            // Roll back pipe table entries.
            PIPE_TABLE.lock().remove(read_bfd);
            PIPE_TABLE.lock().remove(write_bfd);
            return EMFILE;
        }
    }

    let read_fd  = proc_fd_install(pid, read_bfd,  None, rd_flags, None);
    let write_fd = proc_fd_install(pid, write_bfd, None, wr_flags, None);

    // Write [read_fd, write_fd] to user-space pipefd[2].
    let pair: [i32; 2] = [read_fd as i32, write_fd as i32];
    let bytes: [u8; 8] = unsafe { core::mem::transmute(pair) };
    if copy_to_user(pipefd_va, &bytes).is_err() {
        // Clean up the fds we just installed.
        crate::fs::process_fd::proc_fd_close(pid, read_fd);
        crate::fs::process_fd::proc_fd_close(pid, write_fd);
        return EFAULT;
    }

    0
}
