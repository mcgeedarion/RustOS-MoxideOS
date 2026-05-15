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
//! ## Scheme integration
//!
//! `sys_pipe2` now allocates scheme backing fds via `alloc_scheme_backing_fd`
//! and registers a `PipeScheme` instance for each end in `SCHEME_FD_STORE`.
//! This means pipe fds flow through the same `scheme_fd_read` / `scheme_fd_write`
//! / `scheme_fd_close` dispatch as every other scheme resource, giving splice,
//! io_uring, and epoll unified access without any special-casing.
//!
//! The raw `PIPE_TABLE` is still populated for the poll/epoll readiness path
//! (`is_pipe`, `is_pipe_fd`, `pipe_poll`) which keys off the pipe-range bfd.
//! `PipeScheme` reconstructs the ring-buffer bfd from its `SchemeFileId` on
//! every I/O call, so no additional global state is required.
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
//!
//! ## Poll / select / epoll readiness
//!
//! `is_pipe_fd(user_fd)` and `pipe_poll(user_fd, events)` are the two
//! functions called by `poll::fd_ready`.  They translate the user-visible fd
//! to a backing fd via the per-process fd table before inspecting PipeInner.
//!
//! Readiness semantics (matching Linux pipe(7)):
//!
//! | End        | POLLIN ready when                         |
//! |------------|-------------------------------------------|
//! | read end   | len > 0  (data available)                 |
//! | read end   | write_open == 0  → POLLHUP (+ POLLIN)     |
//!
//! | End        | POLLOUT ready when                        |
//! |------------|-------------------------------------------|
//! | write end  | space() > 0  (room to write)              |
//! | write end  | read_open == 0  → POLLERR  (broken pipe)  |

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::fs::scheme_table::Scheme;
use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Capacity of every pipe's ring buffer (bytes).
pub const PIPE_BUF_SIZE: usize = 65536;

/// Atomic write-size guarantee (POSIX PIPE_BUF).
pub const PIPE_BUF: usize = 4096;

/// Backing fd range reserved for pipe ends.  Read end = even, write end = odd.
/// 0x8000_0000 is far above any VFS / devfs / socket fd.
pub(crate) const PIPE_FD_BASE: usize = 0x8000_0000;

/// Linux errno values used internally.
const EAGAIN: isize = -11;
const EPIPE: isize = -32;
const EFAULT: isize = -14;
const EMFILE: isize = -24;

/// SIGPIPE signal number.
const SIGPIPE: u32 = 13;

// ── Ring-buffer ───────────────────────────────────────────────────────────────

struct PipeInner {
    buf: alloc::vec::Vec<u8>,
    head: usize,       // next read position
    len: usize,        // bytes currently in the buffer
    write_open: u32,   // number of open write-end fds (>0 means writers exist)
    read_open: u32,    // number of open read-end fds  (>0 means readers exist)
    nonblocking: bool, // O_NONBLOCK set on either end
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

    #[inline]
    fn capacity(&self) -> usize {
        self.buf.len()
    }
    #[inline]
    fn space(&self) -> usize {
        self.capacity() - self.len
    }
    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[inline]
    fn is_full(&self) -> bool {
        self.len == self.capacity()
    }

    /// Copy up to `dst.len()` bytes out of the ring, returning how many were read.
    fn read_bytes(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.len);
        for i in 0..n {
            dst[i] = self.buf[(self.head + i) % self.capacity()];
        }
        self.head = (self.head + n) % self.capacity();
        self.len -= n;
        n
    }

    /// Copy `src` into the ring.  Caller must ensure `src.len() <= self.space()`.
    fn write_bytes(&mut self, src: &[u8]) {
        let cap = self.capacity();
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
    const fn new() -> Self {
        PipeTable {
            map: BTreeMap::new(),
        }
    }
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
    let read_bfd = PIPE_FD_BASE + off;
    let write_bfd = PIPE_FD_BASE + off + 1;
    (read_bfd, write_bfd)
}

// ── Public predicates ─────────────────────────────────────────────────────────

/// Return `true` if `bfd` is a pipe backing fd (either read or write end).
#[inline]
pub fn is_pipe(bfd: usize) -> bool {
    if bfd < PIPE_FD_BASE {
        return false;
    }
    PIPE_TABLE.lock().contains(bfd)
}

/// Return `true` if the **user-visible** fd `user_fd` (for the calling
/// process) resolves to a pipe backing fd.
///
/// Called by `poll::fd_ready` to route the fd to `pipe_poll`.
pub fn is_pipe_fd(user_fd: usize) -> bool {
    let pid = crate::proc::scheduler::current_pid();
    let bfd = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if bfd < 0 {
        return false;
    }
    is_pipe(bfd as usize)
}

// ── Poll / select / epoll readiness ──────────────────────────────────────────

/// Return the subset of `events` that are currently ready on the pipe end
/// identified by the **user-visible** fd `user_fd`.
pub fn pipe_poll(user_fd: usize, events: u32) -> u32 {
    use crate::fs::poll::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLRDNORM, POLLWRNORM};

    let pid = crate::proc::scheduler::current_pid();
    let bfd_raw = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if bfd_raw < 0 {
        return POLLNVAL;
    }
    let bfd = bfd_raw as usize;

    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None => return POLLNVAL,
    };
    let inner = pipe.lock();

    let is_write_end = bfd & 1 != 0;

    if is_write_end {
        let mut ready = 0u32;
        if inner.read_open == 0 {
            ready |= POLLERR;
        }
        if events & (POLLOUT | POLLWRNORM) != 0 && inner.space() > 0 {
            ready |= POLLOUT | POLLWRNORM;
        }
        ready
    } else {
        let mut ready = 0u32;
        if inner.write_open == 0 {
            ready |= POLLHUP;
            ready |= POLLIN | POLLRDNORM;
        }
        if events & (POLLIN | POLLRDNORM) != 0 && inner.len > 0 {
            ready |= POLLIN | POLLRDNORM;
        }
        ready
    }
}

// ── Dup ──────────────────────────────────────────────────────────────────────

/// Called by `sys_dup`, `sys_dup2`, and the fork fd-table copy whenever a
/// pipe-end fd is duplicated or inherited into a new process.
pub fn pipe_dup(bfd: usize) {
    if bfd < PIPE_FD_BASE {
        return;
    }
    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None => return,
    };
    let mut inner = pipe.lock();
    if bfd & 1 == 0 {
        inner.read_open = inner.read_open.saturating_add(1);
    } else {
        inner.write_open = inner.write_open.saturating_add(1);
    }
}

// ── Read / write ──────────────────────────────────────────────────────────────

/// Read up to `buf.len()` bytes from the read end of a pipe.
pub fn pipe_read(bfd: usize, buf: &mut [u8]) -> isize {
    if buf.is_empty() {
        return 0;
    }

    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None => return -9, // EBADF
    };

    if bfd & 1 != 0 {
        return -9;
    } // wrong end

    loop {
        {
            let mut inner = pipe.lock();
            if !inner.is_empty() {
                let n = inner.read_bytes(buf);
                return n as isize;
            }
            if inner.write_open == 0 {
                return 0; // EOF
            }
            if inner.nonblocking {
                return EAGAIN;
            }
        }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

/// Write `buf` to the write end of a pipe.
pub fn pipe_write(bfd: usize, buf: &[u8]) -> isize {
    if buf.is_empty() {
        return 0;
    }

    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None => return -9,
    };

    if bfd & 1 == 0 {
        return -9;
    } // wrong end

    let pid = crate::proc::scheduler::current_pid();
    let mut written = 0usize;
    let mut remaining = buf;

    while !remaining.is_empty() {
        let atomic = remaining.len() <= PIPE_BUF;

        loop {
            {
                let mut inner = pipe.lock();

                if inner.read_open == 0 {
                    crate::proc::signal::send_signal(pid, SIGPIPE);
                    return if written == 0 {
                        EPIPE
                    } else {
                        written as isize
                    };
                }

                let space = inner.space();
                if space == 0 {
                    if inner.nonblocking {
                        return if written == 0 {
                            EAGAIN
                        } else {
                            written as isize
                        };
                    }
                } else if atomic {
                    if space >= remaining.len() {
                        inner.write_bytes(remaining);
                        written += remaining.len();
                        remaining = &[];
                        break;
                    }
                } else {
                    let chunk = remaining.len().min(space);
                    inner.write_bytes(&remaining[..chunk]);
                    written += chunk;
                    remaining = &remaining[chunk..];
                    break;
                }
            }
            crate::proc::scheduler::schedule();
            core::hint::spin_loop();
        }
    }

    written as isize
}

// ── Close ─────────────────────────────────────────────────────────────────────

/// Called by `PipeScheme::close` (and legacy paths) when a pipe-end fd closes.
pub fn sys_close_pipe(bfd: usize) {
    let pipe = match PIPE_TABLE.lock().get(bfd) {
        Some(p) => p,
        None => return,
    };

    {
        let mut inner = pipe.lock();
        if bfd & 1 == 0 {
            inner.read_open = inner.read_open.saturating_sub(1);
        } else {
            inner.write_open = inner.write_open.saturating_sub(1);
        }
    }

    PIPE_TABLE.lock().remove(bfd);
}

// ── PipeScheme — Scheme trait wrapper around the ring-buffer ─────────────────
//
// Each pipe end is represented as a PipeScheme whose `ring_bfd` field is the
// even (read) backing fd.  The SchemeFileId passed to every method encodes
// which end is being operated on:
//
//   fid.0 is even  =>  read  end  (ring_bfd itself)
//   fid.0 is odd   =>  write end  (ring_bfd + 1)
//
// This lets a single PipeScheme Arc serve both ends while keeping the
// PIPE_TABLE lookup simple.

pub struct PipeScheme {
    /// The even (read-end) backing fd for this pipe.  The write end is + 1.
    ring_bfd: usize,
}

impl PipeScheme {
    fn new(read_bfd: usize) -> Self {
        Self { ring_bfd: read_bfd }
    }

    /// Reconstruct the ring-buffer backing fd from a SchemeFileId.
    #[inline]
    fn bfd_from_fid(&self, fid: SchemeFileId) -> usize {
        // fid.0: 0 = read end, 1 = write end (matches even/odd convention)
        self.ring_bfd + (fid.0 as usize & 1)
    }
}

impl Scheme for PipeScheme {
    // Pipes are created by sys_pipe2, not opened by URL.
    fn open(&self, _url: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let bfd = self.bfd_from_fid(fid);
        let n = pipe_read(bfd, buf);
        if n < 0 {
            Err(SchemeError::Io)
        } else {
            Ok(n as usize)
        }
    }

    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let bfd = self.bfd_from_fid(fid);
        let n = pipe_write(bfd, buf);
        if n == EPIPE {
            Err(SchemeError::Other) // caller translates to -EPIPE
        } else if n < 0 {
            Err(SchemeError::Io)
        } else {
            Ok(n as usize)
        }
    }

    fn seek(&self, _fid: SchemeFileId, _offset: i64, _whence: u8) -> Result<u64, SchemeError> {
        Err(SchemeError::InvalidArg) // pipes are not seekable
    }

    fn ioctl(&self, _fid: SchemeFileId, _cmd: u64, _arg: usize) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        let bfd = self.bfd_from_fid(fid);
        sys_close_pipe(bfd);
        Ok(())
    }
}

// ── sys_pipe / sys_pipe2 ──────────────────────────────────────────────────────

/// Create a pipe and return the read/write fd pair in the array at `pipefd_va`.
///
/// Internally delegates to `sys_pipe2` with flags = 0.
///
/// NR 22.
pub fn sys_pipe(pipefd_va: usize) -> isize {
    sys_pipe2(pipefd_va, 0)
}

/// Like `sys_pipe` but honours `flags`:
///   O_CLOEXEC  (0o2000000) — set FD_CLOEXEC on both ends.
///   O_NONBLOCK (0o4000)    — set O_NONBLOCK on both ends.
///   O_DIRECT   (0o40000)   — accepted (advisory; in-kernel ring has no meaning
///                            for O_DIRECT).
///
/// Both ends are now registered through `SCHEME_FD_STORE` via a `PipeScheme`
/// wrapper, so reads/writes/closes flow through `scheme_fd_read` /
/// `scheme_fd_write` / `scheme_fd_close` like every other scheme resource.
/// The raw `PIPE_TABLE` entries are still inserted so that `is_pipe`,
/// `pipe_poll`, and `pipe_dup` continue to work for the poll/epoll layer.
///
/// NR 293.
pub fn sys_pipe2(pipefd_va: usize, flags: u32) -> isize {
    use crate::fs::process_fd::proc_fd_install;
    use crate::fs::scheme_fd::{alloc_scheme_backing_fd, scheme_fd_register};
    use crate::uaccess::{copy_to_user, validate_user_ptr};

    const O_CLOEXEC: u32 = 0o2000000;
    const O_NONBLOCK: u32 = 0o4000;
    const EINVAL: isize = -22;

    if flags & !(O_CLOEXEC | O_NONBLOCK | 0o40000) != 0 {
        return EINVAL;
    }
    if !validate_user_ptr(pipefd_va, 8) {
        return EFAULT;
    }

    let nonblocking = flags & O_NONBLOCK != 0;
    let cloexec = flags & O_CLOEXEC != 0;

    // ── 1. Allocate the shared ring-buffer ───────────────────────────────────
    let pipe_arc = Arc::new(Mutex::new(PipeInner::new(nonblocking)));

    // ── 2. Allocate ring-buffer bfds (PIPE_TABLE namespace) ─────────────────
    let (read_bfd, write_bfd) = alloc_pipe_fds();

    // ── 3. Register both ends in PIPE_TABLE (needed by poll/dup) ────────────
    {
        let mut tbl = PIPE_TABLE.lock();
        tbl.insert(read_bfd, Arc::clone(&pipe_arc));
        tbl.insert(write_bfd, Arc::clone(&pipe_arc));
    }

    // ── 4. Build a PipeScheme and allocate *scheme* backing fds ─────────────
    //
    // The scheme backing fds are drawn from SCHEME_FD_STORE's namespace
    // (0x8000_0000+), independent of the PIPE_TABLE fds.  We use:
    //   SchemeFileId(0)  for the read  end
    //   SchemeFileId(1)  for the write end
    //
    // Both scheme entries share *one* Arc<PipeScheme>; the PipeScheme
    // reconstructs the correct ring_bfd from the fid parity on each call.
    let scheme: Arc<dyn Scheme> = Arc::new(PipeScheme::new(read_bfd));

    let scheme_read_bfd = alloc_scheme_backing_fd();
    let scheme_write_bfd = alloc_scheme_backing_fd();

    scheme_fd_register(scheme_read_bfd, Arc::clone(&scheme), SchemeFileId(0));
    scheme_fd_register(scheme_write_bfd, Arc::clone(&scheme), SchemeFileId(1));

    // ── 5. RLIMIT_NOFILE check ───────────────────────────────────────────────
    let pid = crate::proc::scheduler::current_pid();
    {
        use crate::fs::process_fd::proc_fd_list;
        let open_count = proc_fd_list(pid).len();
        let (soft, _) = crate::proc::rlimit::getrlimit_for(pid, 7 /* RLIMIT_NOFILE */);
        if (open_count + 2) as u64 > soft {
            // Roll back all allocations.
            PIPE_TABLE.lock().remove(read_bfd);
            PIPE_TABLE.lock().remove(write_bfd);
            crate::fs::scheme_fd::scheme_fd_close(scheme_read_bfd);
            crate::fs::scheme_fd::scheme_fd_close(scheme_write_bfd);
            return EMFILE;
        }
    }

    // ── 6. Install scheme backing fds into the process fd table ─────────────
    //
    // We install the *scheme* backing fds (not the ring-buffer bfds) so
    // that all subsequent read/write/close on the user-visible fd routes
    // through scheme_fd_read / scheme_fd_write / scheme_fd_close.
    //
    // The ring-buffer bfds live only in PIPE_TABLE and are accessed
    // indirectly through PipeScheme.
    let rd_flags = if cloexec { O_CLOEXEC } else { 0 };
    let wr_flags = 1 /* O_WRONLY */ | if cloexec { O_CLOEXEC } else { 0 };

    let read_fd = proc_fd_install(pid, scheme_read_bfd, None, rd_flags, None);
    let write_fd = proc_fd_install(pid, scheme_write_bfd, None, wr_flags, None);

    // ── 7. Copy [read_fd, write_fd] back to user space ───────────────────────
    let pair: [i32; 2] = [read_fd as i32, write_fd as i32];
    let bytes: [u8; 8] = unsafe { core::mem::transmute(pair) };
    if copy_to_user(pipefd_va, &bytes).is_err() {
        // Clean up all fds on fault.
        crate::fs::process_fd::proc_fd_close(pid, read_fd);
        crate::fs::process_fd::proc_fd_close(pid, write_fd);
        return EFAULT;
    }

    0
}
