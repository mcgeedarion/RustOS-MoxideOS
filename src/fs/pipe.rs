//! Pipe subsystem — pipe(2) / pipe2(2) and the backing ring-buffer object.
//!
//! ## Architecture
//!
//! Each pipe is a 64 KiB ring buffer stored behind a `Arc<PipeState>`.
//! `PipeState` holds the data mutex (`Mutex<PipeInner>`) **and** two
//! `WaitQueue`s (`read_wq`, `write_wq`) that live *outside* the mutex so
//! they can be woken without holding the data lock.
//!
//! Both ends (read fd and write fd) hold a clone of the same `Arc<PipeState>`,
//! so they share one buffer regardless of which process holds which end after
//! a fork.
//!
//! ## Blocking model
//!
//! Blocking reads/writes park on a `WaitQueue` via a single
//! `scheduler::block_current()` call — no spin loops, no yield loops.
//!
//! | Direction | Blocks on  | Woken by                          |
//! |-----------|------------|-----------------------------------|
//! | read      | `read_wq`  | writer calls `read_wq.wake(POLLIN)`  after appending data |
//! | read      | `read_wq`  | `sys_close_pipe` (write end) calls `read_wq.wake(POLLHUP)` |
//! | write     | `write_wq` | reader calls `write_wq.wake(POLLOUT)` after consuming data |
//! | write     | `write_wq` | `sys_close_pipe` (read end) calls `write_wq.wake(POLLERR)` |
//!
//! Cancellation (signals, task exit) is handled by the per-task
//! `CancellationToken` stored in `Pcb`, passed into `WaitQueue::wait()`.
//!
//! ## Scheme integration
//!
//! `sys_pipe2` allocates scheme backing fds via `alloc_scheme_backing_fd`
//! and registers a `PipeScheme` instance for each end in `SCHEME_FD_STORE`.
//! Reads/writes/closes flow through `scheme_fd_read` / `scheme_fd_write` /
//! `scheme_fd_close` like every other scheme resource.
//!
//! The raw `PIPE_TABLE` is still populated for the poll/epoll readiness path
//! (`is_pipe`, `is_pipe_fd`, `pipe_poll`, `pipe_poll_source`).
//!
//! ## Backing-fd lifetime
//!
//! Two bfds are allocated per pipe: an even one (read end) and an odd one
//! (write end = read_bfd + 1).  Both are keys in PIPE_TABLE pointing at the
//! *same* `Arc<PipeState>`.  Closing one end removes only *that* key; the
//! peer's key (and Arc clone) stays until the peer is closed.
//!
//! ## Refcounting (dup / fork)
//!
//! `PipeInner.read_open` / `write_open` count how many process-local fds
//! point at each end across all processes.  `pipe_dup(bfd)` increments the
//! appropriate counter; `sys_close_pipe(bfd)` decrements it.  When
//! `write_open` reaches zero the read end sees EOF; when `read_open` reaches
//! zero the write end receives SIGPIPE.
//!
//! ## POSIX guarantees
//!
//! - Writes ≤ PIPE_BUF (4096) are atomic: the mutex is held for the entire
//!   write so no other writer can interleave.
//! - `pipe_write` delivers SIGPIPE + returns -EPIPE when all readers have
//!   closed.
//! - `pipe_read` returns 0 (EOF) when all writers have closed and the buffer is
//!   empty.
//! - `pipe2` honours O_CLOEXEC and O_NONBLOCK.
//!
//! ## Poll / select / epoll readiness
//!
//! `is_pipe_fd(user_fd)` and `pipe_poll(user_fd, events)` are the two
//! functions called by `poll::fd_ready`.  New: `pipe_poll_source(bfd)`
//! returns an `Arc<dyn PollSource>` for the unified poll machinery.
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
use crate::core::fast_hash::KernelFastMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::fs::scheme_table::Scheme;
use crate::sync::poll_source::PollSource;
use crate::sync::wait_queue::ReadyMask;
use crate::sync::wait_queue::{WaitQueue, WakeReason};
use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

use crate::fs::poll::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLRDNORM, POLLWRNORM};

/// Capacity of every pipe's ring buffer (bytes).
pub const PIPE_BUF_SIZE: usize = 65536;

/// Atomic write-size guarantee (POSIX PIPE_BUF).
pub const PIPE_BUF: usize = 4096;

/// Backing fd range reserved for pipe ends.  Read end = even, write end = odd.
/// 0x8000_0000 is far above any VFS / devfs / socket fd.
pub(crate) const PIPE_FD_BASE: usize = 0x8000_0000;

const EAGAIN: isize = -11;
const EINTR: isize = -4;
const EPIPE: isize = -32;
const EFAULT: isize = -14;
const EMFILE: isize = -24;
const SIGPIPE: u32 = 13;

struct PipeInner {
    buf: alloc::vec::Vec<u8>,
    head: usize,
    len: usize,
    write_open: u32,
    read_open: u32,
    nonblocking: bool,
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

    fn read_bytes(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.len);
        for i in 0..n {
            dst[i] = self.buf[(self.head + i) % self.capacity()];
        }
        self.head = (self.head + n) % self.capacity();
        self.len -= n;
        n
    }

    fn write_bytes(&mut self, src: &[u8]) {
        let cap = self.capacity();
        let tail = (self.head + self.len) % cap;
        for (i, &b) in src.iter().enumerate() {
            self.buf[(tail + i) % cap] = b;
        }
        self.len += src.len();
    }
}

struct PipeState {
    inner: Mutex<PipeInner>,
    read_wq: WaitQueue,
    write_wq: WaitQueue,
}

impl PipeState {
    fn new(nonblocking: bool) -> Self {
        PipeState {
            inner: Mutex::new(PipeInner::new(nonblocking)),
            read_wq: WaitQueue::new(),
            write_wq: WaitQueue::new(),
        }
    }
}

struct PipeTable {
    map: KernelFastMap<usize, Arc<PipeState>>,
}

impl PipeTable {
    const fn new() -> Self {
        PipeTable {
            map: KernelFastMap::new(),
        }
    }
    fn get(&self, bfd: usize) -> Option<Arc<PipeState>> {
        self.map.get(&bfd).cloned()
    }
    fn insert(&mut self, bfd: usize, s: Arc<PipeState>) {
        self.map.insert(bfd, s);
    }
    fn remove(&mut self, bfd: usize) -> bool {
        self.map.remove(&bfd).is_some()
    }
    fn contains(&self, bfd: usize) -> bool {
        self.map.contains_key(&bfd)
    }
}

static PIPE_TABLE: Mutex<PipeTable> = Mutex::new(PipeTable::new());
static NEXT_PIPE_FD: AtomicUsize = AtomicUsize::new(0);

fn alloc_pipe_fds() -> (usize, usize) {
    let off = NEXT_PIPE_FD.fetch_add(2, Ordering::Relaxed);
    (PIPE_FD_BASE + off, PIPE_FD_BASE + off + 1)
}

#[inline]
pub fn is_pipe(bfd: usize) -> bool {
    if bfd < PIPE_FD_BASE {
        return false;
    }
    PIPE_TABLE.lock().contains(bfd)
}

pub fn is_pipe_fd(user_fd: usize) -> bool {
    let pid = crate::proc::scheduler::current_pid();
    let bfd = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if bfd < 0 {
        return false;
    }
    is_pipe(bfd as usize)
}

/// Legacy readiness oracle — called by poll::fd_ready().
pub fn pipe_poll(user_fd: usize, events: u32) -> u32 {
    let pid = crate::proc::scheduler::current_pid();
    let bfd_raw = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if bfd_raw < 0 {
        return POLLNVAL;
    }
    let bfd = bfd_raw as usize;

    let state = match PIPE_TABLE.lock().get(bfd) {
        Some(s) => s,
        None => return POLLNVAL,
    };
    let inner = state.inner.lock();
    pipe_ready(&inner, bfd, events)
}

/// Shared readiness logic used by both pipe_poll and PollSource impls.
#[inline]
fn pipe_ready(inner: &PipeInner, bfd: usize, events: u32) -> u32 {
    let is_write_end = bfd & 1 != 0;
    if is_write_end {
        let mut r = 0u32;
        if inner.read_open == 0 {
            r |= POLLERR;
        }
        if events & (POLLOUT | POLLWRNORM) != 0 && inner.space() > 0 {
            r |= POLLOUT | POLLWRNORM;
        }
        r
    } else {
        let mut r = 0u32;
        if inner.write_open == 0 {
            r |= POLLHUP | POLLIN | POLLRDNORM;
        }
        if events & (POLLIN | POLLRDNORM) != 0 && inner.len > 0 {
            r |= POLLIN | POLLRDNORM;
        }
        r
    }
}

pub struct PipeReadSource(Arc<PipeState>, usize /* read_bfd */);
pub struct PipeWriteSource(Arc<PipeState>, usize /* write_bfd */);

impl PollSource for PipeReadSource {
    fn poll(&self, interest: ReadyMask) -> ReadyMask {
        let inner = self.0.inner.lock();
        pipe_ready(&inner, self.1, interest)
    }
    fn wait_queue(&self) -> &WaitQueue {
        &self.0.read_wq
    }
}

impl PollSource for PipeWriteSource {
    fn poll(&self, interest: ReadyMask) -> ReadyMask {
        let inner = self.0.inner.lock();
        pipe_ready(&inner, self.1, interest)
    }
    fn wait_queue(&self) -> &WaitQueue {
        &self.0.write_wq
    }
}

pub fn pipe_poll_source(bfd: usize) -> Option<Arc<dyn PollSource>> {
    let state = PIPE_TABLE.lock().get(bfd)?;
    if bfd & 1 == 0 {
        Some(Arc::new(PipeReadSource(state, bfd)))
    } else {
        Some(Arc::new(PipeWriteSource(state, bfd)))
    }
}

pub fn pipe_dup(bfd: usize) {
    if bfd < PIPE_FD_BASE {
        return;
    }
    let state = match PIPE_TABLE.lock().get(bfd) {
        Some(s) => s,
        None => return,
    };
    let mut inner = state.inner.lock();
    if bfd & 1 == 0 {
        inner.read_open = inner.read_open.saturating_add(1);
    } else {
        inner.write_open = inner.write_open.saturating_add(1);
    }
}

/// Read up to `buf.len()` bytes from the read end of a pipe.
pub fn pipe_read(bfd: usize, buf: &mut [u8]) -> isize {
    if buf.is_empty() {
        return 0;
    }

    let state = match PIPE_TABLE.lock().get(bfd) {
        Some(s) => s,
        None => return -9,
    };
    if bfd & 1 != 0 {
        return -9;
    } // wrong end

    let pid = crate::proc::scheduler::current_pid();
    let cancel = crate::proc::scheduler::task_cancel_token(pid);

    loop {
        let (got_data, is_eof, nonblock) = {
            let mut inner = state.inner.lock();
            if !inner.is_empty() {
                let n = inner.read_bytes(buf);
                // Space just opened: wake any blocked writer.
                // Drop lock before waking to avoid lock inversion.
                drop(inner);
                state.write_wq.wake(POLLOUT);
                return n as isize;
            }
            (false, inner.write_open == 0, inner.nonblocking)
        };
        let _ = got_data;

        if is_eof {
            return 0;
        } // all writers closed, buffer empty
        if nonblock {
            return EAGAIN;
        }

        let reason = state
            .read_wq
            .wait(POLLIN | POLLHUP, cancel.as_deref(), None);
        if reason == WakeReason::Cancelled {
            return EINTR;
        }
        // WakeReason::Ready or Timeout (no timeout set) → re-check loop.
    }
}

/// Write `buf` to the write end of a pipe.
pub fn pipe_write(bfd: usize, buf: &[u8]) -> isize {
    if buf.is_empty() {
        return 0;
    }

    let state = match PIPE_TABLE.lock().get(bfd) {
        Some(s) => s,
        None => return -9,
    };
    if bfd & 1 == 0 {
        return -9;
    } // wrong end

    let pid = crate::proc::scheduler::current_pid();
    let cancel = crate::proc::scheduler::task_cancel_token(pid);
    let mut written = 0usize;
    let mut remaining = buf;

    while !remaining.is_empty() {
        let atomic = remaining.len() <= PIPE_BUF;

        loop {
            let (wrote_chunk, broken_pipe, nonblock) = {
                let mut inner = state.inner.lock();

                if inner.read_open == 0 {
                    // Broken pipe: deliver SIGPIPE, return EPIPE.
                    drop(inner);
                    crate::proc::signal::send_signal(pid, SIGPIPE);
                    return if written == 0 {
                        EPIPE
                    } else {
                        written as isize
                    };
                }

                let space = inner.space();
                if space == 0 {
                    (false, false, inner.nonblocking)
                } else if atomic {
                    if space >= remaining.len() {
                        inner.write_bytes(remaining);
                        let n = remaining.len();
                        written += n;
                        remaining = &[];
                        drop(inner);
                        state.read_wq.wake(POLLIN);
                        (true, false, false)
                    } else {
                        // Atomic write needs space >= len; block until available.
                        (false, false, inner.nonblocking)
                    }
                } else {
                    let chunk = space.min(remaining.len());
                    inner.write_bytes(&remaining[..chunk]);
                    written += chunk;
                    remaining = &remaining[chunk..];
                    drop(inner);
                    state.read_wq.wake(POLLIN);
                    (true, false, false)
                }
            };
            let _ = broken_pipe;

            if wrote_chunk {
                break;
            } // advance outer while loop
            if nonblock {
                return if written == 0 {
                    EAGAIN
                } else {
                    written as isize
                };
            }

            let reason = state.write_wq.wait(POLLOUT, cancel.as_deref(), None);
            if reason == WakeReason::Cancelled {
                return if written == 0 {
                    EINTR
                } else {
                    written as isize
                };
            }
        }
    }

    written as isize
}

/// Called by `PipeScheme::close` when a pipe-end fd closes.
pub fn sys_close_pipe(bfd: usize) {
    let state = match PIPE_TABLE.lock().get(bfd) {
        Some(s) => s,
        None => return,
    };

    let (wake_read, wake_write) = {
        let mut inner = state.inner.lock();
        if bfd & 1 == 0 {
            inner.read_open = inner.read_open.saturating_sub(1);
            (false, inner.read_open == 0) // last reader gone → POLLERR for
                                          // writers
        } else {
            inner.write_open = inner.write_open.saturating_sub(1);
            (inner.write_open == 0, false) // last writer gone → POLLHUP for
                                           // readers
        }
    };

    // Wake blocked tasks AFTER releasing the data lock.
    if wake_read {
        state.read_wq.wake(POLLHUP);
    }
    if wake_write {
        state.write_wq.wake(POLLERR);
    }

    PIPE_TABLE.lock().remove(bfd);
}

pub struct PipeScheme {
    ring_bfd: usize,
}

impl PipeScheme {
    fn new(read_bfd: usize) -> Self {
        Self { ring_bfd: read_bfd }
    }

    #[inline]
    fn bfd_from_fid(&self, fid: SchemeFileId) -> usize {
        self.ring_bfd + (fid.0 as usize & 1)
    }
}

impl Scheme for PipeScheme {
    fn open(&self, _url: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let n = pipe_read(self.bfd_from_fid(fid), buf);
        match n {
            n if n >= 0 => Ok(n as usize),
            -4 => Err(SchemeError::Interrupted), // EINTR
            _ => Err(SchemeError::Io),
        }
    }

    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let n = pipe_write(self.bfd_from_fid(fid), buf);
        match n {
            n if n >= 0 => Ok(n as usize),
            -4 => Err(SchemeError::Interrupted), // EINTR
            -32 => Err(SchemeError::Other),      // EPIPE
            _ => Err(SchemeError::Io),
        }
    }

    fn seek(&self, _fid: SchemeFileId, _offset: i64, _whence: u8) -> Result<u64, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn ioctl(&self, _fid: SchemeFileId, _cmd: u64, _arg: usize) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        sys_close_pipe(self.bfd_from_fid(fid));
        Ok(())
    }
}

/// NR 22.
pub fn sys_pipe(pipefd_va: usize) -> isize {
    sys_pipe2(pipefd_va, 0)
}

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

    // 1. Allocate shared PipeState.
    let pipe_arc = Arc::new(PipeState::new(nonblocking));

    // 2. Allocate ring-buffer bfds.
    let (read_bfd, write_bfd) = alloc_pipe_fds();

    // 3. Register both ends in PIPE_TABLE.
    {
        let mut tbl = PIPE_TABLE.lock();
        tbl.insert(read_bfd, Arc::clone(&pipe_arc));
        tbl.insert(write_bfd, Arc::clone(&pipe_arc));
    }

    // 4. Build PipeScheme and scheme backing fds.
    let scheme: Arc<dyn Scheme> = Arc::new(PipeScheme::new(read_bfd));
    let scheme_read_bfd = alloc_scheme_backing_fd();
    let scheme_write_bfd = alloc_scheme_backing_fd();
    scheme_fd_register(scheme_read_bfd, Arc::clone(&scheme), SchemeFileId(0));
    scheme_fd_register(scheme_write_bfd, Arc::clone(&scheme), SchemeFileId(1));

    // 5. RLIMIT_NOFILE check.
    let pid = crate::proc::scheduler::current_pid();
    {
        use crate::fs::process_fd::proc_fd_list;
        let open_count = proc_fd_list(pid).len();
        let (soft, _) = crate::proc::rlimit::getrlimit_for(pid, 7);
        if (open_count + 2) as u64 > soft {
            PIPE_TABLE.lock().remove(read_bfd);
            PIPE_TABLE.lock().remove(write_bfd);
            crate::fs::scheme_fd::scheme_fd_close(scheme_read_bfd);
            crate::fs::scheme_fd::scheme_fd_close(scheme_write_bfd);
            return EMFILE;
        }
    }

    // 6. Install scheme fds into the process fd table.
    let rd_flags = if cloexec { O_CLOEXEC } else { 0 };
    let wr_flags = 1 | if cloexec { O_CLOEXEC } else { 0 };
    let read_fd = proc_fd_install(pid, scheme_read_bfd, None, rd_flags, None);
    let write_fd = proc_fd_install(pid, scheme_write_bfd, None, wr_flags, None);

    // 7. Copy [read_fd, write_fd] to userspace.
    let pair: [i32; 2] = [read_fd as i32, write_fd as i32];
    let bytes: [u8; 8] = unsafe { core::mem::transmute(pair) };
    if copy_to_user(pipefd_va, &bytes).is_err() {
        crate::fs::process_fd::proc_fd_close(pid, read_fd);
        crate::fs::process_fd::proc_fd_close(pid, write_fd);
        return EFAULT;
    }

    0
}
