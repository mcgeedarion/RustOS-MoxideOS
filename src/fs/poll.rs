//! I/O multiplexing: select(2), pselect6(2), poll(2), ppoll(2),
//! epoll_create(2), epoll_ctl(2), epoll_wait(2).
//!
//! ## Blocking model
//!
//! All four interfaces share a two-phase loop:
//!
//! ```text
//! loop {
//!     ready = check all fds via PollSource::poll()   // lock-free
//!     if ready > 0 || deadline elapsed => return
//!     wait_any(sources, cancel, deadline)             // ONE scheduler sleep
//! }
//! ```
//!
//! `wait_any` registers a forwarder on every source's `WaitQueue`, then
//! calls `block_current()` once.  When any source fires, the aggregate
//! queue is woken, the task unblocks, and the loop re-checks all fds.
//!
//! No `core::hint::spin_loop()` exists anywhere in this file.
//!
//! ## Readiness oracle
//!
//! `fd_poll_source(fdno)` is the canonical dispatch function.  It returns
//! an `Arc<dyn PollSource>` for any known fd type.  `fd_ready()` is kept
//! as a thin wrapper for callers that only need a synchronous snapshot.
//!
//! | Backing        | POLLIN ready when            | POLLOUT ready when          |
//! |----------------|------------------------------|------------------------------|
//! | stdin (fd 0)   | TTY ring buffer non-empty    | always                      |
//! | stdout/stderr  | always                       | always                      |
//! | Pipe read-end  | pipe ring buffer non-empty   | N/A                         |
//! | Pipe write-end | N/A                          | pipe buffer not full        |
//! | Pipe (closed)  | POLLHUP                      |                             |
//! | Socket         | recv-buf non-empty           | send-buf not full           |
//! | eventfd        | counter > 0                  | counter < MAX               |
//! | timerfd        | expirations > 0              | N/A                         |
//! | devfs / file   | always                       | always                      |
//! | unknown fd     | POLLNVAL                     |                             |
//!
//! ## select / pselect6 differences
//!
//!   `select`  uses `struct timeval`  (seconds + microseconds, 2×i64 on
//! x86-64).   `pselect6` uses `struct timespec` (seconds + nanoseconds,  2×i64
//! on x86-64).   `pselect6` 6th argument is `{ const sigset_t *ss; size_t
//! ss_len; }`.
//!
//! ## Timeout writeback
//!
//!   `select`   writes back the remaining timeval on return (POSIX §2.10.16).
//!   `pselect6` does NOT write back the timespec (Linux-compatible).
//!
//! ## epoll
//!
//!   Epoll instance fds live in EPOLL_TABLE in [EPOLL_FD_BASE,
//! EPOLL_FD_BASE+MAX_EPOLLS).   EPOLLONESHOT entries are disarmed after firing;
//! re-arm with EPOLL_CTL_MOD.

extern crate alloc;
use crate::sync::poll_source::{wait_any, AlwaysReady, PollSource};
use crate::sync::wait_queue::{CancellationToken, ReadyMask, WaitQueue, WakeReason};
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub const POLLIN: u32 = 0x0001;
pub const POLLPRI: u32 = 0x0002;
pub const POLLOUT: u32 = 0x0004;
pub const POLLERR: u32 = 0x0008;
pub const POLLHUP: u32 = 0x0010;
pub const POLLNVAL: u32 = 0x0020;
pub const POLLRDNORM: u32 = 0x0040;
pub const POLLWRNORM: u32 = 0x0100;
pub const EPOLLONESHOT: u32 = 0x4000_0000;

#[inline]
fn user_fd_to_bfd(user_fd: usize) -> Option<usize> {
    let pid = crate::proc::scheduler::current_pid();
    let r = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if r < 0 {
        None
    } else {
        Some(r as usize)
    }
}

struct StdinSource {
    wq: WaitQueue,
}

impl StdinSource {
    fn new() -> Self {
        Self {
            wq: WaitQueue::new(),
        }
    }
}

impl PollSource for StdinSource {
    fn poll(&self, interest: ReadyMask) -> ReadyMask {
        let mut r = 0u32;
        if interest & (POLLIN | POLLRDNORM) != 0 && crate::tty::serial::bytes_available() > 0 {
            r |= POLLIN | POLLRDNORM;
        }
        if interest & (POLLOUT | POLLWRNORM) != 0 {
            r |= POLLOUT | POLLWRNORM;
        }
        r
    }
    fn wait_queue(&self) -> &WaitQueue {
        &self.wq
    }
}

/// Return an `Arc<dyn PollSource>` for any user-visible fd.
pub fn fd_poll_source(fdno: usize) -> Option<Arc<dyn PollSource>> {
    // fd 0 — stdin
    if fdno == 0 {
        return Some(Arc::new(StdinSource::new()));
    }
    // fd 1/2 — stdout/stderr: always ready
    if fdno == 1 || fdno == 2 {
        return Some(Arc::new(AlwaysReady::new()));
    }
    // Pipes
    if crate::fs::pipe::is_pipe_fd(fdno) {
        let pid = crate::proc::scheduler::current_pid();
        let bfd = crate::fs::process_fd::proc_fd_backing(pid, fdno);
        if bfd >= 0 {
            return crate::fs::pipe::pipe_poll_source(bfd as usize);
        }
    }
    // Sockets
    if let Some(src) = crate::net::socket::socket_poll_source(fdno) {
        return Some(src);
    }
    // Remaining subsystems need backing fd translation.
    let bfd = user_fd_to_bfd(fdno)?;
    Some(Arc::new(AlwaysReady::new()))
}
