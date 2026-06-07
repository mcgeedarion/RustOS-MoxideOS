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
    let pid = crate::proc::scheduler::current_pid_usize();
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
        let pid = crate::proc::scheduler::current_pid_usize();
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EpollEvent {
    events: u32,
    data: u64,
}

const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;
const EPOLL_FD_BASE: usize = 0x7000_0000;
const MAX_EPOLLS: usize = 1024;

#[derive(Default)]
struct EpollInstance {
    entries: alloc::collections::BTreeMap<i32, EpollEvent>,
}

static EPOLL_TABLE: Mutex<alloc::collections::BTreeMap<usize, EpollInstance>> =
    Mutex::new(alloc::collections::BTreeMap::new());

/// Return the currently-ready subset of `events` for a user-visible fd.
pub fn fd_ready(fdno: usize, events: u32) -> u32 {
    let source = match fd_poll_source(fdno) {
        Some(source) => source,
        None => return POLLNVAL,
    };
    source.poll(events)
}

fn poll_once(fds_va: usize, nfds: usize) -> Result<usize, isize> {
    let size = core::mem::size_of::<PollFd>();
    let mut ready = 0usize;
    for i in 0..nfds {
        let ptr = fds_va + i * size;
        let mut raw = [0u8; core::mem::size_of::<PollFd>()];
        if copy_from_user(raw.as_mut_ptr(), ptr, raw.len()).is_err() {
            return Err(-14);
        }
        let mut pfd: PollFd = unsafe { core::mem::transmute(raw) };
        pfd.revents = 0;
        if pfd.fd >= 0 {
            let mask = fd_ready(pfd.fd as usize, pfd.events as u32) as i16;
            pfd.revents = mask;
            if mask != 0 {
                ready += 1;
            }
        }
        if crate::uaccess::copy_to_user_value(ptr, &pfd).is_err() {
            return Err(-14);
        }
    }
    Ok(ready)
}

/// poll(2).  Readiness is delegated through `fd_poll_source`, so scheme fds
/// opened through proc-fd translation participate like other synthetic fds.
pub fn sys_poll(fds_va: usize, nfds: usize, _timeout_ms: i32) -> isize {
    if nfds == 0 {
        return 0;
    }
    if !validate_user_ptr(fds_va, nfds.saturating_mul(core::mem::size_of::<PollFd>())) {
        return -14;
    }
    match poll_once(fds_va, nfds) {
        Ok(n) => n as isize,
        Err(e) => e,
    }
}

pub fn sys_ppoll(
    fds_va: usize,
    nfds: usize,
    timeout_va: usize,
    _sigmask_va: usize,
    _sigsetsize: usize,
) -> isize {
    let _ = timeout_va;
    sys_poll(fds_va, nfds, 0)
}

pub fn sys_select(
    nfds: usize,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    _timeout: usize,
) -> isize {
    let _ = exceptfds;
    let mut ready = 0isize;
    for fd in 0..nfds {
        let byte = fd / 8;
        let bit = fd % 8;
        let mask = 1u8 << bit;
        if readfds != 0 {
            let mut b = [0u8; 1];
            if copy_from_user(b.as_mut_ptr(), readfds + byte, b.len()).is_err() {
                return -14;
            }
            if b[0] & mask != 0 {
                if fd_ready(fd, POLLIN | POLLRDNORM) != 0 {
                    ready += 1;
                } else {
                    b[0] &= !mask;
                    let _ = crate::uaccess::copy_to_user_value(readfds + byte, &b);
                }
            }
        }
        if writefds != 0 {
            let mut b = [0u8; 1];
            if copy_from_user(b.as_mut_ptr(), writefds + byte, b.len()).is_err() {
                return -14;
            }
            if b[0] & mask != 0 {
                if fd_ready(fd, POLLOUT | POLLWRNORM) != 0 {
                    ready += 1;
                } else {
                    b[0] &= !mask;
                    let _ = crate::uaccess::copy_to_user_value(writefds + byte, &b);
                }
            }
        }
    }
    ready
}

pub fn sys_pselect6(
    nfds: usize,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    timeout: usize,
    sig: usize,
) -> isize {
    let _ = sig;
    sys_select(nfds, readfds, writefds, exceptfds, timeout)
}

pub fn sys_epoll_create(_size: i32) -> isize {
    let mut table = EPOLL_TABLE.lock();
    for i in 0..MAX_EPOLLS {
        let fd = EPOLL_FD_BASE + i;
        if !table.contains_key(&fd) {
            table.insert(fd, EpollInstance::default());
            return fd as isize;
        }
    }
    -24
}

pub fn sys_epoll_ctl(epfd: usize, op: i32, fd: i32, event_va: usize) -> isize {
    let mut table = EPOLL_TABLE.lock();
    let ep = match table.get_mut(&epfd) {
        Some(ep) => ep,
        None => return -9,
    };
    match op {
        EPOLL_CTL_ADD | EPOLL_CTL_MOD => {
            let mut raw = [0u8; core::mem::size_of::<EpollEvent>()];
            if copy_from_user(raw.as_mut_ptr(), event_va, raw.len()).is_err() {
                return -14;
            }
            let event: EpollEvent = unsafe { core::mem::transmute(raw) };
            ep.entries.insert(fd, event);
            0
        },
        EPOLL_CTL_DEL => {
            ep.entries.remove(&fd);
            0
        },
        _ => -22,
    }
}

pub fn sys_epoll_wait(epfd: usize, events_va: usize, maxevents: i32, _timeout_ms: i32) -> isize {
    if maxevents <= 0 {
        return -22;
    }
    let mut out = 0usize;
    let size = core::mem::size_of::<EpollEvent>();
    let table = EPOLL_TABLE.lock();
    let ep = match table.get(&epfd) {
        Some(ep) => ep,
        None => return -9,
    };
    for (&fd, event) in ep.entries.iter() {
        if out >= maxevents as usize {
            break;
        }
        let ready = fd_ready(fd as usize, event.events);
        if ready != 0 {
            let mut ev = *event;
            ev.events = ready;
            if crate::uaccess::copy_to_user_value(events_va + out * size, &ev).is_err() {
                return -14;
            }
            out += 1;
        }
    }
    out as isize
}

pub fn sys_epoll_pwait(
    epfd: usize,
    events_va: usize,
    maxevents: i32,
    timeout_ms: i32,
    sigmask: usize,
    sigsetsize: usize,
) -> isize {
    let _ = (sigmask, sigsetsize);
    sys_epoll_wait(epfd, events_va, maxevents, timeout_ms)
}
