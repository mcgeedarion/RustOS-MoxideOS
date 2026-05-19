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
//!   `select`  uses `struct timeval`  (seconds + microseconds, 2×i64 on x86-64).
//!   `pselect6` uses `struct timespec` (seconds + nanoseconds,  2×i64 on x86-64).
//!   `pselect6` 6th argument is `{ const sigset_t *ss; size_t ss_len; }`.
//!
//! ## Timeout writeback
//!
//!   `select`   writes back the remaining timeval on return (POSIX §2.10.16).
//!   `pselect6` does NOT write back the timespec (Linux-compatible).
//!
//! ## epoll
//!
//!   Epoll instance fds live in EPOLL_TABLE in [EPOLL_FD_BASE, EPOLL_FD_BASE+MAX_EPOLLS).
//!   EPOLLONESHOT entries are disarmed after firing; re-arm with EPOLL_CTL_MOD.

extern crate alloc;
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::Mutex;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};
use crate::sync::wait_queue::{WaitQueue, WakeReason, CancellationToken, ReadyMask};
use crate::sync::poll_source::{PollSource, wait_any, AlwaysReady};

// ── Poll event flags ────────────────────────────────────────────────────────────

pub const POLLIN:       u32 = 0x0001;
pub const POLLPRI:      u32 = 0x0002;
pub const POLLOUT:      u32 = 0x0004;
pub const POLLERR:      u32 = 0x0008;
pub const POLLHUP:      u32 = 0x0010;
pub const POLLNVAL:     u32 = 0x0020;
pub const POLLRDNORM:   u32 = 0x0040;
pub const POLLWRNORM:   u32 = 0x0100;
pub const EPOLLONESHOT: u32 = 0x4000_0000;

// ── fd namespace helper ─────────────────────────────────────────────────────────

#[inline]
fn user_fd_to_bfd(user_fd: usize) -> Option<usize> {
    let pid = crate::proc::scheduler::current_pid();
    let r = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if r < 0 { None } else { Some(r as usize) }
}

// ── Stdio PollSource impls ────────────────────────────────────────────────────────
//
// stdin is backed by the TTY ring; reads from the actual tty WaitQueue
// will be wired in the tty migration.  For now poll() checks the ring
// synchronously and the WaitQueue is a never-slept-on sentinel.

struct StdinSource {
    wq: WaitQueue,
}

impl StdinSource {
    fn new() -> Self { Self { wq: WaitQueue::new() } }
}

impl PollSource for StdinSource {
    fn poll(&self, interest: ReadyMask) -> ReadyMask {
        let mut r = 0u32;
        if interest & (POLLIN | POLLRDNORM) != 0
            && crate::shell::tty::bytes_available() > 0
        {
            r |= POLLIN | POLLRDNORM;
        }
        if interest & (POLLOUT | POLLWRNORM) != 0 {
            r |= POLLOUT | POLLWRNORM;
        }
        r
    }
    fn wait_queue(&self) -> &WaitQueue { &self.wq }
}

// ── PollSource dispatch ───────────────────────────────────────────────────────────

/// Return an `Arc<dyn PollSource>` for any user-visible fd.
///
/// This is the canonical dispatch function replacing the old if/else chain
/// in `fd_ready()`.  Returns `None` only if the fd does not exist at all
/// (POLLNVAL territory).
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

    if crate::fs::eventfd::is_eventfd(bfd) {
        return crate::fs::eventfd::eventfd_poll_source(bfd);
    }
    if crate::fs::timerfd::is_timerfd(bfd) {
        return crate::fs::timerfd::timerfd_poll_source(bfd);
    }
    // devfs and regular VFS files: always ready.
    if crate::fs::devfs::get_dev_fd(bfd).is_some() || crate::fs::vfs::fd_exists(bfd) {
        return Some(Arc::new(AlwaysReady::new()));
    }
    None // POLLNVAL
}

/// Synchronous readiness snapshot.  Kept for legacy callers.
/// Prefer `fd_poll_source` for anything that may block.
pub fn fd_ready(fdno: usize, events: u32) -> u32 {
    match fd_poll_source(fdno) {
        Some(src) => src.poll(events),
        None      => POLLNVAL,
    }
}

// ── Cancellation helper ───────────────────────────────────────────────────────────

#[inline]
fn current_cancel() -> Option<Arc<CancellationToken>> {
    let pid = crate::proc::scheduler::current_pid();
    crate::proc::scheduler::task_cancel_token(pid)
}

// ── Time helpers ─────────────────────────────────────────────────────────────

#[inline]
fn now_ns() -> u64 { crate::time::monotonic_ns() }

#[inline]
fn before_deadline(deadline_ns: u64) -> bool { now_ns() < deadline_ns }

fn read_timespec(va: usize) -> Result<(i64, i64), isize> {
    if !validate_user_ptr(va, 16) { return Err(-14); }
    let mut buf = [0u8; 16];
    copy_from_user(&mut buf, va).map_err(|_| -14isize)?;
    let secs  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let nsecs = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    Ok((secs, nsecs))
}

fn read_timeval(va: usize) -> Result<(i64, i64), isize> {
    if !validate_user_ptr(va, 16) { return Err(-14); }
    let mut buf = [0u8; 16];
    copy_from_user(&mut buf, va).map_err(|_| -14isize)?;
    let secs  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let usecs = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    Ok((secs, usecs))
}

fn write_timeval_remaining(va: usize, deadline_ns: u64) {
    if va == 0 { return; }
    let now      = now_ns();
    let rem_ns   = if deadline_ns > now { deadline_ns - now } else { 0 };
    let rem_sec  = rem_ns / 1_000_000_000;
    let rem_usec = (rem_ns % 1_000_000_000) / 1_000;
    let mut buf  = [0u8; 16];
    buf[0..8].copy_from_slice(&(rem_sec  as i64).to_le_bytes());
    buf[8..16].copy_from_slice(&(rem_usec as i64).to_le_bytes());
    let _ = copy_to_user(va, &buf);
}

fn ms_to_deadline_ns(ms: i32) -> u64 {
    if ms == 0 { return now_ns(); }
    let wait_ns = if ms < 0 { 5_000_000_000u64 } else { (ms as u64) * 1_000_000 };
    now_ns() + wait_ns
}

// ── fd_set bitmap helpers ─────────────────────────────────────────────────────────

fn read_fdset(va: usize, words: usize) -> Result<Vec<u64>, isize> {
    if va == 0 { return Ok(alloc::vec![0u64; words]); }
    if !validate_user_ptr(va, words * 8) { return Err(-14); }
    let mut v = alloc::vec![0u64; words];
    for i in 0..words {
        let mut buf = [0u8; 8];
        copy_from_user(&mut buf, va + i * 8).map_err(|_| -14isize)?;
        v[i] = u64::from_le_bytes(buf);
    }
    Ok(v)
}

fn write_fdset(va: usize, src: &[u64]) {
    if va == 0 { return; }
    for (i, &w) in src.iter().enumerate() {
        let _ = copy_to_user(va + i * 8, &w.to_le_bytes());
    }
}

// ── Signal mask helpers (pselect6) ──────────────────────────────────────────────

fn pselect_swap_sigmask(ss_va: usize) -> Option<u64> {
    if ss_va == 0 { return None; }
    if !validate_user_ptr(ss_va, 16) { return None; }
    let mut arg_buf = [0u8; 16];
    if copy_from_user(&mut arg_buf, ss_va).is_err() { return None; }
    let ss_ptr = u64::from_le_bytes(arg_buf[0..8].try_into().unwrap());
    let ss_len = u64::from_le_bytes(arg_buf[8..16].try_into().unwrap());
    if ss_ptr == 0 || ss_len != 8 { return None; }
    if !validate_user_ptr(ss_ptr as usize, 8) { return None; }
    let mut mask_buf = [0u8; 8];
    if copy_from_user(&mut mask_buf, ss_ptr as usize).is_err() { return None; }
    let new_mask = u64::from_le_bytes(mask_buf);
    let pid = crate::proc::scheduler::current_pid();
    let old = crate::proc::signal::get_sigmask(pid);
    crate::proc::signal::set_sigmask(pid, new_mask);
    Some(old)
}

fn pselect_restore_sigmask(old: Option<u64>) {
    if let Some(m) = old {
        crate::proc::signal::set_sigmask(
            crate::proc::scheduler::current_pid(), m);
    }
}

// ── sys_select  [NR 23] ─────────────────────────────────────────────────────────

pub fn sys_select(
    nfds:    usize,
    rfds_va: usize,
    wfds_va: usize,
    efds_va: usize,
    tv_va:   usize,
) -> isize {
    if nfds > 1024 { return -22; }

    let words     = (nfds + 63) / 64;
    let bmap_size = words * 8;
    for va in [rfds_va, wfds_va, efds_va] {
        if va != 0 && !validate_user_ptr(va, bmap_size) { return -14; }
    }

    let (deadline_ns, zero_poll) = if tv_va == 0 {
        (now_ns() + 5_000_000_000, false)
    } else {
        match read_timeval(tv_va) {
            Err(e) => return e,
            Ok((sec, usec)) => {
                if sec < 0 || usec < 0 { return -22; }
                let wait_ns = (sec as u64) * 1_000_000_000 + (usec as u64) * 1_000;
                let zero    = wait_ns == 0;
                let dl      = if zero { now_ns() } else { now_ns() + wait_ns.min(5_000_000_000) };
                (dl, zero)
            }
        }
    };

    let rfds_k = match read_fdset(rfds_va, words) { Ok(v) => v, Err(e) => return e };
    let wfds_k = match read_fdset(wfds_va, words) { Ok(v) => v, Err(e) => return e };
    let efds_k = match read_fdset(efds_va, words) { Ok(v) => v, Err(e) => return e };

    // Build source list once — (Arc<dyn PollSource>, interest_mask, fd_index).
    struct SelectEntry {
        src:    Arc<dyn PollSource>,
        events: u32,
        fd:     usize,
        want_r: bool,
        want_w: bool,
        want_e: bool,
    }
    let mut entries: Vec<SelectEntry> = Vec::new();
    for fd in 0..nfds {
        let word   = fd / 64;
        let bit    = 1u64 << (fd % 64);
        let want_r = rfds_va != 0 && rfds_k[word] & bit != 0;
        let want_w = wfds_va != 0 && wfds_k[word] & bit != 0;
        let want_e = efds_va != 0 && efds_k[word] & bit != 0;
        if !want_r && !want_w && !want_e { continue; }
        let mut events = 0u32;
        if want_r { events |= POLLIN; }
        if want_w { events |= POLLOUT; }
        if want_e { events |= POLLIN | POLLOUT; }
        if let Some(src) = fd_poll_source(fd) {
            entries.push(SelectEntry { src, events, fd, want_r, want_w, want_e });
        }
    }
    let cancel = current_cancel();
    let cancel_ref = cancel.as_deref();

    let mut out_r = alloc::vec![0u64; words];
    let mut out_w = alloc::vec![0u64; words];
    let mut out_e = alloc::vec![0u64; words];

    loop {
        out_r.fill(0); out_w.fill(0); out_e.fill(0);
        let mut total = 0i32;

        for e in &entries {
            let ready = e.src.poll(e.events);
            let word  = e.fd / 64;
            let bit   = 1u64 << (e.fd % 64);
            if ready & (POLLIN | POLLRDNORM) != 0 && e.want_r {
                out_r[word] |= bit; total += 1;
            }
            if ready & (POLLOUT | POLLWRNORM) != 0 && e.want_w {
                out_w[word] |= bit; total += 1;
            }
            if ready & (POLLERR | POLLHUP | POLLNVAL) != 0 && e.want_e {
                out_e[word] |= bit; total += 1;
            }
        }

        if total > 0 || zero_poll || !before_deadline(deadline_ns) {
            write_fdset(rfds_va, &out_r);
            write_fdset(wfds_va, &out_w);
            write_fdset(efds_va, &out_e);
            write_timeval_remaining(tv_va, deadline_ns);
            return total as isize;
        }

        // Sleep until any source fires, deadline, or signal.
        let sources: Vec<(Arc<dyn PollSource>, ReadyMask)> =
            entries.iter().map(|e| (e.src.clone(), e.events)).collect();
        let reason = wait_any(&sources, cancel_ref, Some(deadline_ns));
        if reason == WakeReason::Cancelled {
            write_timeval_remaining(tv_va, deadline_ns);
            return -4; // EINTR
        }
    }
}

// ── sys_pselect6  [NR 270] ────────────────────────────────────────────────────

pub fn sys_pselect6(
    nfds:      usize,
    rfds_va:   usize,
    wfds_va:   usize,
    efds_va:   usize,
    ts_va:     usize,
    sigarg_va: usize,
) -> isize {
    if nfds > 1024 { return -22; }

    let words     = (nfds + 63) / 64;
    let bmap_size = words * 8;
    for va in [rfds_va, wfds_va, efds_va] {
        if va != 0 && !validate_user_ptr(va, bmap_size) { return -14; }
    }

    let (deadline_ns, zero_poll) = if ts_va == 0 {
        (now_ns() + 5_000_000_000, false)
    } else {
        match read_timespec(ts_va) {
            Err(e) => return e,
            Ok((sec, nsec)) => {
                if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 { return -22; }
                let wait_ns = (sec as u64) * 1_000_000_000 + (nsec as u64);
                let zero    = wait_ns == 0;
                let dl      = if zero { now_ns() } else { now_ns() + wait_ns.min(5_000_000_000) };
                (dl, zero)
            }
        }
    };

    let rfds_k = match read_fdset(rfds_va, words) { Ok(v) => v, Err(e) => return e };
    let wfds_k = match read_fdset(wfds_va, words) { Ok(v) => v, Err(e) => return e };
    let efds_k = match read_fdset(efds_va, words) { Ok(v) => v, Err(e) => return e };

    struct SelectEntry {
        src:    Arc<dyn PollSource>,
        events: u32,
        fd:     usize,
        want_r: bool,
        want_w: bool,
        want_e: bool,
    }
    let mut entries: Vec<SelectEntry> = Vec::new();
    for fd in 0..nfds {
        let word   = fd / 64;
        let bit    = 1u64 << (fd % 64);
        let want_r = rfds_va != 0 && rfds_k[word] & bit != 0;
        let want_w = wfds_va != 0 && wfds_k[word] & bit != 0;
        let want_e = efds_va != 0 && efds_k[word] & bit != 0;
        if !want_r && !want_w && !want_e { continue; }
        let mut events = 0u32;
        if want_r { events |= POLLIN; }
        if want_w { events |= POLLOUT; }
        if want_e { events |= POLLIN | POLLOUT; }
        if let Some(src) = fd_poll_source(fd) {
            entries.push(SelectEntry { src, events, fd, want_r, want_w, want_e });
        }
    }

    let old_mask = pselect_swap_sigmask(sigarg_va);
    let cancel   = current_cancel();
    let cancel_ref = cancel.as_deref();

    let mut out_r = alloc::vec![0u64; words];
    let mut out_w = alloc::vec![0u64; words];
    let mut out_e = alloc::vec![0u64; words];

    let ret = loop {
        out_r.fill(0); out_w.fill(0); out_e.fill(0);
        let mut total = 0i32;

        for e in &entries {
            let ready = e.src.poll(e.events);
            let word  = e.fd / 64;
            let bit   = 1u64 << (e.fd % 64);
            if ready & (POLLIN | POLLRDNORM) != 0 && e.want_r {
                out_r[word] |= bit; total += 1;
            }
            if ready & (POLLOUT | POLLWRNORM) != 0 && e.want_w {
                out_w[word] |= bit; total += 1;
            }
            if ready & (POLLERR | POLLHUP | POLLNVAL) != 0 && e.want_e {
                out_e[word] |= bit; total += 1;
            }
        }

        if total > 0 || zero_poll || !before_deadline(deadline_ns) {
            write_fdset(rfds_va, &out_r);
            write_fdset(wfds_va, &out_w);
            write_fdset(efds_va, &out_e);
            break total as isize;
        }

        let sources: Vec<(Arc<dyn PollSource>, ReadyMask)> =
            entries.iter().map(|e| (e.src.clone(), e.events)).collect();
        let reason = wait_any(&sources, cancel_ref, Some(deadline_ns));
        if reason == WakeReason::Cancelled {
            write_fdset(rfds_va, &out_r);
            write_fdset(wfds_va, &out_w);
            write_fdset(efds_va, &out_e);
            break -4; // EINTR
        }
    };

    pselect_restore_sigmask(old_mask);
    ret
}

// ── sys_poll  [NR 7] ────────────────────────────────────────────────────────────

#[repr(C)]
struct PollFd {
    fd:      i32,
    events:  i16,
    revents: i16,
}

struct PollFdCopy {
    idx:    usize,  // index into the user pollfd array (for revents write-back)
    fd:     usize,
    events: u32,
    src:    Arc<dyn PollSource>,
}

pub fn sys_poll(fds_va: usize, nfds: usize, timeout_ms: i32) -> isize {
    let deadline_ns = ms_to_deadline_ns(timeout_ms);
    let zero_poll   = timeout_ms == 0;
    let cancel      = current_cancel();
    let cancel_ref  = cancel.as_deref();

    // nfds == 0: pure timeout sleep — no spin loop.
    if nfds == 0 {
        if !zero_poll {
            let wq     = WaitQueue::new();
            let reason = wq.wait(0, cancel_ref, Some(deadline_ns));
            if reason == WakeReason::Cancelled { return -4; }
        }
        return 0;
    }

    if nfds > 1024 { return -22; }
    let struct_size = core::mem::size_of::<PollFd>();
    if !validate_user_ptr(fds_va, nfds * struct_size) { return -14; }

    // Parse pollfd array and resolve PollSource for each fd once.
    let mut pfds: Vec<PollFdCopy> = Vec::with_capacity(nfds);
    for i in 0..nfds {
        let pfd_va = fds_va + i * struct_size;
        let mut raw = [0u8; 8];
        if copy_from_user(&mut raw, pfd_va).is_err() { return -14; }
        let fd_i    = i32::from_le_bytes(raw[0..4].try_into().unwrap());
        let events  = i16::from_le_bytes(raw[4..6].try_into().unwrap()) as u32;
        if fd_i < 0 { continue; }
        let fd = fd_i as usize;
        if let Some(src) = fd_poll_source(fd) {
            pfds.push(PollFdCopy { idx: i, fd, events, src });
        } else {
            // Unknown fd — write POLLNVAL immediately.
            let rev = POLLNVAL as i16;
            let va  = fds_va + i * struct_size + 6;
            let _   = copy_to_user(va, &rev.to_le_bytes());
        }
    }

    loop {
        let mut total = 0i32;
        for pfc in &pfds {
            let ready  = pfc.src.poll(pfc.events);
            let rev    = ready as i16;
            let rev_va = fds_va + pfc.idx * struct_size + 6;
            if copy_to_user(rev_va, &rev.to_le_bytes()).is_err() { return -14; }
            if rev != 0 { total += 1; }
        }

        if total > 0 || zero_poll || !before_deadline(deadline_ns) {
            return total as isize;
        }

        // ONE scheduler sleep for all fds.
        let sources: Vec<(Arc<dyn PollSource>, ReadyMask)> =
            pfds.iter().map(|p| (p.src.clone(), p.events)).collect();
        let reason = wait_any(&sources, cancel_ref, Some(deadline_ns));
        if reason == WakeReason::Cancelled { return -4; } // EINTR
        // WakeReason::Timeout -> re-enter loop, deadline check will exit.
    }
}

pub fn sys_ppoll(
    fds_va: usize, nfds: usize,
    ts_va: usize, _sigmask_va: usize, _sigsetsize: usize,
) -> isize {
    let (timeout_ms, zero_poll): (i32, bool) = if ts_va == 0 {
        (-1, false)
    } else {
        match read_timespec(ts_va) {
            Err(e) => return e,
            Ok((sec, nsec)) => {
                if sec < 0 || nsec < 0 { return -22; }
                let ms = (sec * 1000) + (nsec / 1_000_000);
                (ms as i32, ms == 0)
            }
        }
    };
    let _ = zero_poll;
    sys_poll(fds_va, nfds, timeout_ms)
}

// ── epoll ────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct EpollEntry {
    fd:     i32,
    events: u32,
    data:   u64,
}

struct Epoll {
    entries: Vec<EpollEntry>,
}

const MAX_EPOLLS:    usize = 16;
const EPOLL_FD_BASE: usize = 0x3000_0000;

static EPOLL_TABLE: Mutex<[Option<Epoll>; MAX_EPOLLS]> =
    Mutex::new([const { None }; MAX_EPOLLS]);

pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

fn epoll_idx(epfd: usize) -> Option<usize> {
    if epfd < EPOLL_FD_BASE || epfd >= EPOLL_FD_BASE + MAX_EPOLLS { return None; }
    Some(epfd - EPOLL_FD_BASE)
}

pub fn sys_epoll_create(_size_or_flags: i32) -> isize {
    let mut tbl = EPOLL_TABLE.lock();
    for (i, slot) in tbl.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(Epoll { entries: Vec::new() });
            return (EPOLL_FD_BASE + i) as isize;
        }
    }
    -23 // ENFILE
}

pub fn sys_epoll_ctl(epfd: usize, op: i32, target_fd: i32, event_va: usize) -> isize {
    let idx = match epoll_idx(epfd) { Some(i) => i, None => return -9 };

    let (events, data): (u32, u64) = if op != EPOLL_CTL_DEL {
        if !validate_user_ptr(event_va, 12) { return -14; }
        let mut buf = [0u8; 12];
        if copy_from_user(&mut buf, event_va).is_err() { return -14; }
        let ev = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let da = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        (ev, da)
    } else {
        (0, 0)
    };

    let mut tbl = EPOLL_TABLE.lock();
    let ep = match tbl[idx].as_mut() { Some(e) => e, None => return -9 };

    match op {
        EPOLL_CTL_ADD => {
            if ep.entries.iter().any(|e| e.fd == target_fd) { return -17; }
            ep.entries.push(EpollEntry { fd: target_fd, events, data });
            0
        }
        EPOLL_CTL_MOD => {
            match ep.entries.iter_mut().find(|e| e.fd == target_fd) {
                Some(e) => { e.events = events; e.data = data; 0 }
                None    => -2,
            }
        }
        EPOLL_CTL_DEL => {
            let before = ep.entries.len();
            ep.entries.retain(|e| e.fd != target_fd);
            if ep.entries.len() < before { 0 } else { -2 }
        }
        _ => -22,
    }
}

/// sys_epoll_wait  [NR 232]
///
/// Re-reads interest list from EPOLL_TABLE on each wakeup so concurrent
/// EPOLL_CTL_MOD/DEL are immediately visible.
/// EPOLLONESHOT entries are disarmed after they fire.
pub fn sys_epoll_wait(epfd: usize, events_va: usize, maxevents: i32, timeout_ms: i32) -> isize {
    let idx = match epoll_idx(epfd) { Some(i) => i, None => return -9 };
    if maxevents <= 0 { return -22; }
    if !validate_user_ptr(events_va, maxevents as usize * 12) { return -14; }

    let deadline_ns = ms_to_deadline_ns(timeout_ms);
    let zero_poll   = timeout_ms == 0;
    let cancel      = current_cancel();
    let cancel_ref  = cancel.as_deref();

    loop {
        let mut found        = 0i32;
        let mut oneshot_fds: Vec<i32> = Vec::new();
        let mut sources:     Vec<(Arc<dyn PollSource>, ReadyMask)> = Vec::new();

        {
            // Re-read live interest list each iteration.
            let tbl = EPOLL_TABLE.lock();
            let ep  = match tbl[idx].as_ref() { Some(e) => e, None => return -9 };

            for entry in &ep.entries {
                if found >= maxevents { break; }
                let armed = entry.events & !EPOLLONESHOT;
                if armed == 0 { continue; } // disarmed one-shot

                // Collect PollSource for sleep even if not currently ready.
                if let Some(src) = fd_poll_source(entry.fd as usize) {
                    sources.push((src.clone(), armed));
                    let ready = src.poll(armed);
                    if ready == 0 { continue; }

                    let mut rec = [0u8; 12];
                    rec[0..4].copy_from_slice(&ready.to_le_bytes());
                    rec[4..12].copy_from_slice(&entry.data.to_le_bytes());
                    let out_va = events_va + found as usize * 12;
                    if copy_to_user(out_va, &rec).is_err() { return -14; }
                    found += 1;

                    if entry.events & EPOLLONESHOT != 0 {
                        oneshot_fds.push(entry.fd);
                    }
                }
            }
        } // EPOLL_TABLE lock released

        // Disarm fired one-shot entries.
        if !oneshot_fds.is_empty() {
            let mut tbl = EPOLL_TABLE.lock();
            if let Some(ep) = tbl[idx].as_mut() {
                for fd in &oneshot_fds {
                    if let Some(e) = ep.entries.iter_mut().find(|e| e.fd == *fd) {
                        e.events = EPOLLONESHOT;
                    }
                }
            }
        }

        if found > 0 || zero_poll || !before_deadline(deadline_ns) {
            return found as isize;
        }

        // ONE scheduler sleep across all watched fds.
        let reason = wait_any(&sources, cancel_ref, Some(deadline_ns));
        if reason == WakeReason::Cancelled { return -4; } // EINTR
    }
}

pub fn sys_epoll_pwait(
    epfd: usize, events_va: usize, maxevents: i32,
    timeout_ms: i32, _sigmask_va: usize, _sigsetsize: usize,
) -> isize {
    sys_epoll_wait(epfd, events_va, maxevents, timeout_ms)
}

pub fn epoll_close(fdno: usize) -> bool {
    let idx = match epoll_idx(fdno) { Some(i) => i, None => return false };
    let mut tbl = EPOLL_TABLE.lock();
    if tbl[idx].is_some() { tbl[idx] = None; true } else { false }
}

pub fn is_epoll_fd(fdno: usize) -> bool {
    let idx = match epoll_idx(fdno) { Some(i) => i, None => return false };
    EPOLL_TABLE.lock()[idx].is_some()
}
