//! I/O multiplexing: select(2), pselect6(2), poll(2), ppoll(2),
//! epoll_create(2), epoll_ctl(2), epoll_wait(2).
//!
//! ## Fixes in this revision
//!
//!   - fd_ready: translate user fd → backing fd before checking eventfd,
//!     timerfd, devfs, and VFS readiness.  Previously those checks used the
//!     user fd directly as a backing fd, causing POLLNVAL for valid fds.
//!   - select / pselect6: exceptfds membership now derived from efds_va
//!     instead of accidentally reusing rfds/wfds membership.
//!   - epoll_wait: re-reads the interest list from EPOLL_TABLE each scan
//!     so EPOLL_CTL_MOD/DEL while a waiter is blocked become visible.
//!   - EPOLLONESHOT: a ready one-shot entry is disarmed after reporting;
//!     must be re-armed with EPOLL_CTL_MOD (matches Linux).
//!
//! ## Architecture
//!
//!   All four interfaces share a single underlying readiness oracle:
//!   `fd_ready(fdno, events) -> u32`.
//!
//!   | Backing        | POLLIN ready when            | POLLOUT ready when          |
//!   |----------------|------------------------------|------------------------------|
//!   | stdin (fd 0)   | TTY ring buffer non-empty    | always                      |
//!   | stdout/stderr  | always                       | always                      |
//!   | Pipe read-end  | pipe ring buffer non-empty   | N/A                         |
//!   | Pipe write-end | N/A                          | pipe buffer not full        |
//!   | Pipe (closed)  | POLLHUP                      |                             |
//!   | Socket         | recv-buf non-empty           | send-buf not full           |
//!   | eventfd        | counter > 0                  | always (counter < MAX)      |
//!   | timerfd        | expirations > 0              | N/A                         |
//!   | devfs / file   | always                       | always                      |
//!   | unknown fd     | POLLNVAL                     |                             |
//!
//! ## select / pselect6 differences
//!
//!   `select`  uses `struct timeval`  (seconds + microseconds, 2×i64 on x86-64).
//!   `pselect6` uses `struct timespec` (seconds + nanoseconds,  2×i64 on x86-64).
//!
//!   `pselect6` 6th argument is NOT a raw sigset_t pointer.  It is a pointer to
//!   a two-word struct  `{ const sigset_t *ss; size_t ss_len; }`.
//!
//! ## Timeout writeback
//!
//!   `select`   writes back the remaining timeval on return (POSIX §2.10.16).
//!   `pselect6` does NOT write back the timespec (Linux-compatible behaviour).
//!
//! ## Timeout handling
//!
//!   `timeout == 0` means poll once and return immediately.
//!   `timeout < 0` (NULL pointer) means wait indefinitely — capped at 5 s.
//!
//! ## epoll
//!
//!   Epoll instance fds live in EPOLL_TABLE in [EPOLL_FD_BASE, EPOLL_FD_BASE+MAX_EPOLLS).

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── poll event flags ──────────────────────────────────────────────────────────
pub const POLLIN:       u32 = 0x0001;
pub const POLLPRI:      u32 = 0x0002;
pub const POLLOUT:      u32 = 0x0004;
pub const POLLERR:      u32 = 0x0008;
pub const POLLHUP:      u32 = 0x0010;
pub const POLLNVAL:     u32 = 0x0020;
pub const POLLRDNORM:   u32 = 0x0040;
pub const POLLWRNORM:   u32 = 0x0100;
pub const EPOLLONESHOT: u32 = 0x4000_0000;

// ── fd namespace helper ───────────────────────────────────────────────────────

/// Translate a process-local user fd to its kernel backing fd.
#[inline]
fn user_fd_to_bfd(user_fd: usize) -> Option<usize> {
    let pid = crate::proc::scheduler::current_pid();
    let r = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if r < 0 { None } else { Some(r as usize) }
}

// ── readiness oracle ──────────────────────────────────────────────────────────

/// Return the subset of `events` that are currently ready on `fdno`
/// (a user-visible fd), plus POLLERR / POLLHUP / POLLNVAL as appropriate.
pub fn fd_ready(fdno: usize, events: u32) -> u32 {
    // stdin
    if fdno == 0 {
        let readable = crate::shell::tty::bytes_available() > 0;
        let mut r = if readable { POLLIN | POLLRDNORM } else { 0 };
        if events & POLLOUT != 0 { r |= POLLOUT | POLLWRNORM; }
        return r & (events | POLLERR | POLLHUP);
    }
    // stdout / stderr — always writable
    if fdno == 1 || fdno == 2 {
        return (POLLOUT | POLLWRNORM | POLLIN) & (events | POLLERR | POLLHUP);
    }
    // Pipes: is_pipe_fd / pipe_poll translate user fd → bfd internally.
    if crate::fs::pipe::is_pipe_fd(fdno) {
        return crate::fs::pipe::pipe_poll(fdno, events);
    }
    // Sockets: socket_poll translates internally.
    if let Some(ready) = crate::net::socket::socket_poll(fdno, events) {
        return ready;
    }

    // All remaining subsystems operate on backing fds — translate once here.
    let bfd = match user_fd_to_bfd(fdno) {
        Some(b) => b,
        None    => return POLLNVAL,
    };

    if crate::fs::eventfd::is_eventfd(bfd) {
        return crate::fs::eventfd::eventfd_poll(bfd, events);
    }
    if crate::fs::timerfd::is_timerfd(bfd) {
        return crate::fs::timerfd::timerfd_poll(bfd, events);
    }
    if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        let mut r = 0u32;
        if events & POLLIN  != 0 { r |= POLLIN  | POLLRDNORM; }
        if events & POLLOUT != 0 { r |= POLLOUT  | POLLWRNORM; }
        return r;
    }
    if crate::fs::vfs::fd_exists(bfd) {
        let mut r = 0u32;
        if events & POLLIN  != 0 { r |= POLLIN  | POLLRDNORM; }
        if events & POLLOUT != 0 { r |= POLLOUT  | POLLWRNORM; }
        return r;
    }
    POLLNVAL
}

// ── time helpers ──────────────────────────────────────────────────────────────

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
    let now = now_ns();
    let rem_ns   = if deadline_ns > now { deadline_ns - now } else { 0 };
    let rem_sec  = rem_ns / 1_000_000_000;
    let rem_usec = (rem_ns % 1_000_000_000) / 1_000;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&(rem_sec  as i64).to_le_bytes());
    buf[8..16].copy_from_slice(&(rem_usec as i64).to_le_bytes());
    let _ = copy_to_user(va, &buf);
}

fn ms_to_deadline_ns(ms: i32) -> u64 {
    if ms == 0 { return now_ns(); }
    let wait_ns = if ms < 0 { 5_000_000_000u64 } else { (ms as u64) * 1_000_000 };
    now_ns() + wait_ns
}

// ── fd_set bitmap helpers ─────────────────────────────────────────────────────

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

// ── signal mask helpers (pselect6) ────────────────────────────────────────────
//
// pselect6's 6th argument is a pointer to:
//   struct { const sigset_t *ss; size_t ss_len; }   (16 bytes on x86-64)
// We dereference ss_ptr, atomically swap the task's signal mask, and restore
// it on exit.

#[repr(C)]
struct Pselect6SigArg {
    ss_ptr: u64,
    ss_len: u64,
}

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
        let pid = crate::proc::scheduler::current_pid();
        crate::proc::signal::set_sigmask(pid, m);
    }
}

// ── sys_select  [NR 23] ───────────────────────────────────────────────────────
//
// select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
//
// On return *tv is updated with remaining time (POSIX §2.10.16).
// exceptfds bits are set for fds with POLLERR | POLLHUP | POLLNVAL.

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
    // FIX: read efds from efds_va, not derived from rfds/wfds.
    let efds_k = match read_fdset(efds_va, words) { Ok(v) => v, Err(e) => return e };

    let mut out_r = alloc::vec![0u64; words];
    let mut out_w = alloc::vec![0u64; words];
    let mut out_e = alloc::vec![0u64; words];

    loop {
        out_r.fill(0);
        out_w.fill(0);
        out_e.fill(0);
        let mut total = 0i32;

        for fd in 0..nfds {
            let word = fd / 64;
            let bit  = 1u64 << (fd % 64);

            let want_r = rfds_va != 0 && (rfds_k[word] & bit != 0);
            let want_w = wfds_va != 0 && (wfds_k[word] & bit != 0);
            // FIX: want_e based solely on efds_k.
            let want_e = efds_va != 0 && (efds_k[word] & bit != 0);

            if !want_r && !want_w && !want_e { continue; }

            let mut events = 0u32;
            if want_r { events |= POLLIN; }
            if want_w { events |= POLLOUT; }
            if want_e { events |= POLLIN | POLLOUT; }

            let ready = fd_ready(fd, events);

            if ready & (POLLIN | POLLRDNORM) != 0 && want_r {
                out_r[word] |= bit;
                total += 1;
            }
            if ready & (POLLOUT | POLLWRNORM) != 0 && want_w {
                out_w[word] |= bit;
                total += 1;
            }
            if ready & (POLLERR | POLLHUP | POLLNVAL) != 0 && want_e {
                out_e[word] |= bit;
                total += 1;
            }
        }

        if total > 0 || zero_poll || !before_deadline(deadline_ns) {
            write_fdset(rfds_va, &out_r);
            write_fdset(wfds_va, &out_w);
            write_fdset(efds_va, &out_e);
            write_timeval_remaining(tv_va, deadline_ns);
            return total as isize;
        }
        core::hint::spin_loop();
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

    let old_mask = pselect_swap_sigmask(sigarg_va);

    let mut out_r = alloc::vec![0u64; words];
    let mut out_w = alloc::vec![0u64; words];
    let mut out_e = alloc::vec![0u64; words];

    let ret = loop {
        out_r.fill(0);
        out_w.fill(0);
        out_e.fill(0);
        let mut total = 0i32;

        for fd in 0..nfds {
            let word = fd / 64;
            let bit  = 1u64 << (fd % 64);

            let want_r = rfds_va != 0 && (rfds_k[word] & bit != 0);
            let want_w = wfds_va != 0 && (wfds_k[word] & bit != 0);
            let want_e = efds_va != 0 && (efds_k[word] & bit != 0);

            if !want_r && !want_w && !want_e { continue; }

            let mut events = 0u32;
            if want_r { events |= POLLIN; }
            if want_w { events |= POLLOUT; }
            if want_e { events |= POLLIN | POLLOUT; }

            let ready = fd_ready(fd, events);

            if ready & (POLLIN | POLLRDNORM) != 0 && want_r {
                out_r[word] |= bit;
                total += 1;
            }
            if ready & (POLLOUT | POLLWRNORM) != 0 && want_w {
                out_w[word] |= bit;
                total += 1;
            }
            if ready & (POLLERR | POLLHUP | POLLNVAL) != 0 && want_e {
                out_e[word] |= bit;
                total += 1;
            }
        }

        if total > 0 || zero_poll || !before_deadline(deadline_ns) {
            write_fdset(rfds_va, &out_r);
            write_fdset(wfds_va, &out_w);
            write_fdset(efds_va, &out_e);
            break total as isize;
        }
        core::hint::spin_loop();
    };

    pselect_restore_sigmask(old_mask);
    ret
}

// ── sys_poll  [NR 7] ──────────────────────────────────────────────────────────

#[repr(C)]
struct PollFd {
    fd:      i32,
    events:  i16,
    revents: i16,
}

struct PollFdCopy {
    fd:     i32,
    events: i16,
}

pub fn sys_poll(fds_va: usize, nfds: usize, timeout_ms: i32) -> isize {
    if nfds == 0 {
        let deadline = ms_to_deadline_ns(timeout_ms);
        while before_deadline(deadline) { core::hint::spin_loop(); }
        return 0;
    }
    if nfds > 1024 { return -22; }
    let struct_size = core::mem::size_of::<PollFd>();
    if !validate_user_ptr(fds_va, nfds * struct_size) { return -14; }

    let mut pfds: Vec<PollFdCopy> = Vec::with_capacity(nfds);
    for i in 0..nfds {
        let pfd_va = fds_va + i * struct_size;
        let mut raw = [0u8; 8];
        if copy_from_user(&mut raw, pfd_va).is_err() { return -14; }
        pfds.push(PollFdCopy {
            fd:     i32::from_le_bytes(raw[0..4].try_into().unwrap()),
            events: i16::from_le_bytes(raw[4..6].try_into().unwrap()),
        });
    }

    let deadline_ns = ms_to_deadline_ns(timeout_ms);
    let zero_poll   = timeout_ms == 0;

    loop {
        let mut total = 0i32;
        for (i, pfc) in pfds.iter().enumerate() {
            if pfc.fd < 0 { continue; }
            let ready = fd_ready(pfc.fd as usize, pfc.events as u32);
            let rev   = ready as i16;
            let revents_va = fds_va + i * struct_size + 6;
            if copy_to_user(revents_va, &rev.to_le_bytes()).is_err() { return -14; }
            if rev != 0 { total += 1; }
        }
        if total > 0 || zero_poll || !before_deadline(deadline_ns) {
            return total as isize;
        }
        core::hint::spin_loop();
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

// ── epoll ─────────────────────────────────────────────────────────────────────

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
/// FIX 1: re-reads the interest list from EPOLL_TABLE on every scan so
///         concurrent EPOLL_CTL_MOD/DEL are immediately visible.
/// FIX 2: disarms EPOLLONESHOT entries after they fire.
pub fn sys_epoll_wait(epfd: usize, events_va: usize, maxevents: i32, timeout_ms: i32) -> isize {
    let idx = match epoll_idx(epfd) { Some(i) => i, None => return -9 };
    if maxevents <= 0 { return -22; }
    if !validate_user_ptr(events_va, maxevents as usize * 12) { return -14; }

    let deadline_ns = ms_to_deadline_ns(timeout_ms);
    let zero_poll   = timeout_ms == 0;

    loop {
        let mut found = 0i32;
        let mut oneshot_fds: Vec<i32> = Vec::new();

        {
            // Re-read live interest list each iteration (fixes stale snapshot).
            let tbl = EPOLL_TABLE.lock();
            let ep = match tbl[idx].as_ref() {
                Some(ep) => ep,
                None     => return -9,
            };

            for entry in &ep.entries {
                if found >= maxevents { break; }
                // Strip EPOLLONESHOT bookkeeping bit before checking readiness.
                let armed = entry.events & !EPOLLONESHOT;
                if armed == 0 { continue; } // disarmed one-shot — skip
                let ready = fd_ready(entry.fd as usize, armed);
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
        } // table lock released

        // Disarm fired one-shot entries: zero interest bits, keep EPOLLONESHOT
        // marker so the entry is not confused with a deleted one.
        if !oneshot_fds.is_empty() {
            let mut tbl = EPOLL_TABLE.lock();
            if let Some(ep) = tbl[idx].as_mut() {
                for fd in &oneshot_fds {
                    if let Some(e) = ep.entries.iter_mut().find(|e| e.fd == *fd) {
                        e.events = EPOLLONESHOT; // silent until EPOLL_CTL_MOD re-arms
                    }
                }
            }
        }

        if found > 0 || zero_poll || !before_deadline(deadline_ns) {
            return found as isize;
        }
        core::hint::spin_loop();
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
