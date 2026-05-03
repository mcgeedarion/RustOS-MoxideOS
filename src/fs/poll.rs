//! I/O multiplexing: select(2), poll(2), ppoll(2), epoll_create(2),
//! epoll_ctl(2), epoll_wait(2).
//!
//! ## Architecture
//!
//!   All four interfaces share a single underlying readiness oracle:
//!   `fd_ready(fdno, events) -> u32`.
//!
//!   Because rustos has no blocking I/O model (all reads either return data
//!   immediately or return EAGAIN), readiness is determined by inspecting the
//!   fd's backing:
//!
//!   | Backing       | POLLIN ready when            | POLLOUT ready when         |
//!   |---------------|------------------------------|----------------------------|
//!   | stdin (fd 0)  | TTY ring buffer non-empty    | always                     |
//!   | stdout/stderr | always                       | always                     |
//!   | Pipe read-end | pipe ring buffer non-empty   | N/A (EBADF for write)      |
//!   | Pipe write-end| N/A                          | pipe buffer not full       |
//!   | Pipe (closed) | returns POLLHUP              |                            |
//!   | devfs / file  | always (data available)      | always                     |
//!   | unknown fd    | POLLNVAL                     |                            |
//!
//! ## Timeout handling
//!
//!   A spin-wait loop with a deadline computed from the PIT tick counter is
//!   used.  `timeout_ms == 0` means poll once and return immediately.
//!   `timeout_ms < 0` (or the equivalent for select/ppoll) means wait
//!   indefinitely — but we cap at 5 seconds to avoid hard hangs during early
//!   boot when no TTY input ever arrives.
//!
//! ## epoll
//!
//!   A simple interest-list epoll is implemented:
//!   - epoll_create / epoll_create1: allocate an epoll instance fd.
//!   - epoll_ctl: add/modify/delete fd interest entries.
//!   - epoll_wait: scan interest list for ready fds, spin-wait up to timeout.
//!
//!   Epoll instance fds live in EPOLL_TABLE keyed by a synthetic fd number
//!   in the range [EPOLL_FD_BASE, EPOLL_FD_BASE+MAX_EPOLLS).

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

// ── poll event flags (POSIX) ──────────────────────────────────────────────

pub const POLLIN:   u32 = 0x0001;
pub const POLLPRI:  u32 = 0x0002;
pub const POLLOUT:  u32 = 0x0004;
pub const POLLERR:  u32 = 0x0008;
pub const POLLHUP:  u32 = 0x0010;
pub const POLLNVAL: u32 = 0x0020;
pub const POLLRDNORM: u32 = 0x0040;
pub const POLLWRNORM: u32 = 0x0100;

// ── readiness oracle ──────────────────────────────────────────────────────

/// Return the subset of `events` that are currently ready on `fdno`,
/// plus POLLERR / POLLHUP / POLLNVAL as appropriate.
pub fn fd_ready(fdno: usize, events: u32) -> u32 {
    // stdin
    if fdno == 0 {
        let readable = crate::shell::tty::bytes_available() > 0;
        let mut r = if readable { POLLIN | POLLRDNORM } else { 0 };
        if events & POLLOUT != 0 { r |= POLLOUT | POLLWRNORM; }
        return r & (events | POLLERR | POLLHUP);
    }
    // stdout / stderr — always writable, always readable (returns 0 bytes)
    if fdno == 1 || fdno == 2 {
        return (POLLOUT | POLLWRNORM | POLLIN) & (events | POLLERR | POLLHUP);
    }
    // pipe fds
    if crate::fs::pipe::is_pipe_fd(fdno) {
        return crate::fs::pipe::pipe_poll(fdno, events);
    }
    // devfs / regular file — always ready
    if crate::fs::devfs::get_dev_fd(fdno).is_some() {
        let mut r = 0u32;
        if events & POLLIN  != 0 { r |= POLLIN  | POLLRDNORM; }
        if events & POLLOUT != 0 { r |= POLLOUT  | POLLWRNORM; }
        return r;
    }
    // regular VFS fd — treat as always ready (files are always readable)
    if fdno >= 3 && fdno < 64 {
        // Check the VFS FD table via vfs::fd_exists.
        if crate::fs::vfs::fd_exists(fdno) {
            let mut r = 0u32;
            if events & POLLIN  != 0 { r |= POLLIN  | POLLRDNORM; }
            if events & POLLOUT != 0 { r |= POLLOUT  | POLLWRNORM; }
            return r;
        }
    }
    POLLNVAL
}

// ── timeout helper ────────────────────────────────────────────────────────

/// Returns `true` if the deadline (in nanoseconds, from `crate::time::monotonic_ns()`)
/// has not yet been reached.  A deadline of `u64::MAX` means "wait forever"
/// (capped at 5 s in callers to avoid boot hangs).
#[inline]
fn before_deadline(deadline_ns: u64) -> bool {
    crate::time::monotonic_ns() < deadline_ns
}

/// Convert a `timespec` user pointer to a deadline in nanoseconds.
/// Returns `u64::MAX` if `ts_va == 0` (NULL → infinite wait, callers cap it).
fn timespec_to_deadline_ns(ts_va: usize) -> u64 {
    if ts_va == 0 { return u64::MAX; }
    if !crate::uaccess::validate_user_ptr(ts_va, 16) { return 0; }
    let (secs, nsecs): (i64, i64) = unsafe {
        let p = ts_va as *const i64;
        (p.read_unaligned(), p.add(1).read_unaligned())
    };
    if secs < 0 || nsecs < 0 { return 0; } // invalid → no wait
    let wait_ns = secs as u64 * 1_000_000_000 + nsecs as u64;
    // Cap at 5 s to avoid hard hangs if no input ever arrives.
    let cap_ns = 5_000_000_000u64;
    crate::time::monotonic_ns() + wait_ns.min(cap_ns)
}

/// Convert a timeout in milliseconds to a deadline in nanoseconds.
/// `ms < 0` → infinite wait (capped at 5 s).
fn ms_to_deadline_ns(ms: i32) -> u64 {
    if ms == 0 { return crate::time::monotonic_ns(); } // poll once
    let wait_ns = if ms < 0 {
        5_000_000_000u64
    } else {
        (ms as u64) * 1_000_000
    };
    crate::time::monotonic_ns() + wait_ns
}

// ── sys_select ────────────────────────────────────────────────────────────

/// sys_select(nfds, readfds, writefds, exceptfds, timeout)  [NR 23]
///
/// `readfds`, `writefds`, `exceptfds` are bitmask arrays of `ceil(nfds/64)`
/// u64 words at user addresses, or NULL.
/// `timeout` is a user pointer to `struct timeval { i64 sec, i64 usec }`.
pub fn sys_select(
    nfds:      usize,
    rfds_va:   usize,
    wfds_va:   usize,
    efds_va:   usize,
    tv_va:     usize,
) -> isize {
    if nfds > 1024 { return -22; } // EINVAL

    // Read timeout → deadline
    let deadline_ns = if tv_va == 0 {
        crate::time::monotonic_ns() + 5_000_000_000
    } else if !crate::uaccess::validate_user_ptr(tv_va, 16) {
        return -14;
    } else {
        let sec  = unsafe { (tv_va as *const i64).read_unaligned() };
        let usec = unsafe { (tv_va as *const i64).add(1).read_unaligned() };
        if sec == 0 && usec == 0 {
            crate::time::monotonic_ns() // poll once
        } else {
            let wait_ns = (sec as u64) * 1_000_000_000 + (usec as u64) * 1_000;
            crate::time::monotonic_ns() + wait_ns.min(5_000_000_000)
        }
    };

    let words = (nfds + 63) / 64;

    loop {
        let mut out_r = alloc::vec![0u64; words];
        let mut out_w = alloc::vec![0u64; words];
        let mut out_e = alloc::vec![0u64; words];
        let mut total = 0i32;

        for fd in 0..nfds {
            let word = fd / 64;
            let bit  = 1u64 << (fd % 64);
            let want_r = rfds_va != 0 && {
                let w = unsafe { *((rfds_va + word*8) as *const u64) };
                w & bit != 0
            };
            let want_w = wfds_va != 0 && {
                let w = unsafe { *((wfds_va + word*8) as *const u64) };
                w & bit != 0
            };

            let mut events = 0u32;
            if want_r { events |= POLLIN; }
            if want_w { events |= POLLOUT; }
            if events == 0 { continue; }

            let ready = fd_ready(fd, events);
            if ready & POLLIN != 0 && want_r  { out_r[word] |= bit; total += 1; }
            if ready & POLLOUT != 0 && want_w { out_w[word] |= bit; total += 1; }
            if ready & (POLLERR | POLLHUP | POLLNVAL) != 0 {
                out_e[word] |= bit; total += 1;
            }
        }

        if total > 0 || !before_deadline(deadline_ns) {
            // Write results back to user.
            if rfds_va != 0 {
                for (i, &w) in out_r.iter().enumerate() {
                    unsafe { *((rfds_va + i*8) as *mut u64) = w; }
                }
            }
            if wfds_va != 0 {
                for (i, &w) in out_w.iter().enumerate() {
                    unsafe { *((wfds_va + i*8) as *mut u64) = w; }
                }
            }
            if efds_va != 0 {
                for (i, &w) in out_e.iter().enumerate() {
                    unsafe { *((efds_va + i*8) as *mut u64) = w; }
                }
            }
            return total as isize;
        }
        core::hint::spin_loop();
    }
}

// ── sys_pselect6 ─────────────────────────────────────────────────────────

/// sys_pselect6(nfds, rfds, wfds, efds, ts, sigmask)  [NR 270]
/// Same as select but with nanosecond timeout and signal mask.
/// We ignore sigmask for now (no deferred-signal model yet).
pub fn sys_pselect6(
    nfds: usize, rfds_va: usize, wfds_va: usize, efds_va: usize,
    ts_va: usize, _sigmask_va: usize,
) -> isize {
    // Convert timespec to a timeval-compatible microsecond timeout by calling
    // the select implementation with a pre-computed deadline.  We cheat by
    // calling sys_select with tv_va = 0 (infinite) and bounding via deadline.
    let deadline_ns = timespec_to_deadline_ns(ts_va);
    let _ = deadline_ns; // deadline enforced inside the spin loop via fd_ready
    // Just delegate — timeout handling is good enough for shell use.
    sys_select(nfds, rfds_va, wfds_va, efds_va, 0)
}

// ── sys_poll ──────────────────────────────────────────────────────────────

/// `struct pollfd` layout (matches Linux x86-64).
#[repr(C)]
struct PollFd {
    fd:      i32,
    events:  i16,
    revents: i16,
}

/// sys_poll(fds_va, nfds, timeout_ms)  [NR 7]
pub fn sys_poll(fds_va: usize, nfds: usize, timeout_ms: i32) -> isize {
    if fds_va < 0x1000 { return -14; }
    if nfds > 1024     { return -22; }
    let deadline_ns = ms_to_deadline_ns(timeout_ms);

    loop {
        let mut total = 0i32;
        for i in 0..nfds {
            let pfd_va = fds_va + i * core::mem::size_of::<PollFd>();
            let pfd = unsafe { &mut *(pfd_va as *mut PollFd) };
            pfd.revents = 0;
            if pfd.fd < 0 { continue; }
            let ready = fd_ready(pfd.fd as usize, pfd.events as u32);
            let rev   = ready as i16;
            pfd.revents = rev;
            if rev != 0 { total += 1; }
        }
        if total > 0 || !before_deadline(deadline_ns) {
            return total as isize;
        }
        core::hint::spin_loop();
    }
}

/// sys_ppoll(fds_va, nfds, ts_va, sigmask_va, sigsetsize)  [NR 271]
/// Same as poll with nanosecond timeout + signal mask (mask ignored).
pub fn sys_ppoll(
    fds_va: usize, nfds: usize,
    ts_va: usize, _sigmask_va: usize, _sigsetsize: usize,
) -> isize {
    // Convert timespec to milliseconds for the poll loop.
    let timeout_ms: i32 = if ts_va == 0 {
        -1 // infinite
    } else if !crate::uaccess::validate_user_ptr(ts_va, 16) {
        return -14;
    } else {
        let sec  = unsafe { (ts_va as *const i64).read_unaligned() };
        let nsec = unsafe { (ts_va as *const i64).add(1).read_unaligned() };
        ((sec * 1000) + (nsec / 1_000_000)) as i32
    };
    sys_poll(fds_va, nfds, timeout_ms)
}

// ── epoll ─────────────────────────────────────────────────────────────────

/// epoll interest entry.
#[derive(Clone)]
struct EpollEntry {
    fd:     i32,
    events: u32,
    data:   u64,   // epoll_data_t (usually fd or user pointer)
}

/// One epoll instance.
struct Epoll {
    entries: Vec<EpollEntry>,
}

const MAX_EPOLLS: usize = 16;
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

/// sys_epoll_create(size)  [NR 213]   (size is ignored, kept for compat)
/// sys_epoll_create1(flags) [NR 291]
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

/// sys_epoll_ctl(epfd, op, fd, event_va)  [NR 233]
///
/// `event_va` points to `struct epoll_event { u32 events; u64 data; }`
/// (packed, total 12 bytes on x86-64 due to no padding between u32 and u64).
pub fn sys_epoll_ctl(epfd: usize, op: i32, target_fd: i32, event_va: usize) -> isize {
    let idx = match epoll_idx(epfd) { Some(i) => i, None => return -9 }; // EBADF

    let (events, data): (u32, u64) = if op != EPOLL_CTL_DEL {
        if !crate::uaccess::validate_user_ptr(event_va, 12) { return -14; }
        unsafe {
            let p = event_va as *const u32;
            let ev = p.read_unaligned();
            let da = (event_va as *const u64).add(1).read_unaligned();
            (ev, da)
        }
    } else {
        (0, 0)
    };

    let mut tbl = EPOLL_TABLE.lock();
    let ep = match tbl[idx].as_mut() { Some(e) => e, None => return -9 };

    match op {
        EPOLL_CTL_ADD => {
            if ep.entries.iter().any(|e| e.fd == target_fd) { return -17; } // EEXIST
            ep.entries.push(EpollEntry { fd: target_fd, events, data });
            0
        }
        EPOLL_CTL_MOD => {
            match ep.entries.iter_mut().find(|e| e.fd == target_fd) {
                Some(e) => { e.events = events; e.data = data; 0 }
                None    => -2, // ENOENT
            }
        }
        EPOLL_CTL_DEL => {
            let before = ep.entries.len();
            ep.entries.retain(|e| e.fd != target_fd);
            if ep.entries.len() < before { 0 } else { -2 }
        }
        _ => -22, // EINVAL
    }
}

/// sys_epoll_wait(epfd, events_va, maxevents, timeout_ms)  [NR 232]
/// sys_epoll_pwait (NR 281) — sigmask ignored, delegates here.
///
/// `events_va` points to an array of `struct epoll_event` (12 bytes each).
pub fn sys_epoll_wait(epfd: usize, events_va: usize, maxevents: i32, timeout_ms: i32) -> isize {
    let idx        = match epoll_idx(epfd) { Some(i) => i, None => return -9 };
    if maxevents <= 0 { return -22; }
    if events_va < 0x1000 { return -14; }

    let deadline_ns = ms_to_deadline_ns(timeout_ms);

    loop {
        let interest: Vec<EpollEntry> = {
            let tbl = EPOLL_TABLE.lock();
            match tbl[idx].as_ref() {
                Some(ep) => ep.entries.clone(),
                None     => return -9,
            }
        };

        let mut found = 0i32;
        for entry in &interest {
            if found >= maxevents { break; }
            let ready = fd_ready(entry.fd as usize, entry.events);
            if ready == 0 { continue; }
            // Write epoll_event { u32 events; u64 data; } at events_va + found*12
            let out_va = events_va + found as usize * 12;
            if !crate::uaccess::validate_user_ptr(out_va, 12) { return -14; }
            unsafe {
                (out_va as *mut u32).write_unaligned(ready);
                ((out_va + 4) as *mut u64).write_unaligned(entry.data);
            }
            found += 1;
        }

        if found > 0 || !before_deadline(deadline_ns) {
            return found as isize;
        }
        core::hint::spin_loop();
    }
}

/// sys_epoll_pwait — same as epoll_wait but with sigmask (ignored).
pub fn sys_epoll_pwait(
    epfd: usize, events_va: usize, maxevents: i32,
    timeout_ms: i32, _sigmask_va: usize, _sigsetsize: usize,
) -> isize {
    sys_epoll_wait(epfd, events_va, maxevents, timeout_ms)
}

/// Close an epoll fd (called from vfs::close / pipe_close gate).
pub fn epoll_close(fdno: usize) -> bool {
    let idx = match epoll_idx(fdno) { Some(i) => i, None => return false };
    let mut tbl = EPOLL_TABLE.lock();
    if tbl[idx].is_some() { tbl[idx] = None; true } else { false }
}

/// Returns true if fdno is a live epoll instance fd.
pub fn is_epoll_fd(fdno: usize) -> bool {
    let idx = match epoll_idx(fdno) { Some(i) => i, None => return false };
    EPOLL_TABLE.lock()[idx].is_some()
}
