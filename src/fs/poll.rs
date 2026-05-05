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
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── poll event flags (POSIX) ────────────────────────────────────────────────────
pub const POLLIN:     u32 = 0x0001;
pub const POLLPRI:    u32 = 0x0002;
pub const POLLOUT:    u32 = 0x0004;
pub const POLLERR:    u32 = 0x0008;
pub const POLLHUP:    u32 = 0x0010;
pub const POLLNVAL:   u32 = 0x0020;
pub const POLLRDNORM: u32 = 0x0040;
pub const POLLWRNORM: u32 = 0x0100;

// ── readiness oracle ────────────────────────────────────────────────────────────────────

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
    // regular VFS fd — treat as always ready.
    // No upper-bound cap: vfs::fd_exists handles the bounds check internally,
    // so fds > 64 (valid after many open() calls) are no longer misreported
    // as POLLNVAL.
    if fdno >= 3 && crate::fs::vfs::fd_exists(fdno) {
        let mut r = 0u32;
        if events & POLLIN  != 0 { r |= POLLIN  | POLLRDNORM; }
        if events & POLLOUT != 0 { r |= POLLOUT  | POLLWRNORM; }
        return r;
    }
    POLLNVAL
}

// ── timeout helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn before_deadline(deadline_ns: u64) -> bool {
    crate::time::monotonic_ns() < deadline_ns
}

fn timespec_to_deadline_ns(ts_va: usize) -> u64 {
    if ts_va == 0 { return u64::MAX; }
    if !validate_user_ptr(ts_va, 16) { return 0; }
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, ts_va).is_err() { return 0; }
    let secs  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let nsecs = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if secs < 0 || nsecs < 0 { return 0; }
    let wait_ns = secs as u64 * 1_000_000_000 + nsecs as u64;
    crate::time::monotonic_ns() + wait_ns.min(5_000_000_000)
}

fn ms_to_deadline_ns(ms: i32) -> u64 {
    if ms == 0 { return crate::time::monotonic_ns(); }
    let wait_ns = if ms < 0 { 5_000_000_000u64 } else { (ms as u64) * 1_000_000 };
    crate::time::monotonic_ns() + wait_ns
}

// ── sys_select ──────────────────────────────────────────────────────────────────

/// sys_select(nfds, readfds, writefds, exceptfds, timeout)  [NR 23]
pub fn sys_select(
    nfds:    usize,
    rfds_va: usize,
    wfds_va: usize,
    efds_va: usize,
    tv_va:   usize,
) -> isize {
    if nfds > 1024 { return -22; } // EINVAL

    let words     = (nfds + 63) / 64;
    let bmap_size = words * 8;

    if rfds_va != 0 && !validate_user_ptr(rfds_va, bmap_size) { return -14; }
    if wfds_va != 0 && !validate_user_ptr(wfds_va, bmap_size) { return -14; }
    if efds_va != 0 && !validate_user_ptr(efds_va, bmap_size) { return -14; }

    let deadline_ns = if tv_va == 0 {
        crate::time::monotonic_ns() + 5_000_000_000
    } else if !validate_user_ptr(tv_va, 16) {
        return -14;
    } else {
        let mut tv_buf = [0u8; 16];
        if copy_from_user(&mut tv_buf, tv_va).is_err() { return -14; }
        let sec  = i64::from_le_bytes(tv_buf[0..8].try_into().unwrap());
        let usec = i64::from_le_bytes(tv_buf[8..16].try_into().unwrap());
        if sec == 0 && usec == 0 {
            crate::time::monotonic_ns()
        } else {
            let wait_ns = (sec as u64) * 1_000_000_000 + (usec as u64) * 1_000;
            crate::time::monotonic_ns() + wait_ns.min(5_000_000_000)
        }
    };

    // Read input bitmaps once, before the spin loop.
    let mut rfds_k = alloc::vec![0u64; words];
    let mut wfds_k = alloc::vec![0u64; words];
    let read_bmap = |va: usize, dst: &mut Vec<u64>| -> bool {
        if va == 0 { return true; }
        for i in 0..dst.len() {
            let mut buf = [0u8; 8];
            if copy_from_user(&mut buf, va + i * 8).is_err() { return false; }
            dst[i] = u64::from_le_bytes(buf);
        }
        true
    };
    if !read_bmap(rfds_va, &mut rfds_k) { return -14; }
    if !read_bmap(wfds_va, &mut wfds_k) { return -14; }

    // Allocate result bitmaps once outside the spin loop; zero them each tick.
    let mut out_r = alloc::vec![0u64; words];
    let mut out_w = alloc::vec![0u64; words];
    let mut out_e = alloc::vec![0u64; words];

    loop {
        // Zero result bitmaps for this tick (cheaper than re-allocating).
        out_r.fill(0);
        out_w.fill(0);
        out_e.fill(0);
        let mut total = 0i32;

        for fd in 0..nfds {
            let word   = fd / 64;
            let bit    = 1u64 << (fd % 64);
            let want_r = rfds_va != 0 && (rfds_k[word] & bit != 0);
            let want_w = wfds_va != 0 && (wfds_k[word] & bit != 0);

            let mut events = 0u32;
            if want_r { events |= POLLIN; }
            if want_w { events |= POLLOUT; }
            if events == 0 { continue; }

            let ready = fd_ready(fd, events);
            if ready & POLLIN  != 0 && want_r { out_r[word] |= bit; total += 1; }
            if ready & POLLOUT != 0 && want_w { out_w[word] |= bit; total += 1; }
            if ready & (POLLERR | POLLHUP | POLLNVAL) != 0 {
                out_e[word] |= bit; total += 1;
            }
        }

        if total > 0 || !before_deadline(deadline_ns) {
            let write_bmap = |va: usize, src: &[u64]| {
                if va == 0 { return; }
                for (i, &w) in src.iter().enumerate() {
                    let _ = copy_to_user(va + i * 8, &w.to_le_bytes());
                }
            };
            write_bmap(rfds_va, &out_r);
            write_bmap(wfds_va, &out_w);
            write_bmap(efds_va, &out_e);
            return total as isize;
        }
        core::hint::spin_loop();
    }
}

// ── sys_pselect6 ──────────────────────────────────────────────────────────────────

/// sys_pselect6 — like select with nanosecond timeout; sigmask ignored.
pub fn sys_pselect6(
    nfds: usize, rfds_va: usize, wfds_va: usize, efds_va: usize,
    ts_va: usize, _sigmask_va: usize,
) -> isize {
    sys_select(nfds, rfds_va, wfds_va, efds_va, ts_va)
}

// ── sys_poll ──────────────────────────────────────────────────────────────────────

/// `struct pollfd` layout (matches Linux x86-64): fd(i32) events(i16) revents(i16) → 8 bytes.
#[repr(C)]
struct PollFd {
    fd:      i32,
    events:  i16,
    revents: i16,
}

/// sys_poll(fds_va, nfds, timeout_ms)  [NR 7]
pub fn sys_poll(fds_va: usize, nfds: usize, timeout_ms: i32) -> isize {
    if nfds > 1024 { return -22; }
    if !validate_user_ptr(fds_va, nfds * core::mem::size_of::<PollFd>()) { return -14; }
    let deadline_ns = ms_to_deadline_ns(timeout_ms);

    loop {
        let mut total = 0i32;
        for i in 0..nfds {
            let pfd_va = fds_va + i * core::mem::size_of::<PollFd>();
            let mut raw = [0u8; 8];
            if copy_from_user(&mut raw, pfd_va).is_err() { return -14; }
            let fd     = i32::from_le_bytes(raw[0..4].try_into().unwrap());
            let events = i16::from_le_bytes(raw[4..6].try_into().unwrap());
            if fd < 0 { continue; }

            let ready = fd_ready(fd as usize, events as u32);
            let rev   = ready as i16;
            if copy_to_user(pfd_va + 6, &rev.to_le_bytes()).is_err() { return -14; }
            if rev != 0 { total += 1; }
        }
        if total > 0 || !before_deadline(deadline_ns) {
            return total as isize;
        }
        core::hint::spin_loop();
    }
}

/// sys_ppoll — poll with nanosecond timeout + signal mask (mask ignored).
pub fn sys_ppoll(
    fds_va: usize, nfds: usize,
    ts_va: usize, _sigmask_va: usize, _sigsetsize: usize,
) -> isize {
    let timeout_ms: i32 = if ts_va == 0 {
        -1
    } else if !validate_user_ptr(ts_va, 16) {
        return -14;
    } else {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, ts_va).is_err() { return -14; }
        let sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        ((sec * 1000) + (nsec / 1_000_000)) as i32
    };
    sys_poll(fds_va, nfds, timeout_ms)
}

// ── epoll ─────────────────────────────────────────────────────────────────────────

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

/// sys_epoll_create(size) [NR 213] / sys_epoll_create1(flags) [NR 291]
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
/// `event_va` → `struct epoll_event { u32 events; u64 data; }` (12 bytes, packed)
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

/// sys_epoll_wait(epfd, events_va, maxevents, timeout_ms)  [NR 232]
/// `events_va` → array of `struct epoll_event` (12 bytes each).
pub fn sys_epoll_wait(epfd: usize, events_va: usize, maxevents: i32, timeout_ms: i32) -> isize {
    let idx = match epoll_idx(epfd) { Some(i) => i, None => return -9 };
    if maxevents <= 0 { return -22; }
    if !validate_user_ptr(events_va, maxevents as usize * 12) { return -14; }

    let deadline_ns = ms_to_deadline_ns(timeout_ms);

    // Snapshot the interest list once before the spin loop.
    // epoll_ctl mutations during a wait are rare; if they occur the worst
    // case is that the waiter misses one edge — acceptable on a single-CPU
    // cooperative kernel where epoll_ctl cannot run concurrently anyway.
    let interest: Vec<EpollEntry> = {
        let tbl = EPOLL_TABLE.lock();
        match tbl[idx].as_ref() {
            Some(ep) => ep.entries.clone(),
            None     => return -9,
        }
    };

    loop {
        let mut found = 0i32;
        for entry in &interest {
            if found >= maxevents { break; }
            let ready = fd_ready(entry.fd as usize, entry.events);
            if ready == 0 { continue; }
            let mut rec = [0u8; 12];
            rec[0..4].copy_from_slice(&ready.to_le_bytes());
            rec[4..12].copy_from_slice(&entry.data.to_le_bytes());
            let out_va = events_va + found as usize * 12;
            if copy_to_user(out_va, &rec).is_err() { return -14; }
            found += 1;
        }

        if found > 0 || !before_deadline(deadline_ns) {
            return found as isize;
        }
        core::hint::spin_loop();
    }
}

/// sys_epoll_pwait — same as epoll_wait, sigmask ignored.
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
