//! timerfd — Linux-compatible interval timer fds.
//!
//! ## Linux syscall numbers (x86-64)
//!   NR 283  timerfd_create(clockid, flags)
//!   NR 286  timerfd_settime(fd, flags, new_value, old_value)
//!   NR 287  timerfd_gettime(fd, curr_value)
//!   NR 288  timerfd_gettime64 (same on x86-64; alias of 287)
//!
//! ## Semantics
//!
//!   A timerfd holds an `itimerspec`:
//!     it_interval — repeat interval (0 → one-shot)
//!     it_value    — time until next expiry (0 → disarmed)
//!
//!   Once armed, the kernel counts expirations.  read(fd, buf, 8) returns
//!   the number of expirations since the last read as a little-endian u64.
//!   If no expirations have occurred: blocks (or EAGAIN if TFD_NONBLOCK).
//!
//!   poll/epoll: POLLIN when expirations > 0.
//!
//! ## Clocks supported
//!   CLOCK_REALTIME  (0) — mapped to monotonic_ns() for simplicity
//!   CLOCK_MONOTONIC (1) — monotonic_ns()
//!   Others          — returns EINVAL
//!
//! ## Flags
//!   TFD_NONBLOCK  (O_NONBLOCK = 2048)
//!   TFD_CLOEXEC   (O_CLOEXEC  = 524288)
//!   TFD_TIMER_ABSTIME (1) — it_value is absolute, not relative

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── constants ─────────────────────────────────────────────────────────────

pub const TIMERFD_FD_BASE: usize = 0x6000_0000;
const MAX_TIMERFDS: usize = 256;

pub const TFD_NONBLOCK:       u32 = 2048;    // O_NONBLOCK
pub const TFD_CLOEXEC:        u32 = 524288;  // O_CLOEXEC
pub const TFD_TIMER_ABSTIME:  i32 = 1;

const CLOCK_REALTIME:  u32 = 0;
const CLOCK_MONOTONIC: u32 = 1;

// ── data structures ───────────────────────────────────────────────────────

/// One `struct itimerspec` represented in nanoseconds.
#[derive(Clone, Copy, Default)]
pub struct ItimerspecNs {
    /// Repetition interval; 0 = one-shot.
    pub interval_ns: u64,
    /// Absolute deadline for next expiry; 0 = disarmed.
    pub next_ns:     u64,
}

#[derive(Clone, Copy)]
pub struct TimerFdEntry {
    pub spec:          ItimerspecNs,
    pub expirations:   u64,
    pub nonblocking:   bool,
}

// ── global table ──────────────────────────────────────────────────────────

static TABLE: Mutex<BTreeMap<usize, TimerFdEntry>> = Mutex::new(BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// ── helpers ───────────────────────────────────────────────────────────────

#[inline]
fn now_ns() -> u64 { crate::time::monotonic_ns() }

/// Read a `struct itimerspec` from user space.
/// Layout: { {i64 tv_sec, i64 tv_nsec}, {i64 tv_sec, i64 tv_nsec} } = 32 bytes.
/// Returns (interval_ns, value_ns) or Err(-14).
fn read_itimerspec(va: usize) -> Result<(u64, u64), isize> {
    if !validate_user_ptr(va, 32) { return Err(-14); }
    let mut buf = [0u8; 32];
    copy_from_user(&mut buf, va).map_err(|_| -14isize)?;
    let interval_sec  = i64::from_le_bytes(buf[ 0.. 8].try_into().unwrap());
    let interval_nsec = i64::from_le_bytes(buf[ 8..16].try_into().unwrap());
    let value_sec     = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let value_nsec    = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    let interval_ns = (interval_sec.max(0) as u64) * 1_000_000_000
                    + (interval_nsec.max(0) as u64);
    let value_ns    = (value_sec.max(0) as u64) * 1_000_000_000
                    + (value_nsec.max(0) as u64);
    Ok((interval_ns, value_ns))
}

/// Write a `struct itimerspec` to user space.
fn write_itimerspec(va: usize, interval_ns: u64, remaining_ns: u64) {
    if va == 0 { return; }
    let isec  = (interval_ns  / 1_000_000_000) as i64;
    let insec = (interval_ns  % 1_000_000_000) as i64;
    let rsec  = (remaining_ns / 1_000_000_000) as i64;
    let rnsec = (remaining_ns % 1_000_000_000) as i64;
    let mut buf = [0u8; 32];
    buf[ 0.. 8].copy_from_slice(&isec .to_le_bytes());
    buf[ 8..16].copy_from_slice(&insec.to_le_bytes());
    buf[16..24].copy_from_slice(&rsec .to_le_bytes());
    buf[24..32].copy_from_slice(&rnsec.to_le_bytes());
    let _ = copy_to_user(va, &buf);
}

/// Tick the timer for `fdno`: advance expirations if the deadline has passed.
/// Must be called with the table lock held.
fn tick(entry: &mut TimerFdEntry) {
    if entry.spec.next_ns == 0 { return; }
    let now = now_ns();
    if now < entry.spec.next_ns { return; }
    if entry.spec.interval_ns == 0 {
        // One-shot: fire once, disarm.
        entry.expirations += 1;
        entry.spec.next_ns = 0;
    } else {
        // Repeating: count all missed intervals.
        let elapsed   = now - entry.spec.next_ns;
        let full      = elapsed / entry.spec.interval_ns;
        entry.expirations += full + 1;
        entry.spec.next_ns += (full + 1) * entry.spec.interval_ns;
    }
}

// ── public API ────────────────────────────────────────────────────────────

/// Returns true if `fdno` is a live timerfd.
pub fn is_timerfd(fdno: usize) -> bool {
    fdno >= TIMERFD_FD_BASE && TABLE.lock().contains_key(&fdno)
}

// ── sys_timerfd_create [NR 283] ───────────────────────────────────────────

pub fn sys_timerfd_create(clockid: u32, flags: u32) -> isize {
    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC => {}
        _ => return -22, // EINVAL — unsupported clock
    }
    if TABLE.lock().len() >= MAX_TIMERFDS { return -24; } // EMFILE
    let id   = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let fdno = TIMERFD_FD_BASE + id;
    TABLE.lock().insert(fdno, TimerFdEntry {
        spec:        ItimerspecNs::default(),
        expirations: 0,
        nonblocking: flags & TFD_NONBLOCK != 0,
    });
    if flags & TFD_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fdno, true);
    }
    fdno as isize
}

// ── sys_timerfd_settime [NR 286] ──────────────────────────────────────────
//
// int timerfd_settime(int fd, int flags,
//                    const struct itimerspec *new_value,
//                    struct itimerspec       *old_value);

pub fn sys_timerfd_settime(fdno: usize, flags: i32,
                           new_va: usize, old_va: usize) -> isize {
    let (interval_ns, value_ns) = match read_itimerspec(new_va) {
        Ok(v)  => v,
        Err(e) => return e,
    };
    let mut tbl = TABLE.lock();
    let entry = match tbl.get_mut(&fdno) {
        Some(e) => e,
        None    => return -9, // EBADF
    };
    // Write back old spec before modifying.
    if old_va != 0 {
        let remaining = if entry.spec.next_ns > 0 {
            let n = now_ns();
            entry.spec.next_ns.saturating_sub(n)
        } else { 0 };
        drop(tbl); // release lock while doing user copy
        write_itimerspec(old_va, {
            let tbl2 = TABLE.lock();
            tbl2[&fdno].spec.interval_ns
        }, remaining);
        tbl = TABLE.lock();
        if let Some(e) = tbl.get_mut(&fdno) {
            entry_settime(e, flags, interval_ns, value_ns);
        }
    } else {
        entry_settime(entry, flags, interval_ns, value_ns);
    }
    0
}

/// Arm/disarm helper (called with lock held).
fn entry_settime(entry: &mut TimerFdEntry,
                 flags: i32, interval_ns: u64, value_ns: u64) {
    // Reset expirations on re-arm.
    entry.expirations = 0;
    if value_ns == 0 {
        // Disarm.
        entry.spec = ItimerspecNs::default();
        return;
    }
    entry.spec.interval_ns = interval_ns;
    entry.spec.next_ns = if flags & TFD_TIMER_ABSTIME != 0 {
        // Absolute: value_ns is the deadline.
        value_ns
    } else {
        // Relative: deadline = now + value_ns.
        now_ns() + value_ns
    };
}

// ── sys_timerfd_gettime [NR 287 / 288] ────────────────────────────────────
//
// int timerfd_gettime(int fd, struct itimerspec *curr_value);

pub fn sys_timerfd_gettime(fdno: usize, curr_va: usize) -> isize {
    if !validate_user_ptr(curr_va, 32) { return -14; }
    let mut tbl = TABLE.lock();
    let entry = match tbl.get_mut(&fdno) {
        Some(e) => e,
        None    => return -9,
    };
    tick(entry);
    let interval_ns  = entry.spec.interval_ns;
    let remaining_ns = if entry.spec.next_ns > 0 {
        entry.spec.next_ns.saturating_sub(now_ns())
    } else { 0 };
    drop(tbl);
    write_itimerspec(curr_va, interval_ns, remaining_ns);
    0
}

// ── timerfd_read (called from io_syscalls) ────────────────────────────────
//
// Returns 8 on success (expirations as u64 LE in buf[0..8]).
// EAGAIN if nonblocking and no expirations yet.
// Blocks (spin) until expirations > 0 or 5 s timeout.

pub fn timerfd_read(fdno: usize, buf: &mut [u8]) -> isize {
    if buf.len() < 8 { return -22; } // EINVAL
    let deadline = now_ns() + 5_000_000_000; // 5 s max spin
    loop {
        {
            let mut tbl = TABLE.lock();
            if let Some(entry) = tbl.get_mut(&fdno) {
                tick(entry);
                if entry.expirations > 0 {
                    let val = entry.expirations;
                    entry.expirations = 0;
                    buf[..8].copy_from_slice(&val.to_le_bytes());
                    return 8;
                }
                if entry.nonblocking { return -11; } // EAGAIN
            } else {
                return -9; // EBADF
            }
        }
        if now_ns() >= deadline { return -110; } // ETIMEDOUT
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

// ── poll readiness ────────────────────────────────────────────────────────

pub fn timerfd_poll(fdno: usize, events: u32) -> u32 {
    let mut tbl = TABLE.lock();
    match tbl.get_mut(&fdno) {
        None => crate::fs::poll::POLLNVAL,
        Some(entry) => {
            tick(entry);
            if events & crate::fs::poll::POLLIN != 0 && entry.expirations > 0 {
                crate::fs::poll::POLLIN
            } else {
                0
            }
        }
    }
}

// ── close ─────────────────────────────────────────────────────────────────

pub fn timerfd_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}
