//! Interval timer implementation for rustos.
//!
//! Provides:
//!  - ITIMER_REAL per-process one-shot + periodic timers (alarm / setitimer)
//!  - POSIX per-process timers (timer_create / timer_settime / timer_delete)
//!
//! # Tick integration
//!
//! The arch-level timer IRQ handler should call `itimer::tick()` on every
//! hardware tick.  `tick()` is intentionally cheap: it holds the lock for
//! O(N_expired) and delivers signals via `crate::proc::signal::send_signal`.
//!
//! # ITIMER_REAL state
//!
//! One `RealTimer` entry per tgid, stored in `REAL_TIMERS`.  The entry holds:
//!  - `deadline_ns`   – absolute monotonic expiry
//!  - `interval_ns`   – reload interval (0 = one-shot)
//!  - `armed`         – whether the timer is active

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex as SpinMutex;
use crate::uaccess::{copy_from_user, copy_to_user};

// ── helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn tgid_now() -> usize {
    let pid = crate::proc::scheduler::current_pid();
    let t   = crate::proc::thread::tgid_of(pid);
    if t != 0 { t } else { pid }
}

// ── ITIMER_REAL ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct RealTimer {
    deadline_ns: u64,
    interval_ns: u64,
    armed:       bool,
}

static REAL_TIMERS: SpinMutex<BTreeMap<usize, RealTimer>> =
    SpinMutex::new(BTreeMap::new());

/// Internal: arms ITIMER_REAL; returns old remaining seconds.
fn alarm_set(seconds: u32) -> u32 {
    let tgid = tgid_now();
    let now  = crate::time::read_monotonic_ns();
    let mut lock = REAL_TIMERS.lock();
    let entry = lock.entry(tgid).or_default();

    let old_remaining = if entry.armed && entry.deadline_ns > now {
        ((entry.deadline_ns - now + 999_999_999) / 1_000_000_000) as u32
    } else {
        0
    };

    if seconds == 0 {
        entry.armed = false;
    } else {
        entry.deadline_ns  = now + (seconds as u64) * 1_000_000_000;
        entry.interval_ns  = 0;
        entry.armed        = true;
    }
    old_remaining
}

/// `alarm(2)` — NR 37.  Returns old remaining seconds as isize.
pub fn sys_alarm(secs: u32) -> isize {
    alarm_set(secs) as isize
}

/// Internal: returns `(remaining_us, interval_us)` for ITIMER_REAL.
fn getitimer_real() -> (u64, u64) {
    let tgid = tgid_now();
    let now  = crate::time::read_monotonic_ns();
    let lock = REAL_TIMERS.lock();
    if let Some(e) = lock.get(&tgid) {
        if e.armed {
            let rem_ns = if e.deadline_ns > now { e.deadline_ns - now } else { 0 };
            return (rem_ns / 1_000, e.interval_ns / 1_000);
        }
    }
    (0, 0)
}

/// Internal: arms ITIMER_REAL; returns `(old_val_us, old_interval_us)`.
fn setitimer_real(new_val_us: Option<u64>, new_interval_us: Option<u64>) -> (u64, u64) {
    let tgid = tgid_now();
    let now  = crate::time::read_monotonic_ns();
    let mut lock = REAL_TIMERS.lock();
    let entry = lock.entry(tgid).or_default();

    let old_rem_us = if entry.armed && entry.deadline_ns > now {
        (entry.deadline_ns - now) / 1_000
    } else {
        0
    };
    let old_int_us = entry.interval_ns / 1_000;

    if let Some(v) = new_val_us {
        if v == 0 {
            entry.armed = false;
        } else {
            entry.deadline_ns = now + v * 1_000;
            entry.armed       = true;
        }
    }
    if let Some(i) = new_interval_us {
        entry.interval_ns = i * 1_000;
    }

    (old_rem_us, old_int_us)
}

// ── itimerval marshalling (shared by getitimer / setitimer) ───────────────────
//
// struct itimerval { struct timeval it_interval; struct timeval it_value; }
// struct timeval   { time_t tv_sec; suseconds_t tv_usec; }
// On x86-64 both fields are 8 bytes → itimerval is 32 bytes.

fn read_itimerval(va: usize) -> Option<(u64 /* val_us */, u64 /* interval_us */)> {
    if va == 0 { return None; }
    let mut buf = [0u8; 32];
    copy_from_user(&mut buf, va).ok()?;
    let int_sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap())  as u64;
    let int_usec = i64::from_le_bytes(buf[8..16].try_into().unwrap()) as u64;
    let val_sec  = i64::from_le_bytes(buf[16..24].try_into().unwrap()) as u64;
    let val_usec = i64::from_le_bytes(buf[24..32].try_into().unwrap()) as u64;
    let val_us = val_sec.saturating_mul(1_000_000).saturating_add(val_usec);
    let int_us = int_sec.saturating_mul(1_000_000).saturating_add(int_usec);
    Some((val_us, int_us))
}

fn write_itimerval(va: usize, val_us: u64, interval_us: u64) -> bool {
    if va == 0 { return true; }
    let int_sec  = (interval_us / 1_000_000) as i64;
    let int_usec = (interval_us % 1_000_000) as i64;
    let val_sec  = (val_us / 1_000_000)      as i64;
    let val_usec = (val_us % 1_000_000)      as i64;
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&int_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&int_usec.to_le_bytes());
    buf[16..24].copy_from_slice(&val_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&val_usec.to_le_bytes());
    copy_to_user(va, &buf).is_ok()
}

/// `getitimer(2)` — NR 36.
pub fn sys_getitimer(which: i32, curr_value_va: usize) -> isize {
    const ITIMER_REAL: i32 = 0;
    if which != ITIMER_REAL { return -22; } // ITIMER_VIRTUAL/PROF not supported
    let (val_us, int_us) = getitimer_real();
    if !write_itimerval(curr_value_va, val_us, int_us) { return -14; }
    0
}

/// `setitimer(2)` — NR 38.
pub fn sys_setitimer(which: i32, new_value_va: usize, old_value_va: usize) -> isize {
    const ITIMER_REAL: i32 = 0;
    if which != ITIMER_REAL { return -22; }

    let (new_val_us, new_int_us) = match read_itimerval(new_value_va) {
        Some(v) => (Some(v.0), Some(v.1)),
        None    => (None, None),
    };

    let (old_val_us, old_int_us) = setitimer_real(new_val_us, new_int_us);

    if old_value_va != 0 && !write_itimerval(old_value_va, old_val_us, old_int_us) {
        return -14;
    }
    0
}

// ── POSIX per-process timers ──────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub struct PosixTimer {
    pub tgid:        usize,
    pub signo:       u32,
    /// Absolute expiry in nanoseconds (monotonic).
    pub deadline_ns: u64,
    /// Re-arm interval in nanoseconds (0 = one-shot).
    pub interval_ns: u64,
    pub armed:       bool,
    /// Overrun count: incremented each time the timer fires while the
    /// previous signal has not yet been consumed.
    pub overrun:     u32,
}

/// `(tgid, timer_id)` → PosixTimer.
pub static POSIX_TIMERS: SpinMutex<BTreeMap<(usize, u32), PosixTimer>> =
    SpinMutex::new(BTreeMap::new());

/// Register or update a POSIX timer slot.  Called from `sys_timer_create` /
/// `sys_timer_settime`.  `value_ns == 0` stores the slot disarmed.
pub fn arm_posix_timer(
    tgid:        usize,
    timer_id:    u32,
    signo:       u32,
    value_ns:    u64,
    interval_ns: u64,
) {
    let now = crate::time::read_monotonic_ns();
    let mut lock = POSIX_TIMERS.lock();
    let e = lock.entry((tgid, timer_id)).or_default();
    e.tgid        = tgid;
    if signo != 0 { e.signo = signo; }
    if value_ns == 0 {
        e.armed = false;
    } else {
        e.deadline_ns = now + value_ns;
        e.armed       = true;
    }
    e.interval_ns = interval_ns;
}

// Per-tgid timer-id allocator.
static TIMER_ID_ALLOC: SpinMutex<BTreeMap<usize, u32>> =
    SpinMutex::new(BTreeMap::new());

fn alloc_timer_id(tgid: usize) -> u32 {
    let mut map = TIMER_ID_ALLOC.lock();
    let id = map.entry(tgid).or_insert(0);
    let r = *id;
    *id = id.wrapping_add(1);
    r
}

// itimerspec marshalling
// struct itimerspec { struct timespec it_interval; struct timespec it_value; }
// struct timespec   { time_t tv_sec; long tv_nsec; } — 16 bytes each → 32 total

fn read_itimerspec(va: usize) -> Option<(u64 /* val_ns */, u64 /* interval_ns */)> {
    if va == 0 { return None; }
    let mut buf = [0u8; 32];
    copy_from_user(&mut buf, va).ok()?;
    let int_sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap())  as u64;
    let int_nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap()) as u64;
    let val_sec  = i64::from_le_bytes(buf[16..24].try_into().unwrap()) as u64;
    let val_nsec = i64::from_le_bytes(buf[24..32].try_into().unwrap()) as u64;
    let val_ns = val_sec.saturating_mul(1_000_000_000).saturating_add(val_nsec);
    let int_ns = int_sec.saturating_mul(1_000_000_000).saturating_add(int_nsec);
    Some((val_ns, int_ns))
}

fn write_itimerspec(va: usize, val_ns: u64, interval_ns: u64) -> bool {
    if va == 0 { return true; }
    let int_sec  = (interval_ns / 1_000_000_000) as i64;
    let int_nsec = (interval_ns % 1_000_000_000) as i64;
    let val_sec  = (val_ns / 1_000_000_000)      as i64;
    let val_nsec = (val_ns % 1_000_000_000)      as i64;
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&int_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&int_nsec.to_le_bytes());
    buf[16..24].copy_from_slice(&val_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&val_nsec.to_le_bytes());
    copy_to_user(va, &buf).is_ok()
}

/// `timer_create(2)` — NR 222.
///
/// sigevent layout (x86-64, only SIGEV_SIGNAL supported):
///   [0..4]   sigev_value.sival_int
///   [4..8]   pad
///   [8..12]  sigev_signo
///   [12..16] sigev_notify  (0 = SIGEV_SIGNAL)
pub fn sys_timer_create(clockid: u32, sigevent_va: usize, timerid_va: usize) -> isize {
    // We support CLOCK_REALTIME (0), CLOCK_MONOTONIC (1), CLOCK_BOOTTIME (7).
    if clockid > 7 { return -22; }
    if timerid_va == 0 { return -14; }

    let signo: u32 = if sigevent_va != 0 {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, sigevent_va).is_err() { return -14; }
        let notify = i32::from_le_bytes(buf[12..16].try_into().unwrap());
        if notify != 0 { return -22; } // only SIGEV_SIGNAL
        u32::from_le_bytes(buf[8..12].try_into().unwrap())
    } else {
        14 // SIGALRM
    };

    let tgid     = tgid_now();
    let timer_id = alloc_timer_id(tgid);

    // Pre-allocate the slot (disarmed).
    arm_posix_timer(tgid, timer_id, signo, 0, 0);

    if copy_to_user(timerid_va, &timer_id.to_le_bytes()).is_err() { return -14; }
    0
}

/// `timer_settime(2)` — NR 223.
pub fn sys_timer_settime(
    timer_id:   u32,
    flags:      i32,
    new_value_va: usize,
    old_value_va: usize,
) -> isize {
    const TIMER_ABSTIME: i32 = 1;
    let tgid = tgid_now();
    let now  = crate::time::read_monotonic_ns();

    // Write out old value first.
    {
        let lock = POSIX_TIMERS.lock();
        if let Some(e) = lock.get(&(tgid, timer_id)) {
            let rem_ns = if e.armed && e.deadline_ns > now {
                e.deadline_ns - now
            } else { 0 };
            drop(lock);
            if !write_itimerspec(old_value_va, rem_ns, 0) { return -14; }
        } else {
            drop(lock);
        }
    }

    let (val_ns, int_ns) = match read_itimerspec(new_value_va) {
        Some(v) => v,
        None    => return -14,
    };

    // TIMER_ABSTIME: val_ns is an absolute time; convert to relative.
    let rel_ns = if flags & TIMER_ABSTIME != 0 {
        if val_ns > now { val_ns - now } else { 0 }
    } else {
        val_ns
    };

    arm_posix_timer(tgid, timer_id, 0, rel_ns, int_ns);
    0
}

/// `timer_gettime(2)` — NR 224.
pub fn sys_timer_gettime(timer_id: u32, curr_value_va: usize) -> isize {
    let tgid = tgid_now();
    let now  = crate::time::read_monotonic_ns();
    let lock = POSIX_TIMERS.lock();
    let (val_ns, int_ns) = if let Some(e) = lock.get(&(tgid, timer_id)) {
        let rem = if e.armed && e.deadline_ns > now { e.deadline_ns - now } else { 0 };
        (rem, e.interval_ns)
    } else {
        (0, 0)
    };
    drop(lock);
    if !write_itimerspec(curr_value_va, val_ns, int_ns) { return -14; }
    0
}

/// `timer_getoverrun(2)` — NR 225.
pub fn sys_timer_getoverrun(timer_id: u32) -> isize {
    let tgid = tgid_now();
    let lock = POSIX_TIMERS.lock();
    lock.get(&(tgid, timer_id)).map(|e| e.overrun as isize).unwrap_or(-22)
}

/// `timer_delete(2)` — NR 226.
pub fn sys_timer_delete(timer_id: u32) -> isize {
    let tgid = tgid_now();
    let existed = POSIX_TIMERS.lock().remove(&(tgid, timer_id)).is_some();
    if existed { 0 } else { -22 }
}

// ── tick() — called from the arch timer IRQ ───────────────────────────────────
//
// Expire any ITIMER_REAL entries and any POSIX timers whose deadline has
// passed.  Delivers SIGALRM (14) for ITIMER_REAL and the registered signo
// for POSIX timers.  Periodic timers are re-armed automatically.

pub fn tick() {
    let now = crate::time::read_monotonic_ns();

    // ── ITIMER_REAL ──
    {
        let mut expired: alloc::vec::Vec<(usize /* tgid */, u64 /* interval_ns */)> =
            alloc::vec::Vec::new();
        {
            let mut lock = REAL_TIMERS.lock();
            for (&tgid, entry) in lock.iter_mut() {
                if !entry.armed || entry.deadline_ns > now { continue; }
                if entry.interval_ns != 0 {
                    // Re-arm: advance deadline by interval, catching up if needed.
                    let mut next = entry.deadline_ns + entry.interval_ns;
                    while next <= now { next += entry.interval_ns; }
                    entry.deadline_ns = next;
                } else {
                    entry.armed = false;
                }
                expired.push((tgid, entry.interval_ns));
            }
        }
        for (tgid, _) in expired {
            crate::proc::signal::send_signal(tgid, 14 /* SIGALRM */);
        }
    }

    // ── POSIX timers ──
    {
        let mut expired: alloc::vec::Vec<(usize /* tgid */, u32 /* signo */)> =
            alloc::vec::Vec::new();
        {
            let mut lock = POSIX_TIMERS.lock();
            for ((_tgid, _id), entry) in lock.iter_mut() {
                if !entry.armed || entry.deadline_ns > now { continue; }
                if entry.interval_ns != 0 {
                    let mut next = entry.deadline_ns + entry.interval_ns;
                    while next <= now {
                        entry.overrun = entry.overrun.saturating_add(1);
                        next += entry.interval_ns;
                    }
                    entry.deadline_ns = next;
                } else {
                    entry.armed = false;
                }
                expired.push((entry.tgid, entry.signo));
            }
        }
        for (tgid, signo) in expired {
            crate::proc::signal::send_signal(tgid, signo as i32);
        }
    }
}

/// Clean up all timers for a tgid on process exit.
pub fn cleanup_tgid(tgid: usize) {
    REAL_TIMERS.lock().remove(&tgid);
    let keys: alloc::vec::Vec<(usize, u32)> = POSIX_TIMERS.lock()
        .keys()
        .filter(|k| k.0 == tgid)
        .copied()
        .collect();
    let mut lock = POSIX_TIMERS.lock();
    for k in keys { lock.remove(&k); }
    TIMER_ID_ALLOC.lock().remove(&tgid);
}
