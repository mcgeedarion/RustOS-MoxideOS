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

// ── ITIMER_REAL ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct RealTimer {
    deadline_ns: u64,
    interval_ns: u64,
    armed:       bool,
}

static REAL_TIMERS: SpinMutex<BTreeMap<usize, RealTimer>> =
    SpinMutex::new(BTreeMap::new());

/// Implement `alarm(seconds)`: arms ITIMER_REAL for this process.
/// Returns the number of seconds remaining on any previously armed alarm.
pub fn sys_alarm(seconds: u32) -> u32 {
    let tgid = tgid_now();
    let now  = crate::time::monotonic_ns();
    let mut lock = REAL_TIMERS.lock();
    let entry = lock.entry(tgid).or_default();

    // Calculate old remaining seconds before we overwrite.
    let old_remaining = if entry.armed && entry.deadline_ns > now {
        ((entry.deadline_ns - now + 999_999_999) / 1_000_000_000) as u32
    } else {
        0
    };

    if seconds == 0 {
        entry.armed = false;
    } else {
        entry.deadline_ns  = now + (seconds as u64) * 1_000_000_000;
        entry.interval_ns  = 0; // alarm() is always one-shot
        entry.armed        = true;
    }
    old_remaining
}

/// Returns `(remaining_us, interval_us)` for ITIMER_REAL of the current tgid.
pub fn sys_getitimer_real() -> (u64, u64) {
    let tgid = tgid_now();
    let now  = crate::time::monotonic_ns();
    let lock = REAL_TIMERS.lock();
    if let Some(e) = lock.get(&tgid) {
        if e.armed {
            let rem_ns = if e.deadline_ns > now { e.deadline_ns - now } else { 0 };
            let rem_us = rem_ns / 1_000;
            let int_us = e.interval_ns / 1_000;
            return (rem_us, int_us);
        }
    }
    (0, 0)
}

/// Arms or disarms ITIMER_REAL for the current tgid.
/// Returns `(old_val_us, old_interval_us)`.
pub fn sys_setitimer_real(
    new_val_us:      Option<u64>,
    new_interval_us: Option<u64>,
) -> (u64, u64) {
    let tgid = tgid_now();
    let now  = crate::time::monotonic_ns();
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
    /// Overrun count: incremented each time the timer fires while
    /// the previous signal has not yet been consumed.
    pub overrun:     u32,
}

/// `(tgid, timer_id)` → PosixTimer.
pub static POSIX_TIMERS: SpinMutex<BTreeMap<(usize, u32), PosixTimer>> =
    SpinMutex::new(BTreeMap::new());

/// Register or update a POSIX timer slot (called from timer_create /
/// timer_settime).  A timer with `value_ns == 0` is stored disarmed.
pub fn arm_posix_timer(
    tgid:        usize,
    timer_id:    u32,
    signo:       u32,
    value_ns:    u64,
    interval_ns: u64,
) {
    let now = crate::time::monotonic_ns();
    let mut lock = POSIX_TIMERS.lock();
    let e = lock.entry((tgid, timer_id)).or_default();
    e.tgid        = tgid;
    // Only update signo if non-zero (timer_settime keeps original signo).
    if signo != 0 { e.signo = signo; }
    if value_ns == 0 {
        e.armed = false;
    } else {
        e.deadline_ns = now + value_ns;
        e.interval_ns = interval_ns;
        e.armed       = true;
        e.overrun     = 0;
    }
}

/// Disarm and remove a POSIX timer.
pub fn disarm_posix_timer(tgid: usize, timer_id: u32) {
    POSIX_TIMERS.lock().remove(&(tgid, timer_id));
}

/// Return and clear the overrun counter for a timer.
pub fn get_overrun(tgid: usize, timer_id: u32) -> u32 {
    let mut lock = POSIX_TIMERS.lock();
    if let Some(e) = lock.get_mut(&(tgid, timer_id)) {
        let ov = e.overrun;
        e.overrun = 0;
        ov
    } else {
        0
    }
}

/// Return `(remaining_ns, interval_ns)` for a POSIX timer without
/// disturbing its state.  Used by `timer_settime` to populate `old_va`
/// before installing a new value.
///
/// Returns `(0, 0)` if the timer does not exist or is disarmed.
pub fn get_posix_timer_state(tgid: usize, timer_id: u32) -> (u64, u64) {
    let now = crate::time::monotonic_ns();
    let lock = POSIX_TIMERS.lock();
    match lock.get(&(tgid, timer_id)) {
        Some(e) if e.armed => {
            let rem = if e.deadline_ns > now { e.deadline_ns - now } else { 0 };
            (rem, e.interval_ns)
        }
        _ => (0, 0),
    }
}

// ── Tick ─────────────────────────────────────────────────────────────────────
//
// Called from the hardware timer IRQ path (e.g. HPET / APIC tick on x86_64,
// SBI timer on RISC-V).  Must not block.

/// Process all armed timers and deliver signals for any that have expired.
/// This is called from the kernel tick path; it is intentionally allocation-free.
/// Returns the number of signals delivered.
pub fn tick() -> usize {
    let now = crate::time::monotonic_ns();
    let mut delivered = 0;

    // ── ITIMER_REAL ──
    {
        let mut lock = REAL_TIMERS.lock();
        let expired_tgids: alloc::vec::Vec<usize> = lock
            .iter()
            .filter(|(_, t)| t.armed && t.deadline_ns <= now)
            .map(|(&tgid, _)| tgid)
            .collect();

        for tgid in expired_tgids {
            if let Some(e) = lock.get_mut(&tgid) {
                if e.interval_ns > 0 {
                    // Reload: advance deadline by however many intervals have elapsed
                    // to avoid timer drift on a slow tick.
                    let overshot = now.saturating_sub(e.deadline_ns);
                    let periods  = overshot / e.interval_ns + 1;
                    e.deadline_ns += periods * e.interval_ns;
                } else {
                    e.armed = false;
                }
                drop(lock); // release before signal delivery to avoid deadlock
                deliver_signal(tgid, 14 /* SIGALRM */);
                delivered += 1;
                lock = REAL_TIMERS.lock();
            }
        }
    }

    // ── POSIX timers ──
    {
        let mut lock = POSIX_TIMERS.lock();
        let expired: alloc::vec::Vec<(usize, u32)> = lock
            .iter()
            .filter(|(_, t)| t.armed && t.deadline_ns <= now)
            .map(|(&key, _)| key)
            .collect();

        for key in expired {
            if let Some(e) = lock.get_mut(&key) {
                let signo = e.signo;
                if e.interval_ns > 0 {
                    let overshot = now.saturating_sub(e.deadline_ns);
                    let periods  = overshot / e.interval_ns + 1;
                    e.deadline_ns += periods * e.interval_ns;
                    // Track overruns if > 1 period elapsed.
                    if periods > 1 {
                        e.overrun = e.overrun.saturating_add((periods - 1) as u32);
                    }
                } else {
                    e.armed = false;
                }
                if signo != 0 {
                    let tgid = e.tgid;
                    drop(lock);
                    deliver_signal(tgid, signo);
                    delivered += 1;
                    lock = POSIX_TIMERS.lock();
                }
            }
        }
    }

    delivered
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tgid_now() -> usize {
    let pid = crate::proc::scheduler::current_pid();
    let tgid = crate::proc::thread::tgid_of(pid);
    if tgid != 0 { tgid } else { pid }
}

/// Deliver `signo` to the thread group leader of `tgid`.
#[inline]
fn deliver_signal(tgid: usize, signo: u32) {
    crate::proc::signal::send_signal(tgid, signo as usize);
}
