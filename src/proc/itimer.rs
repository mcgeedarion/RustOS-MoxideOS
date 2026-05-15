//! Interval timer (ITIMER_REAL) and POSIX per-process timer SIGEV_SIGNAL delivery.
//!
//! ## Design
//!
//! A single global `TICK` hook is called from the arch timer interrupt
//! (or wherever `crate::time::tick_irq()` fires).  Each call advances all
//! armed ITIMER_REAL entries and all POSIX timers by the elapsed ns since
//! the last tick; when a timer expires it enqueues the configured signal
//! into the process signal queue via `crate::proc::signal::send_signal_group`.
//!
//! `alarm(seconds)` is implemented as a one-shot ITIMER_REAL with
//! `it_interval = 0`.
//!
//! POSIX `timer_create` / `timer_settime` are handled in
//! `src/syscall/posix_timer.rs`; that module calls `arm_posix_timer` /
//! `disarm_posix_timer` here so delivery goes through the same tick path.

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;
use crate::time::monotonic_ns;

// ── ITimer state ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct ITimerReal {
    /// Absolute deadline (monotonic ns). 0 = disarmed.
    deadline_ns: u64,
    /// Reload interval in ns. 0 = one-shot.
    interval_ns: u64,
    /// Previous value at the time of the last setitimer call (ns).
    prev_value_ns: u64,
    /// Previous interval at the time of the last setitimer call (ns).
    prev_interval_ns: u64,
}

/// Per-process ITIMER_REAL state, keyed by TGID.
static ITIMERS: Mutex<BTreeMap<usize, ITimerReal>> = Mutex::new(BTreeMap::new());

// ── POSIX timer state ─────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct PosixTimer {
    pub tgid:        usize,
    pub sig:         u32,
    pub deadline_ns: u64,   // 0 = disarmed
    pub interval_ns: u64,
    pub overrun:     u32,
}

/// Per-kernel POSIX timers, keyed by (tgid, timerid).
static POSIX_TIMERS: Mutex<BTreeMap<(usize, u32), PosixTimer>> =
    Mutex::new(BTreeMap::new());

// ── Public API ────────────────────────────────────────────────────────

/// `alarm(seconds)` — arm a one-shot ITIMER_REAL; return remaining seconds
/// of any previous alarm.
pub fn sys_alarm(seconds: u32) -> u32 {
    let now = monotonic_ns();
    let tgid = crate::proc::scheduler::current_tgid();
    let mut map = ITIMERS.lock();
    let entry = map.entry(tgid).or_insert_with(ITimerReal::default);

    let remaining = if entry.deadline_ns > now {
        let ns_left = entry.deadline_ns - now;
        // Round up to whole seconds
        ((ns_left + 999_999_999) / 1_000_000_000) as u32
    } else {
        0
    };

    if seconds == 0 {
        entry.deadline_ns  = 0;
        entry.interval_ns  = 0;
    } else {
        entry.deadline_ns  = now + seconds as u64 * 1_000_000_000;
        entry.interval_ns  = 0;  // one-shot
    }
    remaining
}

/// `setitimer(ITIMER_REAL, new, old)` — inner implementation.
/// `new_val` and `new_interval` are in microseconds (from the itimerval).
/// Returns (old_value_us, old_interval_us).
pub fn sys_setitimer_real(
    new_val_us:      Option<u64>,
    new_interval_us: Option<u64>,
) -> (u64, u64) {
    let now  = monotonic_ns();
    let tgid = crate::proc::scheduler::current_tgid();
    let mut map = ITIMERS.lock();
    let entry = map.entry(tgid).or_insert_with(ITimerReal::default);

    // Snapshot old values before mutation
    let old_val_us = if entry.deadline_ns > now {
        (entry.deadline_ns - now) / 1_000
    } else {
        0
    };
    let old_interval_us = entry.interval_ns / 1_000;

    if let (Some(val), Some(interval)) = (new_val_us, new_interval_us) {
        entry.prev_value_ns    = entry.deadline_ns.saturating_sub(now);
        entry.prev_interval_ns = entry.interval_ns;
        if val == 0 {
            entry.deadline_ns = 0;
            entry.interval_ns = 0;
        } else {
            entry.deadline_ns = now + val * 1_000;
            entry.interval_ns = interval * 1_000;
        }
    }

    (old_val_us, old_interval_us)
}

/// `getitimer(ITIMER_REAL)` — returns (current_value_us, interval_us).
pub fn sys_getitimer_real() -> (u64, u64) {
    let now  = monotonic_ns();
    let tgid = crate::proc::scheduler::current_tgid();
    let map  = ITIMERS.lock();
    match map.get(&tgid) {
        None => (0, 0),
        Some(e) => {
            let val_us = if e.deadline_ns > now {
                (e.deadline_ns - now) / 1_000
            } else { 0 };
            (val_us, e.interval_ns / 1_000)
        }
    }
}

// ── POSIX timer arming ────────────────────────────────────────────────

/// Called by `sys_timer_settime` to arm a POSIX per-process timer.
pub fn arm_posix_timer(
    tgid:        usize,
    timerid:     u32,
    sig:         u32,
    val_ns:      u64,
    interval_ns: u64,
) {
    let now = monotonic_ns();
    let mut map = POSIX_TIMERS.lock();
    let entry = map.entry((tgid, timerid)).or_insert(PosixTimer {
        tgid, sig, deadline_ns: 0, interval_ns: 0, overrun: 0,
    });
    entry.sig         = sig;
    entry.interval_ns = interval_ns;
    entry.overrun     = 0;
    entry.deadline_ns = if val_ns == 0 { 0 } else { now + val_ns };
}

/// Called by `sys_timer_delete` or `sys_timer_settime` with val=0 to disarm.
pub fn disarm_posix_timer(tgid: usize, timerid: u32) {
    let mut map = POSIX_TIMERS.lock();
    if let Some(e) = map.get_mut(&(tgid, timerid)) {
        e.deadline_ns = 0;
    }
}

/// Remove all POSIX timers for a process (called on exit).
pub fn cleanup_posix_timers(tgid: usize) {
    let mut map = POSIX_TIMERS.lock();
    map.retain(|&(t, _), _| t != tgid);
    let mut itimers = ITIMERS.lock();
    itimers.remove(&tgid);
}

/// Get current overrun count for a POSIX timer (for `timer_getoverrun`).
pub fn get_overrun(tgid: usize, timerid: u32) -> u32 {
    POSIX_TIMERS.lock()
        .get(&(tgid, timerid))
        .map_or(0, |e| e.overrun)
}

// ── Tick handler ──────────────────────────────────────────────────────

/// Called from the hardware timer interrupt path on every tick.
/// Fires SIGALRM / configured signal for any expired timers.
///
/// Must NOT block or allocate heavily — runs in interrupt context.
pub fn tick() {
    let now = monotonic_ns();

    // ── ITIMER_REAL ──────────────────────────────────────────────────
    {
        let mut fired: alloc::vec::Vec<(usize, u64)> = alloc::vec::Vec::new();
        {
            let mut map = ITIMERS.lock();
            for (&tgid, entry) in map.iter_mut() {
                if entry.deadline_ns == 0 { continue; }
                if now >= entry.deadline_ns {
                    fired.push((tgid, entry.interval_ns));
                    if entry.interval_ns > 0 {
                        // Reload: advance deadline by interval to avoid drift
                        let overruns = (now - entry.deadline_ns) / entry.interval_ns;
                        entry.deadline_ns += (overruns + 1) * entry.interval_ns;
                    } else {
                        entry.deadline_ns = 0; // one-shot
                    }
                }
            }
        }
        for (tgid, _interval) in fired {
            crate::proc::signal::send_signal_group(tgid, 14 /* SIGALRM */);
        }
    }

    // ── POSIX timers (SIGEV_SIGNAL) ───────────────────────────────────
    {
        let mut fired: alloc::vec::Vec<(usize, u32)> = alloc::vec::Vec::new();
        {
            let mut map = POSIX_TIMERS.lock();
            for ((_tgid, _id), entry) in map.iter_mut() {
                if entry.deadline_ns == 0 { continue; }
                if now >= entry.deadline_ns {
                    fired.push((entry.tgid, entry.sig));
                    if entry.interval_ns > 0 {
                        let overruns = (now - entry.deadline_ns) / entry.interval_ns;
                        entry.overrun = entry.overrun.saturating_add(overruns as u32);
                        entry.deadline_ns += (overruns + 1) * entry.interval_ns;
                    } else {
                        entry.deadline_ns = 0;
                    }
                }
            }
        }
        for (tgid, sig) in fired {
            crate::proc::signal::send_signal_group(tgid, sig as i32);
        }
    }
}
