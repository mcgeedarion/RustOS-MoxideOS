//! Interval timer (itimer) and alarm(2) implementation.
//!
//! Implements:
//!   alarm(2)      NR  37  – one-shot SIGALRM after N seconds
//!   setitimer(2)  NR 155  – ITIMER_REAL / _VIRTUAL / _PROF
//!   getitimer(2)  NR 102  – read current itimer value
//!
//! ## Data structures
//!
//! AlarmState per process:
//!   deadline_ns  – monotonic ns at which SIGALRM fires (0 = disarmed)
//!   interval_ns  – reload interval in ns (0 = one-shot)
//!
//! Both fields are stored in ITIMER_TABLE keyed by PID.
//!
//! ## Tick integration
//!
//! check_itimers(pid) is called from the scheduler tick path once per
//! scheduling quantum for the currently-running process.  When
//! deadline_ns <= read_monotonic_ns(), SIGALRM is sent and:
//!   - if interval_ns > 0: deadline_ns += interval_ns (periodic)
//!   - if interval_ns == 0: deadline_ns = 0 (disarmed)
//!
//! ## ITIMER_VIRTUAL / ITIMER_PROF
//!
//! Accepted by setitimer/getitimer; stored but never triggered.  Full
//! per-process CPU-time accounting is a prerequisite; this can be completed
//! once cpu_time_ns tracking is wired into the scheduler tick.

extern crate alloc;
use crate::uaccess::{copy_from_user, copy_to_user};
use alloc::collections::BTreeMap;
use spin::Mutex as SpinMutex;

// ── per-process alarm state ────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct AlarmState {
    /// Monotonic ns deadline; 0 means disarmed.
    deadline_ns: u64,
    /// Reload interval in ns; 0 means one-shot.
    interval_ns: u64,
    // Per-timer-which copies for VIRTUAL and PROF (stored, not triggered).
    virtual_deadline_ns: u64,
    virtual_interval_ns: u64,
    prof_deadline_ns: u64,
    prof_interval_ns: u64,
}

static ITIMER_TABLE: SpinMutex<BTreeMap<usize /* pid */, AlarmState>> =
    SpinMutex::new(BTreeMap::new());

// ── helpers ─────────────────────────────────────────────────────────────────

/// Read a `struct itimerval` from userspace.
/// Layout: { timeval value_ns[2] } = { { i64 sec; i64 usec; } x2 }
/// [0] = it_interval, [1] = it_value
fn read_itimerval(va: usize) -> Option<(u64 /* interval_ns */, u64 /* value_ns */)> {
    if va == 0 {
        return None;
    }
    let mut buf = [0u8; 32]; // two timevals, 16 bytes each
    copy_from_user(&mut buf, va).ok()?;
    let itv_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let itv_usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let val_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let val_usec = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    if itv_sec < 0 || itv_usec < 0 || val_sec < 0 || val_usec < 0 {
        return None;
    }
    let interval_ns = itv_sec as u64 * 1_000_000_000 + itv_usec as u64 * 1_000;
    let value_ns = val_sec as u64 * 1_000_000_000 + val_usec as u64 * 1_000;
    Some((interval_ns, value_ns))
}

/// Write a `struct itimerval` to userspace.
/// [0] = it_interval (reload), [1] = it_value (remaining)
fn write_itimerval(va: usize, interval_ns: u64, remaining_ns: u64) -> isize {
    if va == 0 {
        return 0;
    }
    let mut buf = [0u8; 32];
    let write_timeval = |buf: &mut [u8], off: usize, ns: u64| {
        let sec = (ns / 1_000_000_000) as i64;
        let usec = ((ns % 1_000_000_000) / 1_000) as i64;
        buf[off..off + 8].copy_from_slice(&sec.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&usec.to_le_bytes());
    };
    write_timeval(&mut buf, 0, interval_ns);
    write_timeval(&mut buf, 16, remaining_ns);
    if copy_to_user(va, &buf).is_err() {
        -14
    } else {
        0
    }
}

/// Remaining ns on an ITIMER_REAL alarm for `pid`; 0 if disarmed.
fn remaining_real_ns(pid: usize) -> u64 {
    let mono = crate::time::read_monotonic_ns();
    let table = ITIMER_TABLE.lock();
    let state = match table.get(&pid) {
        Some(s) => s,
        None => return 0,
    };
    if state.deadline_ns == 0 {
        return 0;
    }
    state.deadline_ns.saturating_sub(mono)
}

// ── alarm(2) ─────────────────────────────────────────────────────────────────
//
// alarm(seconds) schedules SIGALRM to be delivered to the calling process
// after `seconds` seconds.  Any previously scheduled alarm is cancelled.
// Returns the number of seconds remaining on any previous alarm (rounded up).
// alarm(0) cancels any pending alarm.

pub fn sys_alarm(seconds: u32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let mono = crate::time::read_monotonic_ns();
    let mut table = ITIMER_TABLE.lock();
    let state = table.entry(pid).or_default();

    // Compute and return remaining seconds of the previous alarm.
    let prev_remaining_secs: u32 = if state.deadline_ns == 0 {
        0
    } else {
        let rem_ns = state.deadline_ns.saturating_sub(mono);
        // Round up to the nearest second.
        ((rem_ns + 999_999_999) / 1_000_000_000) as u32
    };

    if seconds == 0 {
        // Cancel any pending alarm.
        state.deadline_ns = 0;
        state.interval_ns = 0;
    } else {
        state.deadline_ns = mono + seconds as u64 * 1_000_000_000;
        state.interval_ns = 0; // alarm(2) is always one-shot
    }

    prev_remaining_secs as isize
}

// ── setitimer(2) ─────────────────────────────────────────────────────────────
//
// setitimer(which, new_va, old_va)
//   which: 0=ITIMER_REAL 1=ITIMER_VIRTUAL 2=ITIMER_PROF
//   new_va: pointer to struct itimerval with new value (may be NULL)
//   old_va: pointer to receive old value (may be NULL)
//
// Returns 0 on success, -EINVAL if `which` is out of range.

pub fn sys_setitimer(which: i32, new_va: usize, old_va: usize) -> isize {
    const ITIMER_REAL: i32 = 0;
    const ITIMER_VIRTUAL: i32 = 1;
    const ITIMER_PROF: i32 = 2;

    if which < ITIMER_REAL || which > ITIMER_PROF {
        return -22;
    } // EINVAL

    let pid = crate::proc::scheduler::current_pid();
    let mono = crate::time::read_monotonic_ns();
    let mut table = ITIMER_TABLE.lock();
    let state = table.entry(pid).or_default();

    match which {
        x if x == ITIMER_REAL => {
            // Write old value before updating.
            let old_rem = if state.deadline_ns == 0 {
                0u64
            } else {
                state.deadline_ns.saturating_sub(mono)
            };
            if old_va != 0 {
                drop(table); // release lock before user copy
                let rc = write_itimerval(old_va, 0 /* old interval */, old_rem);
                if rc != 0 { return rc; }
                table = ITIMER_TABLE.lock();
                // Re-borrow state after re-locking.
                let state = table.entry(pid).or_default();
                if new_va == 0 { return 0; }
                let (iv_ns, val_ns) = match read_itimerval(new_va) {
                    Some(v) => v,
                    None    => return -22,
                };
                state.interval_ns = iv_ns;
                state.deadline_ns = if val_ns == 0 { 0 } else { mono + val_ns };
            } else {
                if new_va == 0 { return 0; }
                let (iv_ns, val_ns) = match read_itimerval(new_va) {
                    Some(v) => v,
                    None    => return -22,
                };
                state.interval_ns = iv_ns;
                state.deadline_ns = if val_ns == 0 { 0 } else { mono + val_ns };
            }
        }
        x if x == ITIMER_VIRTUAL => {
            let old_rem = state.virtual_deadline_ns.saturating_sub(mono);
            if old_va != 0 {
                let _ = write_itimerval(old_va, state.virtual_interval_ns, old_rem);
            }
            if new_va != 0 {
                if let Some((iv, val)) = read_itimerval(new_va) {
                    state.virtual_interval_ns  = iv;
                    state.virtual_deadline_ns  = if val == 0 { 0 } else { mono + val };
                }
            }
        }
        _ /* ITIMER_PROF */ => {
            let old_rem = state.prof_deadline_ns.saturating_sub(mono);
            if old_va != 0 {
                let _ = write_itimerval(old_va, state.prof_interval_ns, old_rem);
            }
            if new_va != 0 {
                if let Some((iv, val)) = read_itimerval(new_va) {
                    state.prof_interval_ns  = iv;
                    state.prof_deadline_ns  = if val == 0 { 0 } else { mono + val };
                }
            }
        }
    }
    0
}

// ── getitimer(2) ─────────────────────────────────────────────────────────────
//
// getitimer(which, cur_va)
// Writes the remaining time and reload interval into the userspace itimerval.

pub fn sys_getitimer(which: i32, cur_va: usize) -> isize {
    const ITIMER_REAL: i32 = 0;
    const ITIMER_VIRTUAL: i32 = 1;
    const ITIMER_PROF: i32 = 2;

    if which < ITIMER_REAL || which > ITIMER_PROF {
        return -22;
    }
    if cur_va == 0 {
        return -14;
    } // EFAULT

    let pid = crate::proc::scheduler::current_pid();
    let mono = crate::time::read_monotonic_ns();
    let table = ITIMER_TABLE.lock();
    let state = table.get(&pid).cloned().unwrap_or_default();
    drop(table);

    let (interval_ns, remaining_ns) = match which {
        x if x == ITIMER_REAL => {
            let rem = if state.deadline_ns == 0 {
                0
            } else {
                state.deadline_ns.saturating_sub(mono)
            };
            (state.interval_ns, rem)
        }
        x if x == ITIMER_VIRTUAL => {
            let rem = if state.virtual_deadline_ns == 0 {
                0
            } else {
                state.virtual_deadline_ns.saturating_sub(mono)
            };
            (state.virtual_interval_ns, rem)
        }
        _ => {
            let rem = if state.prof_deadline_ns == 0 {
                0
            } else {
                state.prof_deadline_ns.saturating_sub(mono)
            };
            (state.prof_interval_ns, rem)
        }
    };

    write_itimerval(cur_va, interval_ns, remaining_ns)
}

// ── check_itimers (scheduler tick integration) ────────────────────────────────
//
// Called from the scheduler tick path for the currently-running process.
// Fires SIGALRM when the ITIMER_REAL deadline has elapsed.
//
// This function must be fast (it runs in interrupt context) and must not
// block.  It does a non-blocking try_lock; if the table is already held
// by another CPU it skips the check rather than deadlocking.

pub fn check_itimers(pid: usize) {
    let mono = crate::time::read_monotonic_ns();

    // Non-blocking: skip if the table is contended.
    let mut table = match ITIMER_TABLE.try_lock() {
        Some(g) => g,
        None => return,
    };

    let state = match table.get_mut(&pid) {
        Some(s) => s,
        None => return,
    };

    if state.deadline_ns == 0 || mono < state.deadline_ns {
        return;
    }

    // Deadline elapsed – fire SIGALRM.
    if state.interval_ns > 0 {
        // Periodic: advance deadline by interval (skip missed ticks).
        let elapsed = mono - state.deadline_ns;
        let skipped = elapsed / state.interval_ns;
        state.deadline_ns += (skipped + 1) * state.interval_ns;
    } else {
        // One-shot: disarm.
        state.deadline_ns = 0;
    }
    drop(table);

    // Deliver SIGALRM (signal 14) to the process.
    crate::proc::signal::send_signal(pid, 14 /* SIGALRM */);
}

/// Remove all itimer state for `pid` on process exit.
pub fn cleanup_itimers(pid: usize) {
    let mut table = ITIMER_TABLE.lock();
    table.remove(&pid);
}
