//! POSIX clock IDs and `clock_gettime` / `clock_settime` / `clock_getres`.
//!
//! ## Clock IDs (matching Linux UAPI <time.h>)
//!
//! | Constant | Value | Source |
//! |----------|-------|--------|
//! | CLOCK_REALTIME           | 0  | MONO + wall offset; settable |
//! | CLOCK_MONOTONIC          | 1  | Monotone ns since boot |
//! | CLOCK_PROCESS_CPUTIME_ID | 2  | Per-process CPU time |
//! | CLOCK_THREAD_CPUTIME_ID  | 3  | Per-thread CPU time |
//! | CLOCK_MONOTONIC_RAW      | 4  | Raw TSC/CLINT, no NTP adj |
//! | CLOCK_REALTIME_COARSE    | 5  | Low-res REALTIME (tick) |
//! | CLOCK_MONOTONIC_COARSE   | 6  | Low-res MONOTONIC (tick) |
//! | CLOCK_BOOTTIME           | 7  | MONOTONIC + suspend |
//! | CLOCK_REALTIME_ALARM     | 8  | REALTIME + wake-from-suspend |
//! | CLOCK_BOOTTIME_ALARM     | 9  | BOOTTIME + wake-from-suspend |
//! | CLOCK_TAI                | 11 | REALTIME + TAI leap offset |

use crate::time::{
    read_boottime_ns, read_monotonic_ns, realtime_offset_ns, tai_offset_s, Timespec, MONO_NS,
    NSEC_PER_SEC,
};
use core::sync::atomic::Ordering;

// ── Clock ID constants ─────────────────────────────────────────────────────────────────

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
pub const CLOCK_MONOTONIC_RAW: i32 = 4;
pub const CLOCK_REALTIME_COARSE: i32 = 5;
pub const CLOCK_MONOTONIC_COARSE: i32 = 6;
pub const CLOCK_BOOTTIME: i32 = 7;
pub const CLOCK_REALTIME_ALARM: i32 = 8;
pub const CLOCK_BOOTTIME_ALARM: i32 = 9;
pub const CLOCK_TAI: i32 = 11;

// ── clock_gettime ──────────────────────────────────────────────────────────────────────

/// Kernel implementation of `clock_gettime(2)`.
/// `clk_id` is the POSIX clock ID; returns `Timespec` or EINVAL.
pub fn clock_gettime(clk_id: i32) -> Result<Timespec, isize> {
    match clk_id {
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW => Ok(Timespec::from_ns(read_monotonic_ns())),
        CLOCK_MONOTONIC_COARSE => Ok(Timespec::from_ns(MONO_NS.load(Ordering::Relaxed))),
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_REALTIME_ALARM => {
            let mono_ns = read_monotonic_ns() as i64;
            let offset = realtime_offset_ns();
            let real_ns = mono_ns.saturating_add(offset);
            if real_ns < 0 {
                return Ok(Timespec::ZERO);
            }
            Ok(Timespec::from_ns(real_ns as u64))
        }
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => Ok(Timespec::from_ns(read_boottime_ns())),
        CLOCK_TAI => {
            let mono_ns = read_monotonic_ns() as i64;
            let offset = realtime_offset_ns();
            let tai_off = tai_offset_s() * NSEC_PER_SEC as i64;
            let ns = mono_ns.saturating_add(offset).saturating_add(tai_off);
            if ns < 0 {
                return Ok(Timespec::ZERO);
            }
            Ok(Timespec::from_ns(ns as u64))
        }
        CLOCK_PROCESS_CPUTIME_ID => Ok(get_process_cputime()),
        CLOCK_THREAD_CPUTIME_ID => Ok(get_thread_cputime()),
        _ => Err(-22), // EINVAL
    }
}

// ── clock_settime ─────────────────────────────────────────────────────────────────────

/// Kernel implementation of `clock_settime(2)`.
///
/// Settable clocks:
///   CLOCK_REALTIME  — adjusts the monotonic→wall offset.
///   CLOCK_TAI       — adjusts the TAI-UTC leap-second offset.
///
/// All other clock IDs return EINVAL (-22) per POSIX.
/// (The previous code returned -1 for the non-settable arm, which is not
/// a valid errno and confused callers.)
pub fn clock_settime(clk_id: i32, ts: Timespec) -> Result<(), isize> {
    if !ts.is_valid() {
        return Err(-22);
    }
    match clk_id {
        CLOCK_REALTIME => {
            let mono_ns = read_monotonic_ns() as i64;
            let new_real_ns = ts.to_ns() as i64;
            let offset = new_real_ns - mono_ns;
            crate::time::set_realtime_offset_ns(offset);
            Ok(())
        }
        CLOCK_TAI => {
            let real_ns = {
                let mono = read_monotonic_ns() as i64;
                mono + crate::time::realtime_offset_ns()
            };
            let tai_ns = ts.to_ns() as i64;
            let tai_off_ns = tai_ns - real_ns;
            crate::time::set_tai_offset_s(tai_off_ns / NSEC_PER_SEC as i64);
            Ok(())
        }
        // CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME,
        // CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, etc.
        // are not settable.  POSIX says EINVAL for an unsupported clock.
        _ => Err(-22), // EINVAL
    }
}

// ── clock_getres ─────────────────────────────────────────────────────────────────────

/// Returns the resolution of the given clock.
/// TSC/CLINT clocks have 1 ns resolution; tick-based have HZ resolution.
pub fn clock_getres(clk_id: i32) -> Result<Timespec, isize> {
    match clk_id {
        CLOCK_REALTIME
        | CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_RAW
        | CLOCK_BOOTTIME
        | CLOCK_TAI
        | CLOCK_REALTIME_ALARM
        | CLOCK_BOOTTIME_ALARM
        | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID => Ok(Timespec {
            tv_sec: 0,
            tv_nsec: 1,
        }),
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => Ok(Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        }),
        _ => Err(-22),
    }
}

// ── CPU-time clocks ─────────────────────────────────────────────────────────────────────

/// Read the current process's accumulated CPU time from the process table.
///
/// `cpu_time_ns` is incremented by `TICK_NS` on every scheduler tick while
/// the process is the running task on any CPU.  This gives 1 ms resolution
/// matching the tick period.
fn get_process_cputime() -> Timespec {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid as usize, |p| p.cpu_time_ns).unwrap_or(0);
    Timespec::from_ns(ns)
}

/// Per-thread CPU time.
///
/// True per-thread accounting requires a `cpu_time_ns` field on `Task`.
/// Until that is added, we return the process-level cpu_time_ns which is
/// correct for single-threaded processes and a conservative upper bound for
/// multi-threaded ones.
///
/// FIXME: add Task::cpu_time_ns, charge in tick() per-task, read here.
fn get_thread_cputime() -> Timespec {
    get_process_cputime()
}

// ── monotonic_ns re-export ─────────────────────────────────────────────────────────

/// Convenience re-export used by the scheduler and other crates that import
/// `clock::monotonic_ns` directly instead of `time::read_monotonic_ns`.
pub use crate::time::read_monotonic_ns as monotonic_ns;

// ── gettimeofday / time(2) convenience wrappers ──────────────────────────────

use crate::time::Timeval;

/// `gettimeofday(2)` — returns the current CLOCK_REALTIME as a `Timeval`.
pub fn gettimeofday() -> Timeval {
    let ts = clock_gettime(CLOCK_REALTIME).unwrap_or(Timespec::ZERO);
    Timeval::from_timespec(ts)
}

/// `time(2)` — returns seconds since the Unix epoch.
pub fn time_secs() -> i64 {
    clock_gettime(CLOCK_REALTIME)
        .map(|ts| ts.tv_sec)
        .unwrap_or(0)
}
