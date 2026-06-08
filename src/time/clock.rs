//! POSIX clock IDs and `clock_gettime` / `clock_settime` / `clock_getres`.

use crate::time::{
    read_boottime_ns, read_monotonic_ns, realtime_offset_ns, tai_offset_s, Timespec, MONO_NS,
    NSEC_PER_SEC,
};
use core::sync::atomic::Ordering;

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

/// Kernel implementation of `clock_gettime(2)`.
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
        },

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
        },

        CLOCK_PROCESS_CPUTIME_ID => Ok(get_process_cputime()),
        CLOCK_THREAD_CPUTIME_ID => Ok(get_thread_cputime()),

        _ => Err(-22), // EINVAL
    }
}

/// Kernel implementation of `clock_settime(2)`.
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
        },

        CLOCK_TAI => {
            let real_ns = {
                let mono = read_monotonic_ns() as i64;
                mono + crate::time::realtime_offset_ns()
            };

            let tai_ns = ts.to_ns() as i64;
            let tai_off_ns = tai_ns - real_ns;
            crate::time::set_tai_offset_s(tai_off_ns / NSEC_PER_SEC as i64);
            Ok(())
        },

        _ => Err(-22), // EINVAL
    }
}

/// Returns the resolution of the given clock.
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

/// Read the current process's accumulated CPU time from the process table.
fn get_process_cputime() -> Timespec {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid as usize, |p| p.cpu_time_ns).unwrap_or(0);

    Timespec::from_ns(ns)
}

/// Per-thread CPU time.
///
/// `Task::cpu_time_ns` is incremented by `TICK_NS` on every scheduler tick
/// while this task is the running task on its CPU.
fn get_thread_cputime() -> Timespec {
    let blk = crate::smp::percpu::current_block();

    if blk.is_null() {
        return Timespec::ZERO;
    }

    let task = unsafe { (*blk).current_task };

    if task.is_null() {
        return Timespec::ZERO;
    }

    let ns = unsafe { (*task).cpu_time_ns };

    Timespec::from_ns(ns)
}

/// Convenience re-export used by the scheduler and other crates that import
/// `clock::monotonic_ns` directly instead of `time::read_monotonic_ns`.
pub use crate::time::read_monotonic_ns as monotonic_ns;

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