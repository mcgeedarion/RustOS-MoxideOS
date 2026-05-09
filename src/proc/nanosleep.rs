//! nanosleep + clock_gettime + clock_nanosleep syscall implementations.
//!
//! ## How nanosleep works now
//!
//! 1. Validate the `struct timespec` from userspace.
//! 2. Record the absolute deadline in `p.sleep_deadline_ns`.
//! 3. Register a one-shot timer via `time::timer::add_oneshot`; the callback
//!    calls `scheduler::wake_pid(pid)` and clears `sleep_deadline_ns`.
//! 4. `block_current()` + `schedule()` — the task sleeps until the tick
//!    handler fires `timer::expire_timers()`, which calls the callback.
//! 5. On return: if we were woken early (EINTR), write the actual remaining
//!    time to `rem_va`.
//!
//! On RISC-V the timer interrupt re-arms `mtimecmp` every tick *and* calls
//! `expire_timers()`; on x86_64 the APIC periodic tick calls `expire_timers()`.
//! Both arches now share the same blocking path through this module.

use crate::uaccess::{copy_from_user, copy_to_user};
use crate::proc::scheduler;
use crate::time::{Timespec, read_monotonic_ns};
use crate::time::timer::{add_oneshot, cancel_timer};

/// sys_nanosleep(req_va, rem_va)  [NR 35]
pub fn sys_nanosleep(req_va: usize, rem_va: usize) -> isize {
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, req_va).is_err() { return -14; } // EFAULT

    let sec  = i64::from_le_bytes(<[u8; 8]>::try_from(&buf[0..8]).unwrap_or([0; 8]));
    let nsec = i64::from_le_bytes(<[u8; 8]>::try_from(&buf[8..16]).unwrap_or([0; 8]));
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 { return -22; } // EINVAL

    let delta_ns = sec as u64 * 1_000_000_000 + nsec as u64;
    if delta_ns == 0 { return 0; }

    let ret = sleep_ns_internal(delta_ns);

    if ret == -4 /* EINTR */ && rem_va != 0 {
        let rem = scheduler::with_proc(scheduler::current_pid(), |p| {
            p.sleep_deadline_ns
                .saturating_sub(read_monotonic_ns())
        }).unwrap_or(0);
        let rem_sec  = rem / 1_000_000_000;
        let rem_nsec = rem % 1_000_000_000;
        let mut rbuf = [0u8; 16];
        rbuf[0..8].copy_from_slice(&rem_sec.to_le_bytes());
        rbuf[8..16].copy_from_slice(&rem_nsec.to_le_bytes());
        let _ = copy_to_user(rem_va, &rbuf);
        return -4; // EINTR
    }

    if rem_va != 0 {
        let _ = copy_to_user(rem_va, &[0u8; 16]);
    }
    ret
}

/// sys_clock_nanosleep(clockid, flags, req_va, rem_va)  [NR 230]
pub fn sys_clock_nanosleep(
    _clockid: u32, flags: i32, req_va: usize, rem_va: usize,
) -> isize {
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, req_va).is_err() { return -14; }

    let sec  = i64::from_le_bytes(<[u8; 8]>::try_from(&buf[0..8]).unwrap_or([0; 8]));
    let nsec = i64::from_le_bytes(<[u8; 8]>::try_from(&buf[8..16]).unwrap_or([0; 8]));
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 { return -22; }

    let req_ns = sec as u64 * 1_000_000_000 + nsec as u64;
    let delta_ns = if flags & 1 != 0 {
        let now = read_monotonic_ns();
        if req_ns <= now { return 0; }
        req_ns - now
    } else {
        req_ns
    };

    if delta_ns == 0 { return 0; }
    let ret = sleep_ns_internal(delta_ns);

    if ret == -4 && rem_va != 0 && flags & 1 == 0 {
        let rem = scheduler::with_proc(scheduler::current_pid(), |p| {
            p.sleep_deadline_ns.saturating_sub(read_monotonic_ns())
        }).unwrap_or(0);
        let mut rbuf = [0u8; 16];
        rbuf[0..8].copy_from_slice(&(rem / 1_000_000_000).to_le_bytes());
        rbuf[8..16].copy_from_slice(&(rem % 1_000_000_000).to_le_bytes());
        let _ = copy_to_user(rem_va, &rbuf);
        return -4;
    }
    ret
}

/// sys_clock_gettime(clockid, timespec_va)  [NR 228]
///
/// All clocks currently return `CLOCK_MONOTONIC` time sourced from the arch
/// clocksource (TSC on x86_64, `mtime` on RISC-V) via `read_monotonic_ns()`.
pub fn sys_clock_gettime(_clockid: u32, timespec_va: usize) -> isize {
    let total_ns = read_monotonic_ns();
    let sec  = (total_ns / 1_000_000_000) as i64;
    let nsec = (total_ns % 1_000_000_000) as i64;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&nsec.to_le_bytes());
    if copy_to_user(timespec_va, &buf).is_err() { return -14; }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: common blocking sleep path
// ─────────────────────────────────────────────────────────────────────────────

/// Block the current task for `delta_ns` nanoseconds.
///
/// Public so that `time::timer::clock_nanosleep` can delegate here without
/// duplicating the blocking protocol.
///
/// Returns 0 on normal completion, -4 (EINTR) if woken early by a signal.
/// On return, `p.sleep_deadline_ns` still holds the original deadline so the
/// caller can compute the remaining time.
pub fn sleep_ns_internal(delta_ns: u64) -> isize {
    let pid      = scheduler::current_pid();
    let deadline = read_monotonic_ns() + delta_ns;

    scheduler::with_proc_mut(pid, |p| {
        p.sleep_deadline_ns = deadline;
    });

    let timer_id = add_oneshot(deadline, move |_| {
        scheduler::with_proc_mut(pid, |p| {
            p.sleep_deadline_ns = 0;
            p.sleep_timer_id    = 0;
            if p.state == crate::proc::process::State::Blocked {
                p.state = crate::proc::process::State::Ready;
            }
        });
        scheduler::wake_pid(pid);
    });

    scheduler::with_proc_mut(pid, |p| {
        p.sleep_timer_id = timer_id;
    });

    scheduler::block_current();
    scheduler::schedule();

    let interrupted = scheduler::with_proc(pid, |p| {
        p.sleep_deadline_ns != 0
    }).unwrap_or(false);

    if interrupted {
        let tid = scheduler::with_proc(pid, |p| p.sleep_timer_id).unwrap_or(0);
        if tid != 0 { cancel_timer(tid); }
        scheduler::with_proc_mut(pid, |p| p.sleep_timer_id = 0);
        return -4; // EINTR
    }

    0
}
