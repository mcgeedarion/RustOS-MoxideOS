//! nanosleep + clock_gettime + clock_nanosleep + clock_getres syscall impls.
//!
//! ## Architecture
//!
//! ```text
//! sys_nanosleep(req, rem)
//!   └─ sleep_ns_internal(delta_ns)
//!         └─ sleep_until_ns(now + delta)   ← real blocking primitive
//!
//! sys_clock_nanosleep(clk, flags, req, rem)
//!   ├─ TIMER_ABSTIME → convert req to monotonic deadline
//!   └─ sleep_until_ns(deadline)
//! ```
//!
//! ## Blocking model
//!
//! `sleep_until_ns` allocates a one-shot `WaitQueue`, stores the deadline
//! in `Pcb::sleep_deadline_ns` (for the rem calculation on EINTR), then
//! calls `wq.wait(0, cancel_token, Some(deadline_ns))`:
//!
//!   - `WakeReason::Timeout`   → 0   (deadline elapsed normally)
//!   - `WakeReason::Cancelled` → -4  (EINTR — signal arrived)
//!   - `WakeReason::Ready`     → 0   (early wakeup, treated as success)
//!
//! Signal interruptibility is immediate: `CancellationToken::cancel()`
//! fires `wq.wake()` which unblocks the task in O(1) regardless of the
//! remaining deadline.
//!
//! No timer wheel entries are created for the blocking itself.  The
//! deadline is enforced by WaitQueue’s internal hrtimer.
//!
//! ## Clock support
//!
//! sys_clock_gettime dispatches to `time::clock::clock_gettime` which
//! handles all eleven POSIX clock IDs.  CLOCK_PROCESS_CPUTIME_ID reads
//! `Pcb::cpu_time_ns` from the scheduler for real per-process CPU time.
//!
//! ## EINTR / remainder
//!
//! On signal interruption:
//!   - Returns -4 (EINTR).
//!   - If `rem_va != 0` and the sleep was *relative*, writes the remaining time
//!     to userspace (Linux-compatible: absolute sleeps never write rem).

use crate::proc::scheduler;
use crate::sync::wait_queue::{WaitQueue, WakeReason};
use crate::time::clock::{self, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID};
use crate::time::{read_monotonic_ns, Timespec};
use crate::uaccess::{copy_from_user, copy_to_user};
use alloc::sync::Arc;

extern crate alloc;

pub fn now_ns() -> u64 {
    read_monotonic_ns()
}

/// sys_nanosleep(req_va, rem_va)  [NR 35]
///
/// Sleeps for the relative duration given in `*req_va`.
/// On EINTR, writes remaining time to `*rem_va` (if non-null).
pub fn sys_nanosleep(req_va: usize, rem_va: usize) -> isize {
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, req_va).is_err() {
        return -14;
    }

    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    let nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap_or([0; 8]));
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return -22;
    }

    let delta_ns = sec as u64 * 1_000_000_000 + nsec as u64;
    if delta_ns == 0 {
        return 0;
    }

    let deadline = read_monotonic_ns().saturating_add(delta_ns);
    let ret = sleep_until_ns(deadline);

    if ret == -4 && rem_va != 0 {
        write_remaining(rem_va, deadline);
        return -4;
    }
    if rem_va != 0 {
        let _ = copy_to_user(rem_va, &[0u8; 16]);
    }
    ret
}

/// sys_clock_nanosleep(clockid, flags, req_va, rem_va)  [NR 230]
///
/// flags == 0          → relative sleep (same as nanosleep but clock-aware).
/// flags & TIMER_ABSTIME → absolute sleep on the given clock.
pub fn sys_clock_nanosleep(clockid: u32, flags: i32, req_va: usize, rem_va: usize) -> isize {
    use crate::time::timer::TIMER_ABSTIME;

    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, req_va).is_err() {
        return -14;
    }

    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    let nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap_or([0; 8]));
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return -22;
    }
    let req_ns = sec as u64 * 1_000_000_000 + nsec as u64;

    let absolute = flags & TIMER_ABSTIME != 0;

    if absolute {
        let clk_now_ns = match clock::clock_gettime(clockid as i32) {
            Ok(ts) => ts.to_ns(),
            Err(e) => return e as isize,
        };
        if req_ns <= clk_now_ns {
            return 0;
        }
        let delta = req_ns - clk_now_ns;
        let mono_dl = read_monotonic_ns() + delta;
        // POSIX: absolute clock_nanosleep does NOT write rem on EINTR.
        sleep_until_ns(mono_dl)
    } else {
        if req_ns == 0 {
            return 0;
        }
        let deadline = read_monotonic_ns().saturating_add(req_ns);
        let ret = sleep_until_ns(deadline);
        if ret == -4 && rem_va != 0 {
            write_remaining(rem_va, deadline);
            return -4;
        }
        if rem_va != 0 {
            let _ = copy_to_user(rem_va, &[0u8; 16]);
        }
        ret
    }
}

/// sys_clock_gettime(clockid, timespec_va)  [NR 228]
pub fn sys_clock_gettime(clockid: u32, timespec_va: usize) -> isize {
    let pid = scheduler::current_pid();

    let ts = match clockid as i32 {
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            let cpu_ns = scheduler::with_proc(pid, |p| p.cpu_time_ns).unwrap_or(0);
            Timespec::from_ns(cpu_ns)
        },
        cid => match clock::clock_gettime(cid) {
            Ok(ts) => ts,
            Err(e) => return e as isize,
        },
    };

    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&ts.tv_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&(ts.tv_nsec as i64).to_le_bytes());
    if !copy_to_user(timespec_va, &buf) {
        return -14;
    }
    0
}

/// sys_clock_getres(clockid, timespec_va)  [NR 229]
pub fn sys_clock_getres(clockid: u32, timespec_va: usize) -> isize {
    let res = match clock::clock_getres(clockid as i32) {
        Ok(ts) => ts,
        Err(e) => return e as isize,
    };
    if timespec_va == 0 {
        return 0;
    }
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&res.tv_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&(res.tv_nsec as i64).to_le_bytes());
    if !copy_to_user(timespec_va, &buf) {
        return -14;
    }
    0
}

/// Block the current task for `delta_ns` nanoseconds.
#[inline]
pub fn sleep_ns_internal(delta_ns: u64) -> isize {
    let deadline = read_monotonic_ns().saturating_add(delta_ns);
    sleep_until_ns(deadline)
}

/// Block the current task until the absolute monotonic deadline `deadline_ns`.
///
/// Uses `WaitQueue::wait` so the task is unblocked immediately on signal
/// delivery (`CancellationToken::cancel()` → `wq.wake()`).
///
/// Return values:
///   0   — deadline elapsed or early wakeup (success)
///  -4   — EINTR (signal delivered while sleeping)
pub fn sleep_until_ns(deadline_ns: u64) -> isize {
    if read_monotonic_ns() >= deadline_ns {
        return 0;
    }

    let pid = scheduler::current_pid();
    let cancel = scheduler::task_cancel_token(pid);

    // Record deadline for write_remaining() on the EINTR path.
    scheduler::with_proc_mut(pid, |p, _pl| {
        p.sleep_deadline_ns = deadline_ns;
    });

    // One-shot WaitQueue: nothing will ever call wq.wake() to signal
    // normal completion — we rely entirely on the timeout path.
    // Signal wakeup arrives via CancellationToken → wq.wake_cancelled().
    let wq = Arc::new(WaitQueue::new());
    let reason = wq.wait(0, cancel.as_deref(), Some(deadline_ns));

    // Clear the deadline so callers / rem logic can distinguish normal exit.
    scheduler::with_proc_mut(pid, |p, _pl| {
        p.sleep_deadline_ns = 0;
        p.sleep_timer_id = 0;
    });

    match reason {
        WakeReason::Timeout | WakeReason::Ready(_) => 0,
        WakeReason::Cancelled => -4, // EINTR
    }
}

/// Write the remaining sleep time to `rem_va` for EINTR paths.
/// `deadline_ns` is the absolute monotonic deadline that was passed to
/// `sleep_until_ns`; we subtract `now` to get the remaining duration.
fn write_remaining(rem_va: usize, deadline_ns: u64) {
    let rem = deadline_ns.saturating_sub(read_monotonic_ns());
    let mut rbuf = [0u8; 16];
    rbuf[0..8].copy_from_slice(&(rem / 1_000_000_000).to_le_bytes());
    rbuf[8..16].copy_from_slice(&(rem % 1_000_000_000).to_le_bytes());
    let _ = copy_to_user(rem_va, &rbuf);
}
