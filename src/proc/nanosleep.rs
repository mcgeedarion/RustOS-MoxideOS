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
//! `sleep_until_ns` arms a one-shot timer wheel entry that transitions
//! the task Blocked → Ready and calls `wake_pid`.  `block_current()`
//! yields to the scheduler.  EINTR is detected via `sleep_deadline_ns ≠ 0`
//! (timer clears it on normal completion; signals leave it non-zero).
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
//!   - If `rem_va != 0` and the sleep was *relative*, writes the remaining
//!     time to userspace (Linux-compatible: absolute sleeps never write rem).
//!   - Cancels the pending timer so the wheel doesn't fire a stale wakeup.

use crate::proc::process::State;
use crate::proc::scheduler;
use crate::time::clock::{self, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID};
use crate::time::timer::{add_oneshot, cancel_timer};
use crate::time::{read_monotonic_ns, Timespec};
use crate::uaccess::{copy_from_user, copy_to_user};

pub fn now_ns() -> u64 {
    read_monotonic_ns()
}

// ── sys_nanosleep ─────────────────────────────────────────────────────────────

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

    let ret = sleep_ns_internal(delta_ns);

    if ret == -4 && rem_va != 0 {
        write_remaining(rem_va);
        return -4;
    }
    if rem_va != 0 {
        let _ = copy_to_user(rem_va, &[0u8; 16]);
    }
    ret
}

// ── sys_clock_nanosleep ────────────────────────────────────────────────────

/// sys_clock_nanosleep(clockid, flags, req_va, rem_va)  [NR 230]
///
/// flags == 0          → relative sleep (same as nanosleep but clock-aware).
/// flags & TIMER_ABSTIME → absolute sleep on the given clock.
///
/// For *relative* sleeps the clock ID only matters for the rem calculation
/// (we always block on the monotonic timer wheel), so all relative paths
/// are functionally clock-agnostic.
///
/// For *absolute* sleeps the deadline is read on the given clock and
/// converted to a monotonic deadline via:
///   deadline_mono = mono_now + (req_clock - clock_now)
/// which correctly handles wall-clock offsets for CLOCK_REALTIME /
/// CLOCK_TAI without depending on the realtime offset being stable.
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
        // Convert the requested absolute time on `clockid` to a monotonic
        // deadline so the timer wheel (which is always monotonic) fires at
        // the right wall-clock instant.
        let clk_now_ns = match clock::clock_gettime(clockid as i32) {
            Ok(ts) => ts.to_ns(),
            Err(e) => return e as isize,
        };
        if req_ns <= clk_now_ns {
            // Deadline already elapsed — return immediately (POSIX).
            return 0;
        }
        let delta = req_ns - clk_now_ns;
        let mono_dl = read_monotonic_ns() + delta;
        let ret = sleep_until_ns(mono_dl);
        // POSIX: absolute clock_nanosleep does NOT write rem on EINTR.
        ret
    } else {
        // Relative sleep: delta is clock-independent.
        if req_ns == 0 {
            return 0;
        }
        let ret = sleep_ns_internal(req_ns);
        if ret == -4 && rem_va != 0 {
            write_remaining(rem_va);
            return -4;
        }
        if rem_va != 0 {
            let _ = copy_to_user(rem_va, &[0u8; 16]);
        }
        ret
    }
}

// ── sys_clock_gettime ──────────────────────────────────────────────────────

/// sys_clock_gettime(clockid, timespec_va)  [NR 228]
///
/// Dispatches to time::clock::clock_gettime which handles all 11 POSIX
/// clock IDs.  CLOCK_PROCESS_CPUTIME_ID and CLOCK_THREAD_CPUTIME_ID are
/// patched here with real per-process CPU time from the PCB before the
/// result is written to userspace.
pub fn sys_clock_gettime(clockid: u32, timespec_va: usize) -> isize {
    let pid = scheduler::current_pid();

    let ts = match clockid as i32 {
        // CPU-time clocks: read directly from PCB for accuracy.
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            let cpu_ns = scheduler::with_proc(pid, |p| p.cpu_time_ns).unwrap_or(0);
            Timespec::from_ns(cpu_ns)
        }
        // All other clocks delegate to the clock layer.
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
///
/// Returns the resolution of the given clock.  Writes a Timespec to
/// userspace (null timespec_va is valid and means "just validate clockid").
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

// ── Internal blocking primitives ─────────────────────────────────────────────

/// Block the current task for `delta_ns` nanoseconds.
/// Converts to an absolute monotonic deadline and calls `sleep_until_ns`.
/// Returns 0 on normal completion, -4 (EINTR) if woken by a signal.
pub fn sleep_ns_internal(delta_ns: u64) -> isize {
    let deadline = read_monotonic_ns().saturating_add(delta_ns);
    sleep_until_ns(deadline)
}

/// Block the current task until the absolute monotonic deadline `deadline_ns`.
///
/// This is the single real blocking primitive.  All nanosleep paths funnel
/// here.  The protocol:
///
///   1. Record `deadline_ns` in `Pcb::sleep_deadline_ns` (read by rem logic).
///   2. Arm a one-shot timer wheel entry.  The callback:
///        a. Clears `sleep_deadline_ns` (marks normal completion).
///        b. Transitions the task Blocked → Ready.
///        c. Calls `wake_pid` to re-enqueue in the run queue.
///   3. Store the timer ID in `Pcb::sleep_timer_id`.
///   4. Call `block_current()` which calls `schedule()` internally.
///      (Do NOT call schedule() again after block_current.)
///   5. After wakeup: if `sleep_deadline_ns` is still non-zero, a signal
///      interrupted the sleep.  Cancel the stale timer and return -EINTR.
///
/// ## Spurious wakeup guard
/// If the deadline has already passed by the time we arm the timer, the
/// wheel fires immediately on the next `expire_timers()` tick, which is
/// correct and avoids sleeping past the deadline.
pub fn sleep_until_ns(deadline_ns: u64) -> isize {
    let pid = scheduler::current_pid();

    // Check if the deadline has already passed.
    if read_monotonic_ns() >= deadline_ns {
        return 0;
    }

    // Step 1: record deadline before arming (prevents lost-wakeup race).
    scheduler::with_proc_mut(pid, |p, _pl| {
        p.sleep_deadline_ns = deadline_ns;
    });

    // Step 2: arm one-shot timer.
    let timer_id = add_oneshot(deadline_ns, move |_| {
        scheduler::with_proc_mut(pid, |p, pl| {
            p.sleep_deadline_ns = 0; // mark normal completion
            p.sleep_timer_id = 0;
            if p.state == State::Blocked {
                pl.set_state(p, State::Ready);
            }
        });
        scheduler::wake_pid(pid);
    });

    // Step 3: persist the timer ID for cancellation on EINTR.
    scheduler::with_proc_mut(pid, |p, _pl| {
        p.sleep_timer_id = timer_id;
    });

    // Step 4: yield to scheduler. block_current() calls schedule() internally;
    // no extra schedule() call must follow.
    scheduler::block_current();

    // Step 5: EINTR detection.
    // Normal completion: timer callback cleared sleep_deadline_ns to 0.
    // Signal interruption: sleep_deadline_ns is still non-zero.
    let interrupted = scheduler::with_proc(pid, |p| p.sleep_deadline_ns != 0).unwrap_or(false);

    if interrupted {
        // Cancel the stale timer so it doesn't fire a spurious wakeup later.
        let tid = scheduler::with_proc(pid, |p| p.sleep_timer_id).unwrap_or(0);
        if tid != 0 {
            cancel_timer(tid);
        }
        scheduler::with_proc_mut(pid, |p, _pl| p.sleep_timer_id = 0);
        return -4; // EINTR
    }
    0
}

// ── Remainder helper ────────────────────────────────────────────────────────────

/// Write the remaining sleep time to `rem_va` for EINTR paths.
/// Called only when rem_va != 0 and the sleep was relative.
fn write_remaining(rem_va: usize) {
    let pid = scheduler::current_pid();
    let rem = scheduler::with_proc(pid, |p| {
        p.sleep_deadline_ns.saturating_sub(read_monotonic_ns())
    })
    .unwrap_or(0);
    let mut rbuf = [0u8; 16];
    rbuf[0..8].copy_from_slice(&(rem / 1_000_000_000).to_le_bytes());
    rbuf[8..16].copy_from_slice(&(rem % 1_000_000_000).to_le_bytes());
    let _ = copy_to_user(rem_va, &rbuf);
}
