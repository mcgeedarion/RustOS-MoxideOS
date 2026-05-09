//! nanosleep + clock_gettime syscalls.

use crate::uaccess::{copy_from_user, copy_to_user};
use crate::proc::scheduler;

/// sys_nanosleep(req_va, rem_va)  [NR 35]
pub fn sys_nanosleep(req_va: usize, rem_va: usize) -> isize {
    // Read `struct timespec { tv_sec: i64, tv_nsec: i64 }` from user.
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, req_va).is_err() { return -14; } // EFAULT

    // SAFETY: buf is [0u8; 16]; slices [0..8] and [8..16] are always exactly
    // 8 bytes so TryFrom<&[u8]> for [u8; 8] cannot fail here.
    let sec  = i64::from_le_bytes(<[u8; 8]>::try_from(&buf[0..8]).unwrap_or([0; 8]));
    let nsec = i64::from_le_bytes(<[u8; 8]>::try_from(&buf[8..16]).unwrap_or([0; 8]));
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 { return -22; } // EINVAL

    // Yield rather than busy-spin: mark ourselves Blocked and call
    // schedule() so other processes can run.
    // For RT tasks, block_current() also resets rt_cpu_time_us per
    // RLIMIT_RTTIME semantics (the budget only counts continuous RT CPU time).
    //
    // TODO: register a timer event that calls scheduler::wake_pid(pid)
    //       after (sec * 1e9 + nsec) nanoseconds for precise semantics.
    if sec > 0 || nsec > 0 {
        scheduler::block_current();
        scheduler::schedule();
        // Re-cache pid after schedule() — the current task pointer may have
        // changed on a SMP migration path (M1 latent fix).
        let pid = scheduler::current_pid();
        scheduler::with_proc_mut(pid, |p| {
            if p.state == crate::proc::process::State::Blocked {
                p.state = crate::proc::process::State::Ready;
            }
        });
    }

    // Write zeroed remainder back to userspace (M1).
    // The sleep completed fully; once a real per-process timer is wired,
    // write the actual remaining time here on EINTR.
    if rem_va != 0 {
        let zero = [0u8; 16];
        let _ = copy_to_user(rem_va, &zero);
    }

    0
}

/// sys_clock_gettime(clockid, timespec_va)  [NR 228]
pub fn sys_clock_gettime(_clockid: u32, timespec_va: usize) -> isize {
    let ticks = crate::arch::x86_64::apic::timer_count() as u64;
    let ns_per_tick: u64 = 10_000_000; // 10 ms per tick (100 Hz APIC)
    let total_ns = ticks.wrapping_mul(ns_per_tick);
    let sec  = (total_ns / 1_000_000_000) as i64;
    let nsec = (total_ns % 1_000_000_000) as i64;

    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&nsec.to_le_bytes());
    if copy_to_user(timespec_va, &buf).is_err() { return -14; } // EFAULT
    0
}
