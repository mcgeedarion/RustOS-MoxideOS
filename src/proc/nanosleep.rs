//! nanosleep syscall  [NR 35].
//!
//! ## Interface
//!   sys_nanosleep(req_va, rem_va) -> 0 / -EINTR / -EFAULT
//!   req: *const timespec  { tv_sec: i64 @ 0, tv_nsec: i64 @ 8 }
//!   rem: *mut   timespec  (zeroed on normal return; set on EINTR)
//!
//! ## Implementation
//!   Uses RDTSC to measure elapsed CPU cycles against a TSC-to-nanosecond
//!   conversion.  TSC_HZ_EST (3 GHz) is a compile-time estimate; a proper
//!   kernel measures this against the HPET/APIC timer on boot.
//!
//!   During the busy-wait the task calls schedule() every 10 ms of elapsed
//!   TSC time, giving cooperative multi-tasking without a hardware timer.
//!
//! ## EINTR
//!   If signal::has_pending_signal(pid) fires during a yield, the sleep is
//!   interrupted: rem_va is written with the remaining duration and
//!   -EINTR (-4) is returned.

use crate::proc::{scheduler, signal};

/// Estimated TSC frequency (3 GHz). Calibrated on boot in a real kernel.
const TSC_HZ_EST: u64 = 3_000_000_000;

/// Call schedule() every 10 ms of TSC-measured time.
const YIELD_INTERVAL_NS: u64 = 10_000_000;

// ── sys_nanosleep [NR 35] ────────────────────────────────────────────────────────

/// sys_nanosleep(req_va, rem_va) → 0 / -EINTR (-4) / -EFAULT (-14) / -EINVAL (-22)
pub fn sys_nanosleep(req_va: usize, rem_va: usize) -> isize {
    if req_va < 0x1000 || req_va.saturating_add(16) > 0x0000_8000_0000_0000 {
        return -14; // EFAULT
    }

    let (tv_sec, tv_nsec): (i64, i64) = unsafe {
        let p = req_va as *const i64;
        (p.read_volatile(), p.add(1).read_volatile())
    };

    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
        return -22; // EINVAL
    }

    let total_ns: u64 = tv_sec as u64 * 1_000_000_000 + tv_nsec as u64;
    if total_ns == 0 { return 0; }

    let start_tsc     = rdtsc();
    let total_cycles  = ns_to_cycles(total_ns);
    let yield_cycles  = ns_to_cycles(YIELD_INTERVAL_NS);
    let pid           = scheduler::current_pid();
    let mut last_yield = start_tsc;

    loop {
        let now     = rdtsc();
        let elapsed = now.wrapping_sub(start_tsc);
        if elapsed >= total_cycles { break; }

        if now.wrapping_sub(last_yield) >= yield_cycles {
            scheduler::schedule();
            last_yield = rdtsc();

            // Check for pending signal after each yield.
            if signal::has_pending_signal(pid) {
                let remaining_cycles =
                    total_cycles.saturating_sub(rdtsc().wrapping_sub(start_tsc));
                let remaining_ns = cycles_to_ns(remaining_cycles);
                write_rem(rem_va, remaining_ns);
                return -4; // EINTR
            }
        }

        core::hint::spin_loop();
    }

    // Normal completion: zero the remainder.
    write_rem(rem_va, 0);
    0
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn write_rem(rem_va: usize, remaining_ns: u64) {
    if rem_va > 0x1000 && rem_va.saturating_add(16) <= 0x0000_8000_0000_0000 {
        let sec  = remaining_ns / 1_000_000_000;
        let nsec = remaining_ns % 1_000_000_000;
        unsafe {
            let p = rem_va as *mut i64;
            p.write_volatile(sec as i64);
            p.add(1).write_volatile(nsec as i64);
        }
    }
}

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | lo as u64
}

#[inline]
fn ns_to_cycles(ns: u64) -> u64 {
    ((ns as u128 * TSC_HZ_EST as u128) / 1_000_000_000) as u64
}

#[inline]
fn cycles_to_ns(cycles: u64) -> u64 {
    ((cycles as u128 * 1_000_000_000) / TSC_HZ_EST as u128) as u64
}
