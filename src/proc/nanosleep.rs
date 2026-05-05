//! nanosleep + clock_gettime syscalls.

use crate::uaccess::{copy_from_user, copy_to_user};

/// sys_nanosleep(req_va, rem_va)  [NR 35]
pub fn sys_nanosleep(req_va: usize, _rem_va: usize) -> isize {
    // Read `struct timespec { tv_sec: i64, tv_nsec: i64 }` from user.
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, req_va).is_err() { return -14; } // EFAULT

    let sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 { return -22; } // EINVAL

    // Approximate busy-wait: ~1 ns per iteration at 1 GHz.
    // Scaled down for emulation. No schedule() call — known limitation;
    // a real sleep would block the process on a timer event.
    let iters  = (sec as u64) * 1_000_000_000 + nsec as u64;
    let scaled = iters / 100;
    for _ in 0..scaled { core::hint::spin_loop(); }
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
