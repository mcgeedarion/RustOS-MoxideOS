//! nanosleep + clock_gettime syscalls.

/// sys_nanosleep(req_va, rem_va)  [NR 35]
/// Spins for the requested duration. No actual timer — busy-wait for now.
pub fn sys_nanosleep(req_va: usize, _rem_va: usize) -> isize {
    if req_va < 0x1000 { return -14; }
    // struct timespec: { tv_sec: i64, tv_nsec: i64 }
    let sec  = unsafe { (req_va as *const i64).read_volatile() };
    let nsec = unsafe { ((req_va + 8) as *const i64).read_volatile() };
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 { return -22; }
    // Approximate spin: ~1 ns per iteration at 1 GHz, very rough.
    let iters = (sec as u64) * 1_000_000_000 + nsec as u64;
    let scaled = iters / 100; // avoid very long spins in emulation
    for _ in 0..scaled { core::hint::spin_loop(); }
    0
}

/// sys_clock_gettime(clockid, timespec_va)  [NR 228]
/// Returns a monotonic counter based on the APIC timer tick count.
/// Resolution is coarse — ticks, not nanoseconds — but sufficient for
/// musl's startup checks and basic program timing.
pub fn sys_clock_gettime(clockid: u32, timespec_va: usize) -> isize {
    if timespec_va < 0x1000 { return -14; }
    // Read APIC timer current count as a rough tick source.
    let ticks = crate::arch::x86_64::apic::timer_count() as u64;
    // Approximate: APIC fires at ~100 Hz (10 ms), count is ~1.875M per tick.
    // Convert ticks to seconds/nanoseconds (very rough).
    let ns_per_tick: u64 = 10_000_000; // 10 ms in nanoseconds
    let total_ns = ticks.wrapping_mul(ns_per_tick);
    let sec  = total_ns / 1_000_000_000;
    let nsec = total_ns % 1_000_000_000;
    unsafe {
        (timespec_va as *mut i64).write_volatile(sec as i64);
        ((timespec_va + 8) as *mut i64).write_volatile(nsec as i64);
    }
    0
}
