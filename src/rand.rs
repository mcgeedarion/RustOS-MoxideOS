//! Xorshift-64 PRNG seeded from the TSC at early boot.
//!
//! `seed_from_tsc()` MUST be called once during kernel_main before any call
//! to `next_u64()`.  The initial compile-time value is intentionally zero so
//! that uninitialised use is immediately obvious (xorshift(0) == 0 forever).
use core::sync::atomic::{AtomicU64, Ordering};

/// PRNG state. Initialised to 0; `seed_from_tsc` replaces it with a live
/// TSC reading mixed with a compile-time salt.
static STATE: AtomicU64 = AtomicU64::new(0);

/// Seed the PRNG from the processor timestamp counter.
///
/// Call once, early in `kernel_main`, before any subsystem that calls
/// `next_u64()` (including ASLR bias selection and `getrandom` fallback).
pub fn seed_from_tsc() {
    let tsc: u64 = unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
                         options(nostack, nomem));
        (hi as u64) << 32 | lo as u64
    };
    // Mix with a compile-time salt so identical TSC values (e.g. in emulators
    // that return 0) still produce a non-zero, unique-per-build seed.
    let seed = tsc ^ 0xdeadbeef_cafebabe;
    // xorshift requires a non-zero state; fall back to the salt alone.
    let seed = if seed == 0 { 0xdeadbeef_cafebabe } else { seed };
    STATE.store(seed, Ordering::Relaxed);
}

/// Return the next pseudo-random u64 (xorshift64).
pub fn next_u64() -> u64 {
    // xorshift64 — period 2^64-1; never produces 0.
    let s = STATE.load(Ordering::Relaxed);
    let s = s ^ (s << 13);
    let s = s ^ (s >> 7);
    let s = s ^ (s << 17);
    STATE.store(s, Ordering::Relaxed);
    s
}

/// Expose raw RDRAND fallback path used by getrandom/devfs.
pub fn rdrand_or_lfsr() -> u64 {
    // Try hardware RDRAND first.
    let result: u64;
    let ok: u8;
    unsafe {
        core::arch::asm!(
            "rdrand {v}",
            "setc {ok}",
            v  = out(reg) result,
            ok = out(reg_byte) ok,
            options(nostack, nomem),
        );
    }
    if ok != 0 { result } else { next_u64() }
}
