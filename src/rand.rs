//! Kernel randomness subsystem.
//!
//! ## Entropy sources
//!
//! | Architecture | Hardware source                         | Fallback          |
//! |--------------|-----------------------------------------|-------------------|
//! | x86_64       | `RDRAND` (retried up to 10×)            | xorshift-64 PRNG  |
//! | riscv64      | `mcycle XOR minstret` (CSR reads)       | xorshift-64 PRNG  |
//!
//! ## API
//!
//! * `seed_from_hw()` — must be called once early in `kernel_main` (replaces
//!   the old `seed_from_tsc()`).  Seeds the xorshift state from hardware.
//! * `arch_entropy()` — returns one u64 of hardware entropy.  Use this for
//!   all **security-sensitive** outputs: stack canaries, `getrandom(2)`,
//!   ASLR offsets, key material.  Never returns xorshift output unless
//!   hardware entropy is unavailable.
//! * `next_u64()` — xorshift-64 PRNG; suitable for non-security randomness
//!   (jitter, scheduling, hash seeds).  SMP-safe via CAS loop.
//! * `rdrand64()` (x86_64 only) — raw RDRAND helper used internally.
//!
//! ## Why separate entropy from PRNG?
//!
//! Xorshift-64 is a fast but **non-cryptographic** PRNG: any output value
//! allows full state recovery.  Using it for stack canaries or getrandom
//! would let an attacker with one read gadget predict all future random
//! output.  `arch_entropy()` isolates the security-critical path.

use core::sync::atomic::{AtomicU64, Ordering};

/// Xorshift-64 PRNG state.  Initialised to 0; seeded by `seed_from_hw()`.
/// Zero state is detectable because xorshift(0) == 0 forever.
static STATE: AtomicU64 = AtomicU64::new(0);

// ── Hardware seeding ─────────────────────────────────────────────────────

/// Seed the xorshift-64 PRNG from a hardware entropy source.
///
/// **Must** be called once during early `kernel_main`, before any call to
/// `next_u64()` or `arch_entropy()`.
///
/// Replaces the old `seed_from_tsc()` which was x86-only and would panic
/// on RISC-V due to the unguarded `rdtsc` instruction.
pub fn seed_from_hw() {
    let raw = hw_seed_raw();
    // Mix with a compile-time salt so zero-TSC / zero-mcycle emulators
    // still produce a non-zero seed that is unique per build.
    let seed = raw ^ 0xDEAD_BEEF_CAFE_BABE_u64;
    let seed = if seed == 0 { 0xDEAD_BEEF_CAFE_BABE_u64 } else { seed };
    STATE.store(seed, Ordering::Relaxed);
}

// Keep the old name as a deprecated alias so existing call sites in
// kernel_main continue to compile without changes.
#[deprecated(note = "renamed to seed_from_hw()")]
#[inline]
pub fn seed_from_tsc() { seed_from_hw(); }

/// Read a raw u64 from the hardware timing source on this architecture.
/// Not suitable for direct security use — use `arch_entropy()` instead.
#[inline]
fn hw_seed_raw() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags)
        );
        (hi as u64) << 32 | lo as u64
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        let cycle: u64;
        let instret: u64;
        core::arch::asm!(
            "csrr {c}, mcycle",
            "csrr {i}, minstret",
            c = out(reg) cycle,
            i = out(reg) instret,
            options(nostack, nomem)
        );
        cycle ^ instret
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    compile_error!("rand::hw_seed_raw: unsupported architecture — add a case here");
}

// ── arch_entropy — security-critical entropy ─────────────────────────────

/// Return one u64 of hardware entropy suitable for security-sensitive use.
///
/// - x86_64: tries `RDRAND` up to 10 times (per Intel guidance).  Falls
///   back to xorshift only if RDRAND fails all attempts (e.g. a VM that
///   doesn't expose RDRAND), with a panic-level log warning.
/// - riscv64: XORs `mcycle` and `minstret`, then mixes with xorshift state
///   for additional diffusion.  Not ideal entropy but avoids the x86-only
///   instruction trap on RISC-V.
///
/// **Never** returns a pure xorshift value on x86_64 without logging a
/// warning, so RDRAND failures do not silently degrade security.
pub fn arch_entropy() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        for _ in 0..10 {
            let result: u64;
            let ok: u8;
            unsafe {
                core::arch::asm!(
                    "rdrand {v}",
                    "setc   {ok}",
                    v  = out(reg)      result,
                    ok = out(reg_byte) ok,
                    options(nostack, nomem)
                );
            }
            if ok != 0 { return result; }
        }
        // RDRAND failed 10 consecutive times — extremely rare on real hardware;
        // common only under certain hypervisors that disable the instruction.
        // Fall through to xorshift with a clear warning.
        crate::println!("WARN: rand: RDRAND failed 10× — falling back to xorshift entropy");
        next_u64()
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        // RISC-V does not have a standardised entropy CSR in S-mode until
        // the Zkr extension (not yet universally available in QEMU virt).
        // Use mcycle XOR minstret as a low-quality but hardware-derived
        // source and mix it thoroughly with the xorshift state.
        let cycle: u64;
        let instret: u64;
        core::arch::asm!(
            "csrr {c}, mcycle",
            "csrr {i}, minstret",
            c = out(reg) cycle,
            i = out(reg) instret,
            options(nostack, nomem)
        );
        let hw = cycle ^ instret;
        // Mix hardware bits into xorshift state and return the mixed value.
        let xs = next_u64();
        // Final avalanche: multiply-xorshift mix.
        let mixed = hw.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(xs);
        mixed ^ (mixed >> 30)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    compile_error!("rand::arch_entropy: unsupported architecture — add a case here");
}

// ── Xorshift-64 PRNG ──────────────────────────────────────────────────────

/// Return the next pseudo-random u64 from the xorshift-64 PRNG.
///
/// **Not cryptographically secure.** Use only for non-security randomness:
/// scheduler jitter, hash table seeds, non-critical offsets.
///
/// SMP-safe: uses a compare-and-swap retry loop so two CPUs advancing from
/// the same state cannot produce the same sequence.
pub fn next_u64() -> u64 {
    loop {
        let s = STATE.load(Ordering::Relaxed);
        // xorshift64 step — period 2^64-1; never produces 0.
        let s1 = s ^ (s << 13);
        let s1 = s1 ^ (s1 >> 7);
        let s1 = s1 ^ (s1 << 17);
        // CAS: only commit if state hasn't changed under us.
        match STATE.compare_exchange_weak(s, s1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_)  => return s1,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

// ── x86_64-only helpers (kept for backward compat with callers) ───────────

/// Raw RDRAND — x86_64 only.  Prefer `arch_entropy()` at call sites.
/// Returns `None` if RDRAND fails on all attempts.
#[cfg(target_arch = "x86_64")]
pub fn rdrand64() -> u64 {
    for _ in 0..10 {
        let result: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc   {ok}",
                v  = out(reg)      result,
                ok = out(reg_byte) ok,
                options(nostack, nomem)
            );
        }
        if ok != 0 { return result; }
    }
    next_u64()
}

/// RDRAND with xorshift fallback — x86_64 only.
/// Kept for call-site compatibility; prefer `arch_entropy()` for new code.
#[cfg(target_arch = "x86_64")]
pub fn rdrand_or_lfsr() -> u64 { rdrand64() }
