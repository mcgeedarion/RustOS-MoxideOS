//! Kernel randomness subsystem.
//!
//! ## Entropy sources
//!
//! | Architecture | Hardware source                         | Fallback          |
//! |--------------|-----------------------------------------|-------------------|
//! | x86_64       | `RDRAND` (in-asm retry loop, ≤10×)      | xorshift-64 PRNG  |
//! | riscv64      | `mcycle XOR minstret` (CSR reads)       | xorshift-64 PRNG  |
//!
//! ## API
//!
//! * `seed_from_hw()` — must be called once early in `kernel_main`.
//! * `arch_entropy()` — one u64 of hardware entropy for security-sensitive
//!   outputs (stack canaries, `getrandom(2)`, ASLR, key material).
//! * `next_u64()` — xorshift-64 PRNG; non-security randomness only.
//! * `rdrand64()` (x86_64 only) — raw RDRAND helper used internally.
//!
//! ## RDRAND retry optimisation
//!
//! The original code retried RDRAND via a Rust `for` loop that re-entered
//! the `asm!` block on each failed attempt.  Every `asm!` entry point is
//! an opaque scheduling barrier for LLVM, so each retry incurred the full
//! block overhead.  Moving the retry loop *inside* the `asm!` block with a
//! local label (`2: rdrand / jnc 2b`) eliminates that overhead and keeps
//! the entire retry sequence in a single micro-op dispatch window.

use core::sync::atomic::{AtomicU64, Ordering};

/// Xorshift-64 PRNG state.  Initialised to 0; seeded by `seed_from_hw()`.
static STATE: AtomicU64 = AtomicU64::new(0);

// ── Hardware seeding ─────────────────────────────────────────────────────

pub fn seed_from_hw() {
    let raw = hw_seed_raw();
    let seed = raw ^ 0xDEAD_BEEF_CAFE_BABE_u64;
    let seed = if seed == 0 { 0xDEAD_BEEF_CAFE_BABE_u64 } else { seed };
    STATE.store(seed, Ordering::Relaxed);
}

#[deprecated(note = "renamed to seed_from_hw()")]
#[inline]
pub fn seed_from_tsc() { seed_from_hw(); }

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

pub fn arch_entropy() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // Retry loop is entirely inside the asm! block using a local numeric
        // label so that every retry stays within a single dispatch window and
        // LLVM never sees a branch back into a new asm! barrier.
        // The outer Rust counter limits total retries to 10 (Intel guidance)
        // before falling back to xorshift.
        let result: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "xor {cnt:e}, {cnt:e}",       // cnt = 0
                "2:",
                "rdrand {v}",
                "jc 3f",                       // CF=1 → success, jump to exit
                "inc {cnt:e}",
                "cmp {cnt:e}, 10",
                "jl 2b",                       // retry up to 10 times
                "xor {ok}, {ok}",             // all retries failed: ok=0
                "jmp 4f",
                "3:",
                "mov {ok}, 1",
                "4:",
                v   = out(reg)      result,
                ok  = out(reg_byte) ok,
                cnt = out(reg)      _,
                options(nostack, nomem)
            );
        }
        if ok != 0 { return result; }
        crate::println!("WARN: rand: RDRAND failed 10× — falling back to xorshift entropy");
        next_u64()
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
        let hw = cycle ^ instret;
        let xs = next_u64();
        let mixed = hw.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(xs);
        mixed ^ (mixed >> 30)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    compile_error!("rand::arch_entropy: unsupported architecture — add a case here");
}

// ── Xorshift-64 PRNG ──────────────────────────────────────────────────────

pub fn next_u64() -> u64 {
    loop {
        let s = STATE.load(Ordering::Relaxed);
        let s1 = s ^ (s << 13);
        let s1 = s1 ^ (s1 >> 7);
        let s1 = s1 ^ (s1 << 17);
        match STATE.compare_exchange_weak(s, s1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_)  => return s1,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

// ── x86_64-only helpers ───────────────────────────────────────────────────

/// Raw RDRAND — x86_64 only.  Prefer `arch_entropy()` at call sites.
/// The retry loop lives inside the `asm!` block (see module doc).
#[cfg(target_arch = "x86_64")]
pub fn rdrand64() -> u64 {
    let result: u64;
    let ok: u8;
    unsafe {
        core::arch::asm!(
            "xor {cnt:e}, {cnt:e}",
            "2:",
            "rdrand {v}",
            "jc 3f",
            "inc {cnt:e}",
            "cmp {cnt:e}, 10",
            "jl 2b",
            "xor {ok}, {ok}",
            "jmp 4f",
            "3:",
            "mov {ok}, 1",
            "4:",
            v   = out(reg)      result,
            ok  = out(reg_byte) ok,
            cnt = out(reg)      _,
            options(nostack, nomem)
        );
    }
    if ok != 0 { result } else { next_u64() }
}

/// RDRAND with xorshift fallback — kept for call-site compatibility.
#[cfg(target_arch = "x86_64")]
pub fn rdrand_or_lfsr() -> u64 { rdrand64() }
