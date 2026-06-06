//! x86_64 TSC (Time Stamp Counter) clocksource.
//!
//! ## Calibration strategy
//!
//! 1. Check CPUID leaf 0x15 (`TSC / Core Crystal Clock ratio`).  If the
//!    denominator is non-zero, use the hardware-reported frequency directly.
//!    This is guaranteed accurate on Skylake+.
//!
//! 2. Fall back to CPUID leaf 0x16 (CPU/Bus/Reference MHz) — available on
//!    Broadwell+.
//!
//! 3. Final fall-back: use the legacy PIT (8253) channel 2 to gate-count TSC
//!    ticks over a ~10 ms window, giving ~1% accuracy.
//!
//! ## Invariant TSC check
//!
//! `CPUID[80000007H].EDX[8]` (Invariant TSC).  If clear, TSC is unsafe to
//! use as a clocksource (frequency changes with P-states).
//!
//! ## `read_ns()`
//!
//! Converts raw TSC ticks to nanoseconds using the pre-computed multiplier
//! and shift (the same `(mul, shift)` trick as Linux `cyc2ns`):
//!
//!   ns = (tsc * mul) >> shift
//!
//! where `mul = (10^9 << shift) / freq_hz` and `shift` is chosen so that
//! `mul` fits in a `u64` without overflow.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

static TSC_MUL: AtomicU64 = AtomicU64::new(0);
static TSC_SHIFT: AtomicU32 = AtomicU32::new(0);
static TSC_BASE: AtomicU64 = AtomicU64::new(0); // TSC value at boot
static INVARIANT: AtomicBool = AtomicBool::new(false);

/// Attempt TSC calibration.  Returns `true` if TSC is invariant and usable.
pub fn calibrate() -> bool {
    if !is_invariant() {
        return false;
    }
    let freq = detect_freq_hz();
    if freq == 0 {
        return false;
    }
    compute_mul_shift(freq);
    TSC_BASE.store(rdtsc(), Ordering::SeqCst);
    true
}

/// Read current time in nanoseconds since `calibrate()` was called.
pub fn read_ns() -> u64 {
    let tsc = rdtsc().wrapping_sub(TSC_BASE.load(Ordering::Relaxed));
    let mul = TSC_MUL.load(Ordering::Relaxed);
    let shift = TSC_SHIFT.load(Ordering::Relaxed);
    // 128-bit intermediate to avoid overflow:
    let hi = (tsc >> 32) * mul;
    let lo = (tsc & 0xFFFF_FFFF) * mul;
    ((hi + (lo >> 32)) >> (shift - 32)) as u64
}

pub fn freq_hz() -> u64 {
    let mul = TSC_MUL.load(Ordering::Relaxed);
    let shift = TSC_SHIFT.load(Ordering::Relaxed);
    if mul == 0 {
        return 0;
    }
    (1_000_000_000u64 << shift) / mul
}

fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

fn is_invariant() -> bool {
    // CPUID[80000007H].EDX bit 8
    let edx = cpuid_edx(0x8000_0007);
    let inv = edx & (1 << 8) != 0;
    INVARIANT.store(inv, Ordering::SeqCst);
    inv
}

/// CPUID leaf 0x15: TSC / Crystal ratio.
fn cpuid15() -> Option<u64> {
    let (eax, ebx, ecx) = cpuid3(0x15);
    if eax == 0 || ebx == 0 {
        return None;
    }
    // freq = ecx * ebx / eax  (ecx = crystal Hz; 0 on some CPUs)
    if ecx != 0 {
        return Some(ecx as u64 * ebx as u64 / eax as u64);
    }
    // Broadwell: crystal is 25 MHz
    Some(25_000_000u64 * ebx as u64 / eax as u64)
}

/// CPUID leaf 0x16: CPU base frequency (MHz).
fn cpuid16() -> Option<u64> {
    let (eax, _, _) = cpuid3(0x16);
    if eax == 0 {
        None
    } else {
        Some(eax as u64 * 1_000_000)
    }
}

/// PIT-based calibration: gate TSC ticks over ~10 ms.
fn pit_calibrate() -> u64 {
    // PIT channel 2, mode 0 (one-shot), 11932 ticks ≈ 10 ms.
    const PIT_HZ: u64 = 1_193_182;
    const PIT_COUNT: u64 = 11_932; // ≈ 10 ms
    unsafe {
        // Enable gate, disable speaker.
        let mut v: u8 = inb(0x61) & 0xFD | 0x01;
        outb(0x61, v);
        // Set mode: channel 2, mode 0, binary.
        outb(0x43, 0xB0);
        outb(0x42, (PIT_COUNT & 0xFF) as u8);
        outb(0x42, ((PIT_COUNT >> 8) & 0xFF) as u8);
        // Reset gate to start count.
        v = inb(0x61) & 0xFE;
        outb(0x61, v);
        let t0 = rdtsc();
        v |= 0x01;
        outb(0x61, v);
        // Wait for OUT2 (bit 5 of 0x61) to go high.
        while inb(0x61) & 0x20 == 0 {}
        let t1 = rdtsc();
        // freq = ticks / time_s = ticks * PIT_HZ / PIT_COUNT
        (t1.wrapping_sub(t0)) * PIT_HZ / PIT_COUNT
    }
}

fn detect_freq_hz() -> u64 {
    if let Some(f) = cpuid15() {
        return f;
    }
    if let Some(f) = cpuid16() {
        return f;
    }
    pit_calibrate()
}

/// Compute `(mul, shift)` such that `(tsc * mul) >> shift = ns`.
fn compute_mul_shift(freq_hz: u64) {
    // Choose shift so that mul < 2^64.
    let mut shift = 32u32;
    loop {
        let mul = (1_000_000_000u128 << shift) / freq_hz as u128;
        if mul <= u64::MAX as u128 {
            TSC_MUL.store(mul as u64, Ordering::SeqCst);
            TSC_SHIFT.store(shift, Ordering::SeqCst);
            return;
        }
        shift -= 1;
        if shift == 0 {
            break;
        }
    }
}

fn cpuid3(leaf: u32) -> (u32, u32, u32) {
    let (eax, ebx, ecx): (u32, u32, u32);
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "cpuid",
            inout("eax") leaf => eax,
            out("ebx") ebx,
            inout("ecx") 0u32 => ecx,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = leaf;
        (0, 0, 0)
    }
    #[cfg(target_arch = "x86_64")]
    (eax, ebx, ecx)
}

fn cpuid_edx(leaf: u32) -> u32 {
    let edx: u32;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "cpuid",
            inout("eax") leaf => _,
            out("ebx") _, out("ecx") _,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = leaf;
        edx = 0;
    }
    edx
}

#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack));
    val
}
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack));
}
