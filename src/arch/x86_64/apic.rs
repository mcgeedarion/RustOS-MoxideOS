//! Local APIC + IO-APIC driver with SMP AP bringup.
//!
//! Supports both xAPIC (MMIO) and x2APIC (MSR) modes.
//! AP bringup follows the MP specification:
//!   1. INIT IPI  → resets AP
//!   2. 10 ms delay
//!   3. SIPI #1   → AP starts executing trampoline at `TRAMPOLINE_PHYS >> 12`
//!   4. 200 µs delay
//!   5. SIPI #2   → second attempt (spec-required)
//!
//! ## APIC timer calibration (real hardware)
//!
//! The APIC timer bus-clock frequency varies per chip and is NOT fixed.
//! We calibrate it once at BSP init using one of two methods:
//!
//!   Method A — CPUID leaf 0x15 (preferred, Skylake+)
//!     Gives TSC frequency directly: core_crystal_hz = ecx,
//!     tsc_hz = core_crystal_hz * ebx / eax.
//!     APIC timer ticks at tsc_hz / (bus_ratio), but we use the TSC
//!     as our reference in busy_wait_us so Method A only needs TSC_HZ.
//!
//!   Method B — PIT channel 2 gate (fallback, works on all x86 hardware)
//!     Gate PIT ch2 for exactly 50 ms, count APIC timer decrements.
//!     APIC_TICKS_PER_MS = ticks_counted / 50.
//!
//! After calibration `APIC_TICKS_PER_MS` and `TSC_TICKS_PER_US` are set.
//! `busy_wait_us` uses the TSC, `apic_timer_start_ms` uses APIC ticks.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::ptr::{read_volatile, write_volatile};

// ───── MMIO base (remapped to a fixed kernel VA) ─────────────────────────────
pub const LAPIC_PHYS_BASE: u64 = 0xFEE0_0000;
pub const LAPIC_VIRT_BASE: u64 = 0xFFFF_FFFF_FEE0_0000;

// ───── Local APIC register offsets (bytes) ───────────────────────────────────
const LAPIC_ID:          usize = 0x020;
const LAPIC_VERSION:     usize = 0x030;
const LAPIC_TPR:         usize = 0x080;
const LAPIC_EOI:         usize = 0x0B0;
const LAPIC_SPURIOUS:    usize = 0x0F0;
const LAPIC_ICR_LO:      usize = 0x300;
const LAPIC_ICR_HI:      usize = 0x310;
const LAPIC_TIMER_LVT:   usize = 0x320;
const LAPIC_THERMAL_LVT: usize = 0x330;
const LAPIC_PERF_LVT:    usize = 0x340;
const LAPIC_LINT0_LVT:   usize = 0x350;
const LAPIC_LINT1_LVT:   usize = 0x360;
const LAPIC_ERROR_LVT:   usize = 0x370;
const LAPIC_TIMER_ICR:   usize = 0x380;
const LAPIC_TIMER_CCR:   usize = 0x390;
const LAPIC_TIMER_DCR:   usize = 0x3E0;

// ───── ICR delivery mode bits ─────────────────────────────────────────────────
const ICR_FIXED:             u32 = 0 << 8;
const ICR_INIT:              u32 = 5 << 8;
const ICR_SIPI:              u32 = 6 << 8;
const ICR_ASSERT:            u32 = 1 << 14;
const ICR_DEASSERT:          u32 = 0 << 14;
const ICR_LEVEL:             u32 = 1 << 15;
const ICR_DELIVERY_PENDING:  u32 = 1 << 12;

// ───── Spurious vector ───────────────────────────────────────────────────────
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// Physical address of the AP trampoline page (must be < 1 MiB).
pub const TRAMPOLINE_PHYS: u64 = 0x8000;

/// x2APIC available?
static X2APIC: AtomicBool = AtomicBool::new(false);

// ───── Calibrated timing values ──────────────────────────────────────────────

/// APIC timer ticks per millisecond (set by calibrate_apic_timer).
/// At DCR=0 (divide-by-2) this is typically 1–5 million on modern hardware.
static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);

/// TSC ticks per microsecond (set by calibrate_tsc).
static TSC_TICKS_PER_US: AtomicU64 = AtomicU64::new(0);

// ───── Register accessors ────────────────────────────────────────────────────

#[inline]
unsafe fn lapic_read(offset: usize) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        let msr = 0x800u32 + (offset >> 4) as u32;
        let mut lo: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") _,
            options(nostack, preserves_flags)
        );
        lo
    } else {
        let va = (LAPIC_VIRT_BASE as usize + offset) as *const u32;
        read_volatile(va)
    }
}

#[inline]
unsafe fn lapic_write(offset: usize, val: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        let msr = 0x800u32 + (offset >> 4) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val,
            in("edx") 0u32,
            options(nostack, preserves_flags)
        );
    } else {
        let va = (LAPIC_VIRT_BASE as usize + offset) as *mut u32;
        write_volatile(va, val);
    }
}

/// Wait until ICR delivery is no longer pending.
#[inline]
unsafe fn icr_wait() {
    while lapic_read(LAPIC_ICR_LO) & ICR_DELIVERY_PENDING != 0 {
        core::hint::spin_loop();
    }
}

// ───── BSP init ──────────────────────────────────────────────────────────────

/// Initialise the BSP's local APIC and calibrate the timer.
/// Called once from `apic_init()` in kernel_main.
pub unsafe fn init() {
    // Check for x2APIC capability (CPUID leaf 1, ECX bit 21).
    let ecx: u32;
    core::arch::asm!(
        "mov eax, 1",
        "cpuid",
        out("ecx") ecx,
        out("eax") _,
        out("ebx") _,
        out("edx") _,
        options(nostack)
    );
    if ecx & (1 << 21) != 0 {
        let mut base_lo: u32;
        let mut base_hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0x1Bu32,
            out("eax") base_lo,
            out("edx") base_hi,
            options(nostack)
        );
        base_lo |= (1 << 10) | (1 << 11);
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x1Bu32,
            in("eax") base_lo,
            in("edx") base_hi,
            options(nostack)
        );
        X2APIC.store(true, Ordering::Relaxed);
        log::info!("apic: x2APIC mode enabled");
    }

    // Enable LAPIC.
    lapic_write(LAPIC_SPURIOUS, 0x100 | SPURIOUS_VECTOR as u32);
    lapic_write(LAPIC_TIMER_LVT,   0x10000);
    lapic_write(LAPIC_THERMAL_LVT, 0x10000);
    lapic_write(LAPIC_PERF_LVT,    0x10000);
    lapic_write(LAPIC_LINT0_LVT,   0x10000);
    lapic_write(LAPIC_LINT1_LVT,   0x10000);
    lapic_write(LAPIC_ERROR_LVT,   0x10000);
    lapic_write(LAPIC_TPR, 0);

    log::info!("apic: BSP LAPIC id={}", lapic_read(LAPIC_ID));

    // Calibrate TSC and APIC timer frequencies.
    calibrate_tsc();
    calibrate_apic_timer();
}

/// Returns APIC timer ticks per millisecond (after calibration).
#[inline]
pub fn apic_ticks_per_ms() -> u64 {
    APIC_TICKS_PER_MS.load(Ordering::Relaxed)
}

/// Program the APIC timer in one-shot mode to fire after `ms` milliseconds
/// on the given `vector`. Caller must have interrupts disabled or handle
/// the race between programming and enabling.
pub fn apic_timer_start_ms(ms: u64, vector: u8) {
    let ticks_per_ms = apic_ticks_per_ms();
    let initial_count = (ticks_per_ms * ms) as u32;
    unsafe {
        // DCR = divide by 2 (must match calibration).
        lapic_write(LAPIC_TIMER_DCR, 0x0);
        // LVT timer: one-shot, not masked.
        lapic_write(LAPIC_TIMER_LVT, vector as u32);
        lapic_write(LAPIC_TIMER_ICR, initial_count);
    }
}

// ───── AP init ────────────────────────────────────────────────────────────────

/// Initialise the LAPIC on an AP. Called from `ap_entry()` on each AP.
pub unsafe fn ap_init_local() {
    lapic_write(LAPIC_SPURIOUS, 0x100 | SPURIOUS_VECTOR as u32);
    lapic_write(LAPIC_TIMER_LVT,   0x10000);
    lapic_write(LAPIC_THERMAL_LVT, 0x10000);
    lapic_write(LAPIC_PERF_LVT,    0x10000);
    lapic_write(LAPIC_LINT0_LVT,   0x10000);
    lapic_write(LAPIC_LINT1_LVT,   0x10000);
    lapic_write(LAPIC_ERROR_LVT,   0x10000);
    lapic_write(LAPIC_TPR, 0);
}

// ───── AP bringup ─────────────────────────────────────────────────────────────

pub fn start_all_aps() {
    install_trampoline();
    let n = crate::smp::num_cpus();
    for cpu in 0..n {
        if let Some(info) = crate::smp::cpu_info(cpu) {
            if !info.is_bsp {
                unsafe { start_ap(info.hw_id, cpu); }
            }
        }
    }
}

fn install_trampoline() {
    extern "C" {
        static ap_trampoline_start: u8;
        static ap_trampoline_end:   u8;
    }
    unsafe {
        let src = &ap_trampoline_start as *const u8;
        let end = &ap_trampoline_end   as *const u8;
        let len = end as usize - src as usize;
        let dst = TRAMPOLINE_PHYS as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
    log::debug!("apic: trampoline installed at {:#x}", TRAMPOLINE_PHYS);
}

unsafe fn start_ap(hw_id: u32, cpu_id: u32) {
    let cpu_id_slot = (TRAMPOLINE_PHYS + 0xFF8) as *mut u32;
    write_volatile(cpu_id_slot, cpu_id);
    core::sync::atomic::fence(Ordering::Release);

    log::debug!("apic: starting AP hw_id={} cpu_id={}", hw_id, cpu_id);

    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_INIT | ICR_ASSERT | ICR_LEVEL);
    icr_wait();
    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_INIT | ICR_DEASSERT | ICR_LEVEL);
    icr_wait();

    busy_wait_ms(10);

    let vector = (TRAMPOLINE_PHYS >> 12) as u32;
    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_SIPI | ICR_ASSERT | vector);
    icr_wait();
    busy_wait_us(200);

    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_SIPI | ICR_ASSERT | vector);
    icr_wait();
    busy_wait_us(200);
}

#[inline]
pub fn send_ipi(hw_id: u32, vector: u8) {
    unsafe {
        icr_wait();
        lapic_write(LAPIC_ICR_HI, hw_id << 24);
        lapic_write(LAPIC_ICR_LO, ICR_FIXED | ICR_ASSERT | vector as u32);
    }
}

#[inline]
pub fn eoi() {
    unsafe { lapic_write(LAPIC_EOI, 0); }
}

// ───── Timer calibration ─────────────────────────────────────────────────────

/// Calibrate the TSC frequency.
///
/// Method A: CPUID leaf 0x15 — TSC/core crystal ratio (Skylake+, Goldmont+).
///   tsc_hz = crystal_hz * ebx / eax.
///   Known crystal frequencies by Family/Model when ECX=0:
///     Skylake/Kaby Lake client  : 24 MHz
///     Atom Goldmont / Apollo    : 19.2 MHz
///     Xeon Scalable (Purley+)   : 25 MHz
///
/// Method B: PIT channel 0 gate (fallback for older CPUs).
///   We count TSC ticks during a 50 ms PIT interval.
unsafe fn calibrate_tsc() {
    // Try CPUID leaf 0x15.
    let max_leaf: u32;
    core::arch::asm!("cpuid", in("eax") 0u32, out("eax") max_leaf,
        out("ebx") _, out("ecx") _, out("edx") _, options(nostack));

    if max_leaf >= 0x15 {
        let (eax, ebx, ecx): (u32, u32, u32);
        core::arch::asm!(
            "cpuid",
            in("eax") 0x15u32,
            out("eax") eax, out("ebx") ebx, out("ecx") ecx, out("edx") _,
            options(nostack)
        );
        if eax != 0 && ebx != 0 {
            // crystal_hz: use ECX when provided, else guess 24 MHz.
            let crystal_hz: u64 = if ecx != 0 { ecx as u64 } else { 24_000_000 };
            let tsc_hz = crystal_hz * ebx as u64 / eax as u64;
            let ticks_per_us = tsc_hz / 1_000_000;
            if ticks_per_us > 0 {
                TSC_TICKS_PER_US.store(ticks_per_us, Ordering::Relaxed);
                log::info!("apic: TSC {tsc_hz} Hz via CPUID.0x15 ({ticks_per_us} ticks/µs)");
                return;
            }
        }
    }

    // Fallback: PIT channel 0, 50 ms window.
    // PIT runs at 1.193182 MHz. Divisor for 50 ms = 59659.
    const PIT_DIVISOR: u16 = 59659; // ≈ 50 ms
    const PIT_CMD:  u16 = 0x43;
    const PIT_CH0:  u16 = 0x40;

    // Set mode 2 (rate generator), channel 0, lo/hi byte.
    pit_write(PIT_CMD, 0x34); // ch0, lo/hi, mode 2, binary
    pit_write(PIT_CH0, (PIT_DIVISOR & 0xFF) as u8);
    pit_write(PIT_CH0, (PIT_DIVISOR >> 8) as u8);

    let tsc_start = rdtsc();
    // Wait until PIT counter wraps (goes from 0 back to DIVISOR).
    // We poll the PIT status via latch command.
    let mut prev_count = pit_read_count();
    loop {
        let cur_count = pit_read_count();
        // Counter wrapped (cur > prev means it reloaded).
        if cur_count > prev_count { break; }
        prev_count = cur_count;
    }
    let tsc_end = rdtsc();

    let elapsed_tsc = tsc_end.wrapping_sub(tsc_start);
    // elapsed_tsc covers ~50 ms → ticks_per_us = elapsed / 50_000.
    let ticks_per_us = elapsed_tsc / 50_000;
    let ticks_per_us = if ticks_per_us == 0 { 1 } else { ticks_per_us };
    TSC_TICKS_PER_US.store(ticks_per_us, Ordering::Relaxed);
    log::info!("apic: TSC ~{} ticks/µs via PIT fallback", ticks_per_us);
}

/// Calibrate the APIC timer frequency against the now-known TSC frequency.
///
/// Set APIC timer to one-shot with a large ICR, wait exactly 10 ms via TSC,
/// read the CCR to find how many ticks elapsed.  APIC_TICKS_PER_MS = delta / 10.
unsafe fn calibrate_apic_timer() {
    // DCR = divide-by-2.
    lapic_write(LAPIC_TIMER_DCR, 0x0);
    // Masked one-shot; vector 0 (masked so it never fires).
    lapic_write(LAPIC_TIMER_LVT, 0x10000);
    // Load a large initial count so it won't expire during 10 ms.
    const SENTINEL: u32 = 0xFFFF_FFFF;
    lapic_write(LAPIC_TIMER_ICR, SENTINEL);

    busy_wait_us(10_000); // 10 ms

    let ccr = lapic_read(LAPIC_TIMER_CCR);
    let ticks_elapsed = SENTINEL - ccr;
    let ticks_per_ms = ticks_elapsed as u64 / 10;
    let ticks_per_ms = if ticks_per_ms == 0 { 1 } else { ticks_per_ms };
    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::Relaxed);
    log::info!("apic: timer {} ticks/ms (DCR=÷2)", ticks_per_ms);

    // Stop the timer.
    lapic_write(LAPIC_TIMER_ICR, 0);
}

// ───── Timing helpers (TSC-based after calibration) ──────────────────────────

#[inline]
unsafe fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "lfence",   // serialise before reading TSC
        "rdtsc",
        out("eax") lo,
        out("edx") hi,
        options(nostack, preserves_flags)
    );
    ((hi as u64) << 32) | lo as u64
}

/// Spin for approximately `us` microseconds using the calibrated TSC.
/// Falls back to a rough I/O-port loop if TSC calibration has not run yet
/// (i.e. during early boot before `calibrate_tsc()`).
pub fn busy_wait_us(us: u64) {
    let ticks_per_us = TSC_TICKS_PER_US.load(Ordering::Relaxed);
    if ticks_per_us == 0 {
        // Pre-calibration fallback: crude `pause` loop.
        for _ in 0..(us * 100) {
            unsafe { core::arch::asm!("pause", options(nostack, preserves_flags)); }
        }
        return;
    }
    let target = unsafe { rdtsc() } + ticks_per_us * us;
    while unsafe { rdtsc() } < target {
        core::hint::spin_loop();
    }
}

pub fn busy_wait_ms(ms: u64) {
    busy_wait_us(ms * 1000);
}

// ───── PIT helpers (used only during calibration) ────────────────────────────

#[inline]
unsafe fn pit_write(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nostack, preserves_flags)
    );
}

/// Latch and read the current 16-bit count from PIT channel 0.
#[inline]
unsafe fn pit_read_count() -> u16 {
    // Latch command: channel 0, latch count.
    pit_write(0x43, 0x00);
    let lo: u8;
    let hi: u8;
    core::arch::asm!("in al, dx", in("dx") 0x40u16, out("al") lo, options(nostack));
    core::arch::asm!("in al, dx", in("dx") 0x40u16, out("al") hi, options(nostack));
    (lo as u16) | ((hi as u16) << 8)
}
