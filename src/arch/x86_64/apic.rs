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
//!
//!   Method B — PIT channel 0 gate (fallback, works on all x86 hardware)
//!     Gate PIT ch0 for exactly 50 ms, count APIC timer decrements.
//!
//! After calibration `APIC_TICKS_PER_MS` and `TSC_TICKS_PER_US` are set.
//! `busy_wait_us` uses the TSC, `apic_timer_start_ms` uses APIC ticks.
//!
//! ## LAPIC MMIO base
//!
//! The architectural default is 0xFEE0_0000 but firmware may relocate it
//! via IA32_APIC_BASE (MSR 0x1B), bits 51:12.  We always read the MSR in
//! init() and use the actual physical address for MMIO access.  Under UEFI
//! the memory map is identity-mapped so phys == virt before we switch page
//! tables.  After the kernel installs its own page tables, apic.rs must be
//! revisited to remap LAPIC_PHYS_BASE_ACTUAL into the kernel VA space.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::ptr::{read_volatile, write_volatile};

// ───── Fallback / default LAPIC base constants ────────────────────────────────
/// Architectural default physical base (used as fallback if MSR read fails).
pub const LAPIC_PHYS_DEFAULT: u64 = 0xFEE0_0000;

/// Actual LAPIC physical base, read from IA32_APIC_BASE (MSR 0x1B) during init.
/// Set once by init(); read-only thereafter.
static LAPIC_PHYS_BASE_ACTUAL: AtomicU64 = AtomicU64::new(0xFEE0_0000);

/// Under the UEFI identity map, phys == virt.  After the kernel installs its
/// own page tables this will need updating (TODO: remap in paging.rs).
#[inline]
fn lapic_virt_base() -> usize {
    LAPIC_PHYS_BASE_ACTUAL.load(Ordering::Relaxed) as usize
}

// ───── Local APIC register offsets (bytes) ──────────────────────────────────
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

// ───── ICR delivery mode bits ────────────────────────────────────────────────
const ICR_FIXED:             u32 = 0 << 8;
const ICR_INIT:              u32 = 5 << 8;
const ICR_SIPI:              u32 = 6 << 8;
const ICR_ASSERT:            u32 = 1 << 14;
const ICR_DEASSERT:          u32 = 0 << 14;
const ICR_LEVEL:             u32 = 1 << 15;
const ICR_DELIVERY_PENDING:  u32 = 1 << 12;

pub const SPURIOUS_VECTOR: u8 = 0xFF;
pub const TRAMPOLINE_PHYS: u64 = 0x8000;

static X2APIC: AtomicBool = AtomicBool::new(false);
static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);
static TSC_TICKS_PER_US:  AtomicU64 = AtomicU64::new(0);

// ───── Register accessors ───────────────────────────────────────────────────────

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
        let va = (lapic_virt_base() + offset) as *const u32;
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
        let va = (lapic_virt_base() + offset) as *mut u32;
        write_volatile(va, val);
    }
}

#[inline]
unsafe fn icr_wait() {
    while lapic_read(LAPIC_ICR_LO) & ICR_DELIVERY_PENDING != 0 {
        core::hint::spin_loop();
    }
}

// ───── BSP init ─────────────────────────────────────────────────────────────────

/// Initialise the BSP’s local APIC and calibrate the timer.
/// Called once from `apic_init()` in kernel_main.
pub unsafe fn init() {
    // ── Step 0: read actual LAPIC base from IA32_APIC_BASE (MSR 0x1B) ───────
    //
    // Bits 51:12 = physical base address (4 KiB aligned).
    // Bit  11    = APIC global enable.
    // Bit  10    = x2APIC enable (written back below if supported).
    // Bit   8    = BSP flag (read-only).
    let apic_base_lo: u32;
    let apic_base_hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") 0x1Bu32,
        out("eax") apic_base_lo,
        out("edx") apic_base_hi,
        options(nostack, preserves_flags)
    );
    // Reconstruct 64-bit physical address, mask off flag bits 11:0.
    let apic_base_raw: u64 = ((apic_base_hi as u64) << 32) | (apic_base_lo as u64);
    let apic_phys: u64 = apic_base_raw & !0xFFF;

    if apic_phys != 0 {
        LAPIC_PHYS_BASE_ACTUAL.store(apic_phys, Ordering::Relaxed);
        if apic_phys != LAPIC_PHYS_DEFAULT {
            log::warn!("apic: LAPIC relocated to {apic_phys:#x} (default is {LAPIC_PHYS_DEFAULT:#x})");
        }
    }
    log::info!("apic: LAPIC base = {:#x}", LAPIC_PHYS_BASE_ACTUAL.load(Ordering::Relaxed));

    // ── Step 1: check for x2APIC (CPUID leaf 1, ECX bit 21) ─────────────
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
        // Enable x2APIC in IA32_APIC_BASE: set bit 10 alongside bit 11 (global enable).
        let new_lo = apic_base_lo | (1 << 10) | (1 << 11);
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x1Bu32,
            in("eax") new_lo,
            in("edx") apic_base_hi,
            options(nostack)
        );
        X2APIC.store(true, Ordering::Relaxed);
        log::info!("apic: x2APIC mode enabled");
    }

    // ── Step 2: enable LAPIC, mask all LVT entries ────────────────────────
    lapic_write(LAPIC_SPURIOUS, 0x100 | SPURIOUS_VECTOR as u32);
    lapic_write(LAPIC_TIMER_LVT,   0x10000);
    lapic_write(LAPIC_THERMAL_LVT, 0x10000);
    lapic_write(LAPIC_PERF_LVT,    0x10000);
    lapic_write(LAPIC_LINT0_LVT,   0x10000);
    lapic_write(LAPIC_LINT1_LVT,   0x10000);
    lapic_write(LAPIC_ERROR_LVT,   0x10000);
    lapic_write(LAPIC_TPR, 0);

    log::info!("apic: BSP LAPIC id={}", lapic_read(LAPIC_ID));

    // ── Step 3: calibrate TSC and APIC timer ─────────────────────────────
    calibrate_tsc();
    calibrate_apic_timer();
}

#[inline]
pub fn apic_ticks_per_ms() -> u64 {
    APIC_TICKS_PER_MS.load(Ordering::Relaxed)
}

pub fn apic_timer_start_ms(ms: u64, vector: u8) {
    let initial_count = (apic_ticks_per_ms() * ms) as u32;
    unsafe {
        lapic_write(LAPIC_TIMER_DCR, 0x0);
        lapic_write(LAPIC_TIMER_LVT, vector as u32);
        lapic_write(LAPIC_TIMER_ICR, initial_count);
    }
}

// ───── AP init ────────────────────────────────────────────────────────────────

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

// ───── Timer calibration ───────────────────────────────────────────────────────

unsafe fn calibrate_tsc() {
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
    const PIT_DIVISOR: u16 = 59659;
    const PIT_CMD: u16 = 0x43;
    const PIT_CH0: u16 = 0x40;
    pit_write(PIT_CMD, 0x34);
    pit_write(PIT_CH0, (PIT_DIVISOR & 0xFF) as u8);
    pit_write(PIT_CH0, (PIT_DIVISOR >> 8) as u8);

    let tsc_start = rdtsc();
    let mut prev_count = pit_read_count();
    loop {
        let cur_count = pit_read_count();
        if cur_count > prev_count { break; }
        prev_count = cur_count;
    }
    let tsc_end = rdtsc();

    let elapsed_tsc = tsc_end.wrapping_sub(tsc_start);
    let ticks_per_us = (elapsed_tsc / 50_000).max(1);
    TSC_TICKS_PER_US.store(ticks_per_us, Ordering::Relaxed);
    log::info!("apic: TSC ~{} ticks/µs via PIT fallback", ticks_per_us);
}

unsafe fn calibrate_apic_timer() {
    lapic_write(LAPIC_TIMER_DCR, 0x0);
    lapic_write(LAPIC_TIMER_LVT, 0x10000);
    const SENTINEL: u32 = 0xFFFF_FFFF;
    lapic_write(LAPIC_TIMER_ICR, SENTINEL);

    busy_wait_us(10_000);

    let ccr = lapic_read(LAPIC_TIMER_CCR);
    let ticks_per_ms = ((SENTINEL - ccr) as u64 / 10).max(1);
    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::Relaxed);
    log::info!("apic: timer {} ticks/ms (DCR=÷2)", ticks_per_ms);

    lapic_write(LAPIC_TIMER_ICR, 0);
}

// ───── Timing helpers ──────────────────────────────────────────────────────────

#[inline]
unsafe fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "lfence",
        "rdtsc",
        out("eax") lo,
        out("edx") hi,
        options(nostack, preserves_flags)
    );
    ((hi as u64) << 32) | lo as u64
}

pub fn busy_wait_us(us: u64) {
    let ticks_per_us = TSC_TICKS_PER_US.load(Ordering::Relaxed);
    if ticks_per_us == 0 {
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

// ───── PIT helpers (calibration only) ───────────────────────────────────────

#[inline]
unsafe fn pit_write(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nostack, preserves_flags)
    );
}

#[inline]
unsafe fn pit_read_count() -> u16 {
    pit_write(0x43, 0x00);
    let lo: u8;
    let hi: u8;
    core::arch::asm!("in al, dx", in("dx") 0x40u16, out("al") lo, options(nostack));
    core::arch::asm!("in al, dx", in("dx") 0x40u16, out("al") hi, options(nostack));
    (lo as u16) | ((hi as u16) << 8)
}
