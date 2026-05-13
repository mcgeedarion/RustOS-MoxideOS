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
//! Method A — CPUID leaf 0x15 (preferred, Skylake+)
//!   Gives TSC frequency: core_crystal_hz = ecx, tsc_hz = crystal * ebx / eax.
//!
//! Method B — PIT channel 0 gate (fallback, works on all x86 hardware)
//!   Gate PIT ch0 for ~50 ms, count APIC timer decrements.
//!
//! ## LAPIC MMIO base
//!
//! The architectural default is [`mem_layout::apic::LAPIC_PHYS_DEFAULT`] but
//! firmware may relocate it.  We always read IA32_APIC_BASE (MSR 0x1B) in
//! init() and use the actual physical address.
//!
//! ## AP trampoline shared-memory layout
//!
//! Offsets within the trampoline page are defined in
//! [`mem_layout::trampoline`] and must match the assembly in ap_boot.s.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::ptr::{read_volatile, write_volatile};
use super::mem_layout::{apic as A, pit as PIT, trampoline as T};

// Re-export the two constants external callers use.
pub use A::LAPIC_PHYS_DEFAULT;
pub use A::SPURIOUS_VECTOR;
pub use A::TRAMPOLINE_PHYS;

/// Actual LAPIC physical base, read from IA32_APIC_BASE (MSR 0x1B) during init.
static LAPIC_PHYS_BASE_ACTUAL: AtomicU64 = AtomicU64::new(A::LAPIC_PHYS_DEFAULT);

static X2APIC:           AtomicBool = AtomicBool::new(false);
static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);
static TSC_TICKS_PER_US:  AtomicU64 = AtomicU64::new(0);

/// Under the UEFI identity map, phys == virt.
#[inline]
fn lapic_virt_base() -> usize {
    LAPIC_PHYS_BASE_ACTUAL.load(Ordering::Relaxed) as usize
}

// ── Register accessors ─────────────────────────────────────────────────────────

#[inline]
unsafe fn lapic_read(offset: usize) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        let msr = A::X2APIC_MSR_BASE + (offset >> 4) as u32;
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
        let msr = A::X2APIC_MSR_BASE + (offset >> 4) as u32;
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
    while lapic_read(A::REG_ICR_LO) & A::ICR_DELIVERY_PENDING != 0 {
        core::hint::spin_loop();
    }
}

// ── BSP init ───────────────────────────────────────────────────────────────────

pub unsafe fn init() {
    // Step 0: read actual LAPIC base from IA32_APIC_BASE.
    let apic_base_lo: u32;
    let apic_base_hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") A::MSR_IA32_APIC_BASE,
        out("eax") apic_base_lo,
        out("edx") apic_base_hi,
        options(nostack, preserves_flags)
    );
    let raw: u64 = ((apic_base_hi as u64) << 32) | (apic_base_lo as u64);
    let phys: u64 = raw & A::MSR_APIC_BASE_MASK;
    if phys != 0 {
        LAPIC_PHYS_BASE_ACTUAL.store(phys, Ordering::Relaxed);
        if phys != A::LAPIC_PHYS_DEFAULT {
            log::warn!("apic: LAPIC relocated to {phys:#x} (default {:#x})",
                       A::LAPIC_PHYS_DEFAULT);
        }
    }
    log::info!("apic: LAPIC base = {:#x}",
               LAPIC_PHYS_BASE_ACTUAL.load(Ordering::Relaxed));

    // Step 1: check for x2APIC support (CPUID.1:ECX bit 21).
    let ecx: u32;
    core::arch::asm!(
        "mov eax, 1", "cpuid",
        out("ecx") ecx, out("eax") _, out("ebx") _, out("edx") _,
        options(nostack)
    );
    if ecx & (1 << 21) != 0 {
        let new_lo = apic_base_lo | A::MSR_X2APIC_ENABLE | A::MSR_APIC_GLOBAL_EN;
        core::arch::asm!(
            "wrmsr",
            in("ecx") A::MSR_IA32_APIC_BASE,
            in("eax") new_lo,
            in("edx") apic_base_hi,
            options(nostack)
        );
        X2APIC.store(true, Ordering::Relaxed);
        log::info!("apic: x2APIC mode enabled");
    }

    // Step 2: enable LAPIC, mask all LVT entries.
    lapic_write(A::REG_SPURIOUS,
                A::SPURIOUS_ENABLE | A::SPURIOUS_VECTOR as u32);
    lapic_write(A::REG_TIMER_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_THERMAL_LVT, A::LVT_MASKED);
    lapic_write(A::REG_PERF_LVT,    A::LVT_MASKED);
    lapic_write(A::REG_LINT0_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_LINT1_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_ERROR_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_TPR, 0);

    log::info!("apic: BSP LAPIC id={}", lapic_read(A::REG_ID));

    // Step 3: calibrate timers.
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
        lapic_write(A::REG_TIMER_DCR, 0x0);
        lapic_write(A::REG_TIMER_LVT, vector as u32);
        lapic_write(A::REG_TIMER_ICR, initial_count);
    }
}

#[inline]
pub fn send_eoi() {
    unsafe { lapic_write(A::REG_EOI, 0); }
}

#[inline]
pub fn eoi() { send_eoi(); }

// ── AP init ────────────────────────────────────────────────────────────────────

pub unsafe fn ap_init_local() {
    lapic_write(A::REG_SPURIOUS,
                A::SPURIOUS_ENABLE | A::SPURIOUS_VECTOR as u32);
    lapic_write(A::REG_TIMER_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_THERMAL_LVT, A::LVT_MASKED);
    lapic_write(A::REG_PERF_LVT,    A::LVT_MASKED);
    lapic_write(A::REG_LINT0_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_LINT1_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_ERROR_LVT,   A::LVT_MASKED);
    lapic_write(A::REG_TPR, 0);
}

pub fn start_all_aps() {
    install_trampoline();
    let n = crate::smp::num_cpus();
    for cpu in 0..n {
        if let Some(info) = crate::smp::cpu_info(cpu) {
            if !info.is_bsp {
                let kstack = crate::mm::kstack::alloc_kstack();
                crate::arch::x86_64::gdt::write_trampoline_kstack(kstack);
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
        let dst = A::TRAMPOLINE_PHYS as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
    log::debug!("apic: trampoline installed at {:#x}", A::TRAMPOLINE_PHYS);
}

unsafe fn start_ap(hw_id: u32, cpu_id: u32) {
    // Write the logical cpu_id into the shared-memory slot.
    let cpu_id_slot = (A::TRAMPOLINE_PHYS as usize + T::CPU_ID_OFFSET) as *mut u32;
    write_volatile(cpu_id_slot, cpu_id);
    core::sync::atomic::fence(Ordering::Release);
    log::debug!("apic: starting AP hw_id={} cpu_id={}", hw_id, cpu_id);

    lapic_write(A::REG_ICR_HI, hw_id << 24);
    lapic_write(A::REG_ICR_LO,
        A::ICR_DELIVERY_INIT | A::ICR_LEVEL_ASSERT | A::ICR_TRIGGER_LEVEL);
    icr_wait();
    lapic_write(A::REG_ICR_HI, hw_id << 24);
    lapic_write(A::REG_ICR_LO,
        A::ICR_DELIVERY_INIT | A::ICR_LEVEL_DEASSERT | A::ICR_TRIGGER_LEVEL);
    icr_wait();

    busy_wait_ms(10);

    let vector = (A::TRAMPOLINE_PHYS >> 12) as u32;
    lapic_write(A::REG_ICR_HI, hw_id << 24);
    lapic_write(A::REG_ICR_LO,
        A::ICR_DELIVERY_SIPI | A::ICR_LEVEL_ASSERT | vector);
    icr_wait();
    busy_wait_us(200);

    lapic_write(A::REG_ICR_HI, hw_id << 24);
    lapic_write(A::REG_ICR_LO,
        A::ICR_DELIVERY_SIPI | A::ICR_LEVEL_ASSERT | vector);
    icr_wait();
    busy_wait_us(200);
}

#[inline]
pub fn send_ipi(hw_id: u32, vector: u8) {
    unsafe {
        icr_wait();
        lapic_write(A::REG_ICR_HI, hw_id << 24);
        lapic_write(A::REG_ICR_LO,
            A::ICR_DELIVERY_FIXED | A::ICR_LEVEL_ASSERT | vector as u32);
    }
}

// ── Timer calibration ──────────────────────────────────────────────────────────

unsafe fn calibrate_tsc() {
    let max_leaf: u32;
    core::arch::asm!(
        "cpuid",
        in("eax") 0u32,
        out("eax") max_leaf,
        out("ebx") _, out("ecx") _, out("edx") _,
        options(nostack)
    );

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

    // Fallback: calibrate via PIT channel 0.
    pit_write(PIT::CMD, PIT::CMD_CH0_RATE_GEN);
    pit_write(PIT::CH0, (PIT::CALIB_DIVISOR & 0xFF) as u8);
    pit_write(PIT::CH0, (PIT::CALIB_DIVISOR >> 8) as u8);

    let tsc_start = rdtsc();
    let mut prev = pit_read_count();
    loop {
        let cur = pit_read_count();
        if cur > prev { break; }
        prev = cur;
    }
    let tsc_end = rdtsc();

    let elapsed = tsc_end.wrapping_sub(tsc_start);
    let ticks_per_us = (elapsed / 50_000).max(1);
    TSC_TICKS_PER_US.store(ticks_per_us, Ordering::Relaxed);
    log::info!("apic: TSC ~{} ticks/µs via PIT fallback", ticks_per_us);
}

unsafe fn calibrate_apic_timer() {
    const SENTINEL: u32 = 0xFFFF_FFFF;
    lapic_write(A::REG_TIMER_DCR, 0x0);
    lapic_write(A::REG_TIMER_LVT, A::LVT_MASKED);
    lapic_write(A::REG_TIMER_ICR, SENTINEL);

    busy_wait_us(10_000);

    let ccr = lapic_read(A::REG_TIMER_CCR);
    let ticks_per_ms = ((SENTINEL - ccr) as u64 / 10).max(1);
    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::Relaxed);
    log::info!("apic: timer {} ticks/ms (DCR=÷2)", ticks_per_ms);

    lapic_write(A::REG_TIMER_ICR, 0);
}

// ── Timing helpers ─────────────────────────────────────────────────────────────

#[inline]
unsafe fn rdtsc() -> u64 {
    let lo: u32; let hi: u32;
    core::arch::asm!(
        "lfence", "rdtsc",
        out("eax") lo, out("edx") hi,
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
    while unsafe { rdtsc() } < target { core::hint::spin_loop(); }
}

pub fn busy_wait_ms(ms: u64) { busy_wait_us(ms * 1000); }

// ── PIT helpers (calibration only) ────────────────────────────────────────────

#[inline]
unsafe fn pit_write(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port, in("al") val,
        options(nostack, preserves_flags)
    );
}

#[inline]
unsafe fn pit_read_count() -> u16 {
    pit_write(PIT::CMD, PIT::CMD_CH0_LATCH);
    let lo: u8; let hi: u8;
    core::arch::asm!("in al, dx", in("dx") PIT::CH0, out("al") lo, options(nostack));
    core::arch::asm!("in al, dx", in("dx") PIT::CH0, out("al") hi, options(nostack));
    (lo as u16) | ((hi as u16) << 8)
}
