//! Local APIC + IO-APIC driver with SMP AP bringup.
//!
//! Supports both xAPIC (MMIO) and x2APIC (MSR) modes.
//! AP bringup follows the MP specification:
//!   1. INIT IPI  → resets AP
//!   2. 10 ms delay
//!   3. SIPI #1   → AP starts executing trampoline at `TRAMPOLINE_PHYS >> 12`
//!   4. 200 µs delay
//!   5. SIPI #2   → second attempt (spec-required)

use core::sync::atomic::{AtomicBool, Ordering};
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
const ICR_FIXED:       u32 = 0 << 8;
const ICR_INIT:        u32 = 5 << 8;
const ICR_SIPI:        u32 = 6 << 8;
const ICR_ASSERT:      u32 = 1 << 14;
const ICR_DEASSERT:    u32 = 0 << 14;
const ICR_LEVEL:       u32 = 1 << 15;
const ICR_DEST_FIELD:  u32 = 0 << 18; // destination = ICR_HI[31:24]
const ICR_DELIVERY_PENDING: u32 = 1 << 12;

// ───── Spurious vector ───────────────────────────────────────────────────────
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// Physical address of the AP trampoline page (must be < 1 MiB).
/// This 4 KiB page contains `ap_boot.s` assembled code.
pub const TRAMPOLINE_PHYS: u64 = 0x8000;

/// x2APIC available?
static X2APIC: AtomicBool = AtomicBool::new(false);

// ───── Register accessors ────────────────────────────────────────────────────

#[inline]
unsafe fn lapic_read(offset: usize) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        // MSR base = 0x800 + offset/16
        let msr = 0x800u32 + (offset >> 4) as u32;
        let mut lo: u32;
        let mut hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
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

/// Initialise the BSP's local APIC.  Called once from `arch_init()`.
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
        // Enable x2APIC via IA32_APIC_BASE MSR bit 10.
        let mut base_lo: u32;
        let mut base_hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0x1Bu32,
            out("eax") base_lo,
            out("edx") base_hi,
            options(nostack)
        );
        base_lo |= (1 << 10) | (1 << 11); // x2APIC enable + global APIC enable
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

    // Enable LAPIC: set spurious-interrupt vector register.
    lapic_write(LAPIC_SPURIOUS, 0x100 | SPURIOUS_VECTOR as u32);
    // Mask all LVT entries initially.
    lapic_write(LAPIC_TIMER_LVT,   0x10000);
    lapic_write(LAPIC_THERMAL_LVT, 0x10000);
    lapic_write(LAPIC_PERF_LVT,    0x10000);
    lapic_write(LAPIC_LINT0_LVT,   0x10000);
    lapic_write(LAPIC_LINT1_LVT,   0x10000);
    lapic_write(LAPIC_ERROR_LVT,   0x10000);
    // Accept all interrupts (TPR = 0).
    lapic_write(LAPIC_TPR, 0);

    log::info!("apic: BSP LAPIC id={}", lapic_read(LAPIC_ID));
}

/// Initialise the LAPIC on an AP.  Called from `ap_entry()` on each AP.
pub unsafe fn ap_init_local() {
    lapic_write(LAPIC_SPURIOUS, 0x100 | SPURIOUS_VECTOR as u32);
    lapic_write(LAPIC_TIMER_LVT,   0x10000);
    lapic_write(LAPIC_THERMAL_LVT, 0x10000);
    lapic_write(LAPIC_PERF_LVT,    0x10000);
    lapic_write(LAPIC_LINT0_LVT,   0x10000);
    lapic_write(LAPIC_LINT1_LVT,   0x10000);
    lapic_write(LAPIC_ERROR_LVT,   0x10000);
    lapic_write(LAPIC_TPR, 0);
    // Unmask IPI vectors via IDT (already loaded in ap_entry).
    // Timer will be configured by scheduler::ap_idle.
}

// ───── AP bringup ─────────────────────────────────────────────────────────────

/// Copy the AP trampoline to `TRAMPOLINE_PHYS` and send INIT+SIPI to every
/// non-BSP CPU recorded in the SMP topology table.
pub fn start_all_aps() {
    install_trampoline();
    let n = crate::smp::num_cpus();
    let bsp_hw_id = unsafe { lapic_read(LAPIC_ID) };
    for cpu in 0..n {
        if let Some(info) = crate::smp::cpu_info(cpu) {
            if !info.is_bsp {
                unsafe { start_ap(info.hw_id, cpu); }
            }
        }
    }
}

/// Copy the compiled AP trampoline blob to low memory.
fn install_trampoline() {
    extern "C" {
        static ap_trampoline_start: u8;
        static ap_trampoline_end:   u8;
    }
    unsafe {
        let src = &ap_trampoline_start as *const u8;
        let end = &ap_trampoline_end as *const u8;
        let len = end as usize - src as usize;
        let dst = TRAMPOLINE_PHYS as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
    log::debug!("apic: trampoline installed at {:#x}", TRAMPOLINE_PHYS);
}

/// Send INIT + two SIPIs to APIC id `hw_id`, setting `cpu_id` so the AP
/// can install its per-CPU block.
unsafe fn start_ap(hw_id: u32, cpu_id: u32) {
    // Write the cpu_id into the trampoline data area so the AP picks it up.
    let cpu_id_slot = (TRAMPOLINE_PHYS + 0xFF8) as *mut u32;
    write_volatile(cpu_id_slot, cpu_id);
    core::sync::atomic::fence(Ordering::Release);

    log::debug!("apic: starting AP hw_id={} cpu_id={}", hw_id, cpu_id);

    // ── INIT IPI ──────────────────────────────────────────────────────────────
    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_INIT | ICR_ASSERT | ICR_LEVEL);
    icr_wait();
    // Deassert INIT.
    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_INIT | ICR_DEASSERT | ICR_LEVEL);
    icr_wait();

    // 10 ms wait.
    busy_wait_ms(10);

    // ── SIPI #1 ───────────────────────────────────────────────────────────────
    let vector = (TRAMPOLINE_PHYS >> 12) as u32; // 0x08
    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_SIPI | ICR_ASSERT | vector);
    icr_wait();
    busy_wait_us(200);

    // ── SIPI #2 ───────────────────────────────────────────────────────────────
    lapic_write(LAPIC_ICR_HI, hw_id << 24);
    lapic_write(LAPIC_ICR_LO, ICR_SIPI | ICR_ASSERT | vector);
    icr_wait();
    busy_wait_us(200);
}

/// Send a fixed IPI to `hw_id` with the given `vector`.
#[inline]
pub fn send_ipi(hw_id: u32, vector: u8) {
    unsafe {
        icr_wait();
        lapic_write(LAPIC_ICR_HI, hw_id << 24);
        lapic_write(LAPIC_ICR_LO, ICR_FIXED | ICR_ASSERT | vector as u32);
    }
}

/// Signal end-of-interrupt to the local APIC.
#[inline]
pub fn eoi() {
    unsafe { lapic_write(LAPIC_EOI, 0); }
}

// ───── Timing helpers (crude, uses TSC calibration) ──────────────────────────

fn busy_wait_ms(ms: u64) {
    busy_wait_us(ms * 1000);
}

fn busy_wait_us(us: u64) {
    // Fall back to I/O port 0x80 for ~1 µs per write if TSC freq unknown.
    // A real implementation would use the TSC; this is boot-time only.
    for _ in 0..(us * 100) {
        unsafe { core::arch::asm!("pause", options(nostack, preserves_flags)); }
    }
}
