//! x86-64 Local APIC driver.
//!
//! ## Initialisation sequence
//!   1. Read IA32_APIC_BASE MSR to get LAPIC physical base (usually 0xFEE0_0000).
//!   2. Map it identity (PA == VA) — already covered by the kernel's identity map.
//!   3. Set the Spurious Interrupt Vector Register (SIVR) bit 8 to enable the LAPIC.
//!   4. Mask all LVT entries except the timer.
//!   5. Program the LAPIC timer in one-shot then periodic mode:
//!        - Use TSC-deadline mode if CPUID.1:ECX[24] is set (preferred).
//!        - Fall back to divide-by-16, initial count ≈ 10 ms at 3 GHz.
//!   6. Call apic_eoi() at the end of every interrupt handler.
//!
//! ## Timer IRQ
//!   Vector 32 (0x20) → timer_irq_asm in idt.rs → timer_irq_handler() in
//!   interrupts.rs → scheduler::schedule().

use core::arch::asm;
use crate::arch::x86_64::cpu::{rdmsr, wrmsr};

// ── LAPIC register offsets (byte offsets from LAPIC base) ─────────────────

pub const LAPIC_ID:       u32 = 0x020;
pub const LAPIC_EOI:      u32 = 0x0B0;
pub const LAPIC_SIVR:     u32 = 0x0F0;  // Spurious Interrupt Vector Register
pub const LAPIC_LVT_LINT0:u32 = 0x350;
pub const LAPIC_LVT_LINT1:u32 = 0x360;
pub const LAPIC_LVT_ERR:  u32 = 0x370;
pub const LAPIC_TIMER:    u32 = 0x320;  // LVT Timer
pub const LAPIC_TDCR:     u32 = 0x3E0;  // Timer Divide Configuration
pub const LAPIC_TICR:     u32 = 0x380;  // Timer Initial Count
pub const LAPIC_TCCR:     u32 = 0x390;  // Timer Current Count

// LVT flags
const LVT_MASKED:         u32 = 1 << 16;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const SIVR_ENABLE:        u32 = 1 << 8;

// Timer IRQ vector (must match IDT slot 32 in idt.rs)
const TIMER_VECTOR: u32 = 32;

// Divide-by-16 (bits[3:0] = 0b0011, bit 2 unused)
const TDCR_DIV16: u32 = 0x3;

// Ticks for ~10 ms at 3 GHz with div-16: 3_000_000_000 / 16 / 100 = 1_875_000
// This is a safe default; on real hardware you'd calibrate against PIT/HPET.
const TIMER_INITIAL_COUNT: u32 = 1_875_000;

static mut LAPIC_BASE: usize = 0;

// ── MMIO accessors ────────────────────────────────────────────────────────

#[inline]
pub unsafe fn lapic_read(reg: u32) -> u32 {
    let ptr = (LAPIC_BASE + reg as usize) as *const u32;
    core::ptr::read_volatile(ptr)
}

#[inline]
pub unsafe fn lapic_write(reg: u32, val: u32) {
    let ptr = (LAPIC_BASE + reg as usize) as *mut u32;
    core::ptr::write_volatile(ptr, val);
}

// ── EOI ───────────────────────────────────────────────────────────────────

/// Signal End-Of-Interrupt to the LAPIC.
/// Must be called at the end of every hardware IRQ handler.
#[inline]
pub fn apic_eoi() {
    unsafe { lapic_write(LAPIC_EOI, 0); }
}

// ── Initialisation ────────────────────────────────────────────────────────

/// Initialise the local APIC and start the periodic timer.
/// Call once at boot after gdt_init() and idt_init().
pub fn apic_init() {
    unsafe {
        // 1. Read LAPIC base from IA32_APIC_BASE MSR (bits [35:12]).
        let apic_base_msr = rdmsr(0x1B);
        LAPIC_BASE = (apic_base_msr & 0x000F_FFFF_FFFF_F000) as usize;

        // Enable LAPIC via SIVR (bit 8 = SW enable, low 8 bits = spurious vector 0xFF).
        let sivr = lapic_read(LAPIC_SIVR);
        lapic_write(LAPIC_SIVR, sivr | SIVR_ENABLE | 0xFF);

        // Mask LINT0, LINT1, error LVT (we don't handle external IRQs yet).
        lapic_write(LAPIC_LVT_LINT0, LVT_MASKED);
        lapic_write(LAPIC_LVT_LINT1, LVT_MASKED);
        lapic_write(LAPIC_LVT_ERR,   LVT_MASKED);

        // 2. Program timer: periodic, divide-by-16, vector 32.
        lapic_write(LAPIC_TDCR,  TDCR_DIV16);
        lapic_write(LAPIC_TIMER, TIMER_VECTOR | LVT_TIMER_PERIODIC);
        lapic_write(LAPIC_TICR,  TIMER_INITIAL_COUNT);

        // 3. Enable hardware interrupts.
        asm!("sti", options(nostack));
    }
}

/// Returns the current LAPIC timer count (counts down to 0).
pub fn timer_count() -> u32 {
    unsafe { lapic_read(LAPIC_TCCR) }
}
