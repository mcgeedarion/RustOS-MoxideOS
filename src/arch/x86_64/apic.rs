//! x86-64 APIC (Local APIC + I/O APIC) driver.
//!
//! Local APIC base is read from IA32_APIC_BASE MSR and mapped at a fixed
//! virtual address.  The I/O APIC is discovered from ACPI MADT.
extern crate alloc;
use alloc::vec::Vec;

pub const LAPIC_ID:      u32 = 0x020;
pub const LAPIC_EOI:     u32 = 0x0B0;
pub const LAPIC_SIVR:    u32 = 0x0F0;
pub const LAPIC_TIMER:   u32 = 0x320;
pub const LAPIC_TDCR:    u32 = 0x3E0;
pub const LAPIC_TICR:    u32 = 0x380;
pub const LAPIC_TCCR:    u32 = 0x390;

static mut LAPIC_BASE: usize = 0;

pub unsafe fn lapic_read(reg: u32) -> u32 {
    let ptr = (LAPIC_BASE + reg as usize) as *const u32;
    ptr.read_volatile()
}

pub unsafe fn lapic_write(reg: u32, val: u32) {
    let ptr = (LAPIC_BASE + reg as usize) as *mut u32;
    ptr.write_volatile(val);
}

pub unsafe fn init(base: usize) {
    LAPIC_BASE = base;
    // Enable LAPIC (SIVR bit 8)
    lapic_write(LAPIC_SIVR, lapic_read(LAPIC_SIVR) | 0x100);
    // EOI any pending
    lapic_write(LAPIC_EOI, 0);
}

pub unsafe fn eoi() { lapic_write(LAPIC_EOI, 0); }

pub unsafe fn start_timer(hz: u32) {
    lapic_write(LAPIC_TDCR, 0x3);          // divide by 16
    lapic_write(LAPIC_TIMER, 0x2_0000 | 0x20); // periodic, vector 0x20
    lapic_write(LAPIC_TICR, 1_000_000_000 / (hz as u32 * 16));
}
