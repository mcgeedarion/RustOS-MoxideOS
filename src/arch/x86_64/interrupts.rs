//! IRQ handler stubs.
//! Real IRQ handling (APIC timer, keyboard, NVMe) is added per-driver.
//! The IDT is set up in idt.rs; this file holds the Rust-side dispatch.

/// Called from the APIC timer IRQ to drive the scheduler.
/// Wired by apic.rs once the APIC is initialised.
#[no_mangle]
pub extern "C" fn timer_irq_handler() {
    crate::proc::scheduler::schedule();
}
