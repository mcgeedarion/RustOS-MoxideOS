//! AArch64/ARM64 architecture support.
//!
//! Baseline hardware requirement follows the ReactOS ARM64 bring-up target:
//! UEFI firmware on an Armv8-A (or newer) processor with either a GICv2 or GICv3
//! interrupt controller.

pub mod boot;
pub mod hal;
pub mod mem_layout;
pub mod paging;
pub mod uefi_entry;

/// ARM64 early/kernel boot hook used by the common entry point.
pub fn init(_boot_info: &'static crate::init::boot_info::BootInfo) -> ! {
    crate::serial_println!(
        "RustOS ARM64 boot: {}",
        crate::arch::aarch64::mem_layout::BASELINE
    );
    crate::irq::aarch64::gic::init(crate::irq::aarch64::gic::GicConfig::qemu_virt_v3());
    loop {
        crate::arch::aarch64::hal::wait_for_interrupt();
    }
}
