//! AArch64/ARM64 architecture support.
//!
//! Baseline hardware requirement follows the ReactOS ARM64 bring-up target:
//! UEFI firmware on an Armv8-A (or newer) processor with either a GICv2 or
//! GICv3 interrupt controller.

pub mod boot;
pub mod cpu;
pub mod hal;
pub mod interrupts;
pub mod kernel_main;
pub mod mem_layout;
pub mod paging;
pub mod pci;
pub mod serial;
pub mod simd;
pub mod smp;
pub mod syscall;
pub mod uefi_entry;
pub mod uentry;

/// ARM64 early/kernel boot hook used by the common entry point.
pub fn init(boot_info: &'static crate::init::boot_info::BootInfo) -> ! {
    kernel_main::init(boot_info)
}
