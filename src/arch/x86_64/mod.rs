pub mod apic;
pub mod cpu;
pub mod gdt;
pub mod hal;
pub mod idt;
pub mod interrupts;
pub mod kernel_main;
pub mod mem_layout;
pub mod memory;
pub mod paging;
pub mod pci;
pub mod power;
pub mod serial;
pub mod syscall;
#[cfg(target_os = "uefi")]
pub mod uefi_boot_stack;
pub mod uefi_entry;
pub mod uentry;
pub mod xsave;

/// x86_64 early/kernel boot hook used by the common entry point.
pub fn init(boot_info: &'static crate::init::boot_info::BootInfo) -> ! {
    kernel_main::init(boot_info)
}
