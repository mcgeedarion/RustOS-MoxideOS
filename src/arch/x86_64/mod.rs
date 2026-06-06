// NOTE: ap_boot.s and boot.s are bare assembly fragments (GAS / NASM
// syntax). They are not Rust modules and are not assembled by build.rs
// today; `_start` is provided in Rust by multiboot2_entry.rs via
// #[naked] + global_asm!. The .s files are retained as reference /
// future-replacement material; wire them through build.rs (or move
// their bodies into global_asm! blocks) when SMP/multiboot lands.
pub mod apic;
pub mod cpu;
pub mod gdt;
pub mod hal;
pub mod idt;
pub mod interrupts;
pub mod kernel_main;
pub mod mem_layout;
pub mod memory;
pub mod multiboot2;
pub mod multiboot2_entry;
pub mod paging;
pub mod pci;
pub mod serial;
pub mod syscall;
pub mod uefi_entry;
pub mod uentry;
pub mod xsave;

/// x86_64 early/kernel boot hook used by the common entry point.
pub fn init(boot_info: &'static crate::init::boot_info::BootInfo) -> ! {
    kernel_main::init(boot_info)
}
