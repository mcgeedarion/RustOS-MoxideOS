//! Kernel binary entry points.
//!
//! ## UEFI path (default, matches x86_64.ld ENTRY)
//!   Firmware → uefi_start()  (in arch/x86_64/uefi_entry.rs)
//!            → kernel_main() (in arch/x86_64/kernel_main.rs)
//!
//! ## Multiboot2 / QEMU -kernel path
//!   QEMU loads the ELF64, enters long mode, jumps to _start below.
//!   _start sets RSP to __boot_stack_top and calls kernel_main().
//!
//! Both paths converge at kernel_main().

#![no_std]
#![no_main]
extern crate rustos;

/// Multiboot2 / QEMU entry stub.
/// Sets up a temporary 16 KiB stack then calls kernel_main.
#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "lea rsp, [rip + __boot_stack_top]",
        "xor rbp, rbp",
        "mov qword ptr [rip + {rsdp}], 0",
        "call kernel_main",
        "2: hlt",
        "jmp 2b",
        // Use arch-internal symbol — entry points are inherently arch-specific
        // and remain the one legitimate direct arch import in main.rs.
        rsdp = sym rustos::arch::x86_64::uefi_entry::RSDP_PHYS,
        options(noreturn)
    );
}

/// 16 KiB boot stack used before gdt_init() allocates a proper per-CPU kstack.
#[link_section = ".bss"]
static mut __BOOT_STACK: [u8; 16384] = [0u8; 16384];

/// Symbol loaded into RSP by both _start and uefi_start.
#[no_mangle]
#[link_section = ".bss"]
static __boot_stack_top: [u8; 0] = [];
