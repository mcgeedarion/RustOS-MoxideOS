//! Kernel binary entry point.
//! The bootloader (UEFI or multiboot2) jumps to _start in 64-bit long mode
//! with a flat identity-mapped address space and interrupts disabled.

#![no_std]
#![no_main]
extern crate rustos;

/// Naked entry stub: set up a temporary stack then call kernel_main.
/// The bootloader may not have set RSP to a valid kernel stack, so we
/// load one explicitly before calling Rust code.
#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        // Temporary boot stack: 16 KiB of BSS.
        "lea rsp, [rip + __boot_stack_top]",
        "xor rbp, rbp",
        "call kernel_main",
        // kernel_main is -> ! but if it ever returns, halt.
        "2: hlt",
        "jmp 2b",
        options(noreturn)
    );
}

/// 16 KiB boot stack used before gdt_init() allocates a proper kstack.
#[link_section = ".bss"]
static mut __BOOT_STACK: [u8; 16384] = [0u8; 16384];

/// Symbol that _start loads into RSP.
#[no_mangle]
#[link_section = ".bss"]
static __boot_stack_top: [u8; 0] = [];
