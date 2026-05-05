//! Kernel binary entry points.
//!
//! ## RISC-V path
//!   OpenSBI → _start  (in arch/riscv64/boot.rs)
//!           → kernel_main() (in kernel_main.rs)
//!
//! ## x86_64 UEFI path
//!   Firmware → uefi_start()  (in arch/x86_64/uefi_entry.rs)
//!            → kernel_main() (in arch/x86_64/kernel_main.rs)
//!
//! ## x86_64 Multiboot2 / QEMU -kernel path
//!   QEMU loads the ELF64, enters long mode, jumps to _start below.
//!   _start sets RSP to __boot_stack_top and calls kernel_main().

#![no_std]
#![no_main]
extern crate rustos;

/// x86_64 Multiboot2 / QEMU entry stub.
/// Sets up a temporary 16 KiB stack then calls kernel_main.
/// Not compiled for RISC-V — that arch uses arch/riscv64/boot.rs instead.
#[cfg(target_arch = "x86_64")]
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
        rsdp = sym rustos::arch::x86_64::uefi_entry::RSDP_PHYS,
        options(noreturn)
    );
}

/// 16 KiB boot stack used before gdt_init() allocates a proper per-CPU kstack.
#[cfg(target_arch = "x86_64")]
#[link_section = ".bss"]
static mut __BOOT_STACK: [u8; 16384] = [0u8; 16384];

/// Symbol loaded into RSP by both _start and uefi_start.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[link_section = ".bss"]
static __boot_stack_top: [u8; 0] = [];
