//! Kernel binary entry points.
//!
//! ## RISC-V path
//!   OpenSBI → `_start`  (in `arch/riscv64/boot.rs`)
//!           → `kernel_main()` (in `kernel_main.rs`)
//!
//! ## x86_64 UEFI path
//!   Firmware → `uefi_start()` (in `arch/x86_64/uefi_entry.rs`)
//!            → `kernel_main()` (in `arch/x86_64/kernel_main.rs`)
//!
//! ## x86_64 Multiboot2 / QEMU `-kernel` path
//!   QEMU loads the ELF64, enters long mode, and jumps to `_start` below.
//!   `_start` sets RSP to `BOOT_STACK_TOP` and calls `kernel_main()`.

#![no_std]
#![no_main]
extern crate rustos;

use rustos::arch::x86_64::uefi_entry::RSDP_PHYS;

/// x86_64 Multiboot2 / QEMU entry stub.
///
/// Sets up a temporary 16 KiB stack, zeroes the RSDP slot (no firmware
/// on this path), then calls `kernel_main`. Not compiled for RISC-V —
/// that arch uses `arch/riscv64/boot.rs` instead.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "lea  rsp, [rip + BOOT_STACK_TOP]",
        "xor  rbp, rbp",
        "mov  qword ptr [rip + {rsdp}], 0",
        "call kernel_main",
        "2:",
        "hlt",
        "jmp  2b",
        rsdp = sym RSDP_PHYS,
        options(noreturn)
    );
}

/// 16 KiB boot stack, used until `gdt::init()` allocates a proper per-CPU kstack.
///
/// Placed in `.bss` so it costs nothing in the binary image.
#[cfg(target_arch = "x86_64")]
#[link_section = ".bss"]
static mut BOOT_STACK: [u8; 16 * 1024] = [0; 16 * 1024];

/// Top-of-stack symbol loaded into RSP by both `_start` and `uefi_start`.
///
/// The linker places this immediately after `BOOT_STACK` in `.bss`; on
/// x86_64 the stack grows down, so RSP starts here and descends into
/// `BOOT_STACK`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[link_section = ".bss"]
static BOOT_STACK_TOP: [u8; 0] = [];
