//! x86_64 Multiboot2 / QEMU `-kernel` entry stub.
//!
//! QEMU loads the ELF64, enters long mode, and jumps to `_start`.
//! `_start` sets RSP to `BOOT_STACK_TOP`, zeroes the RSDP slot
//! (no firmware on this path), and calls `kernel_main(&BOOT_INFO)`.
//!
//! For the UEFI path see `uefi_entry.rs`.

use super::uefi_entry::RSDP_PHYS;
use crate::init::boot_info::BootInfo;

/// Multiboot2 / QEMU entry stub.
///
/// Sets up a temporary 16 KiB stack and calls `kernel_main`.
#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "lea  rsp, [rip + BOOT_STACK_TOP]",
        "xor  rbp, rbp",
        "mov  qword ptr [rip + {rsdp}], 0",
        "lea  rdi, [rip + {boot_info}]",
        "call kernel_main",
        "2:",
        "hlt",
        "jmp  2b",
        rsdp = sym RSDP_PHYS,
        boot_info = sym BOOT_INFO,
        options(noreturn)
    );
}

/// 16 KiB boot stack used until `gdt::init()` allocates a proper per-CPU kstack.
///
/// Placed in `.bss` so it costs nothing in the binary image.
#[link_section = ".bss"]
static mut BOOT_STACK: [u8; 16 * 1024] = [0; 16 * 1024];

/// Top-of-stack symbol loaded into RSP by `_start`.
///
/// The linker places this immediately after `BOOT_STACK` in `.bss`; on
/// x86_64 the stack grows down, so RSP starts here and descends into
/// `BOOT_STACK`.
#[no_mangle]
#[link_section = ".bss"]
static BOOT_STACK_TOP: [u8; 0] = [];

/// Minimal boot handoff for the x86_64 bare-metal / Multiboot2 path.
#[link_section = ".bss"]
static BOOT_INFO: BootInfo = BootInfo::empty();
