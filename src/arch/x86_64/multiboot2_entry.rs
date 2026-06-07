//! x86_64 Multiboot2 / QEMU `-kernel` entry stub.
//!
//! QEMU (or GRUB2) loads the ELF64, enters long mode, and jumps to `_start`
//! with:
//!   EAX = 0x36D76289  (Multiboot2 magic)
//!   EBX = physical address of the MBI structure
//!
//! `_start` saves EBX/EAX *before* touching the stack (the stack pointer is
//! still undefined at that point), sets RSP, then tail-calls
//! `multiboot2_start(magic, mbi_ptr)` which validates magic, records the MBI
//! pointer, and enters the common `kernel_main`.
//!
//! For the UEFI path see `uefi_entry.rs`.

use super::uefi_entry::RSDP_PHYS;
use crate::init::boot_info::BootInfo;

/// Physical address of the MBI passed by the boot loader.
/// Written once by `multiboot2_start` before any other code runs.
pub static mut MBI_PTR: usize = 0;

/// Multiboot2 / QEMU `-kernel` entry point.
///
/// Naked so we control every register before `call`.  We must save EBX (MBI
/// physical address) and EAX (magic) into callee-saved registers *before*
/// establishing a stack, then set up RSP and forward them to
/// `multiboot2_start`.
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        // Save Multiboot2 arguments before RSP is valid.
        // EBX = MBI ptr  →  r15 (callee-saved, survives the call)
        // EAX = magic    →  r14
        "mov  r15, rbx",
        "mov  r14d, eax",
        // Establish boot stack.
        "lea  rsp, [rip + BOOT_STACK_TOP]",
        "xor  rbp, rbp",
        // No RSDP on this path.
        "mov  qword ptr [rip + {rsdp}], 0",
        // Call multiboot2_start(magic: u32, mbi_ptr: usize).
        // System-V ABI: rdi = arg0, rsi = arg1.
        "mov  edi, r14d",
        "mov  rsi, r15",
        "call multiboot2_start",
        // Should never return; halt if it does.
        "2:",
        "hlt",
        "jmp  2b",
        rsdp = sym RSDP_PHYS,
        options(noreturn)
    );
}

/// Rust trampoline called from `_start` with the Multiboot2 magic and MBI ptr.
///
/// Validates magic, records `MBI_PTR` for later use by `parse_mbi`, then
/// enters the common kernel entry point.
#[no_mangle]
pub unsafe extern "C" fn multiboot2_start(magic: u32, mbi_ptr: usize) -> ! {
    const MB2_MAGIC: u32 = 0x36d7_6289;
    if magic == MB2_MAGIC {
        MBI_PTR = mbi_ptr;
    }
    // parse_mbi must run before heap_init in kernel_main so the initramfs
    // physical range is recorded before initramfs::load() runs.
    if MBI_PTR != 0 {
        crate::arch::x86_64::multiboot2::parse_mbi(MBI_PTR);
    }
    kernel_main(&BOOT_INFO)
}

/// 16 KiB boot stack used until `gdt::init()` allocates a proper per-CPU
/// kstack.
#[link_section = ".bss"]
static mut BOOT_STACK: [u8; 16 * 1024] = [0; 16 * 1024];

/// Top-of-stack symbol — RSP is pointed here by `_start`.
/// Linker places this immediately after `BOOT_STACK` in `.bss`; stack grows
/// down.
#[no_mangle]
#[link_section = ".bss"]
static BOOT_STACK_TOP: [u8; 0] = [];

/// `BootInfo` for the bare-metal / Multiboot2 path.
/// Fields that Multiboot2 doesn't provide (EFI map, framebuffer) stay zeroed;
/// memory layout is discovered later via `parse_mbi`.
#[link_section = ".bss"]
static BOOT_INFO: BootInfo = BootInfo::empty();
