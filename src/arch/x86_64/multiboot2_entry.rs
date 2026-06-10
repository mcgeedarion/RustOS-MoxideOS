//! x86_64 Multiboot2 / QEMU `-kernel` entry stub.
//!
//! QEMU (or GRUB2) loads the ELF64, enters long mode, and jumps to `_start`
//! with:
//!   EAX = 0x36D76289  (Multiboot2 magic)
//!   EBX = physical address of the MBI structure
//!
//! `_start` is the naked assembly shim in `boot.s` which:
//!   1. Stashes EBX/EAX into callee-saved registers.
//!   2. Sets RSP to `__boot_stack_top` (the 32 KiB stack in the linker
//!      script `.bss` section).
//!   3. Calls `multiboot2_entry(magic, mbi_ptr)`.
//!
//! There is no separate boot stack in this file — `boot.s` owns the stack.
//! For the UEFI path see `uefi_entry.rs`.

use crate::init::boot_info::BootInfo;

/// Physical address of the MBI passed by the boot loader.
/// Written once by `multiboot2_entry` before any other code runs.
pub static mut MBI_PTR: usize = 0;

/// Rust trampoline called from `_start` (boot.s) with the Multiboot2 magic
/// and MBI ptr.
///
/// Accepts any magic value: if the magic matches MB2, MBI_PTR is recorded
/// and parse_mbi runs; otherwise we boot with no MBI (ACPI already handles
/// a null RSDP gracefully — see firmware/acpi/mod.rs).
#[no_mangle]
pub unsafe extern "C" fn multiboot2_entry(magic: u32, mbi_ptr: usize) -> ! {
    // RSDP_PHYS is a static mut and is zero-initialised by the linker, so
    // ACPI will see rsdp_phys==0 and skip table parsing — no explicit zero
    // write needed here.
    const MB2_MAGIC: u32 = 0x36d7_6289;
    if magic == MB2_MAGIC {
        MBI_PTR = mbi_ptr;
    } else {
        crate::serial_println!("multiboot2: unexpected magic {:#x}, booting without MBI", magic);
    }
    if MBI_PTR != 0 {
        crate::arch::x86_64::multiboot2::parse_mbi(MBI_PTR);
    }
    crate::kernel_main(&BOOT_INFO)
}

/// `BootInfo` for the bare-metal / Multiboot2 path.
/// Fields that Multiboot2 doesn't provide (EFI map, framebuffer) stay zeroed;
/// memory layout is discovered later via `parse_mbi`.
#[link_section = ".bss"]
static BOOT_INFO: BootInfo = BootInfo::empty();
