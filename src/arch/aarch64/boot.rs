//! ARM64 boot glue.
//!
//! Two entry paths:
//!   - UEFI:       `efi_main` in `uefi_entry.rs` (EDK2 calls this directly).
//!   - Bare-metal: `_start` below (linked into `.text.boot` by linker_aarch64.ld).
//!
//! The bare-metal path is used with the `aarch64-kernel` target JSON and is
//! intended for future bring-up without UEFI (e.g. U-Boot, custom firmware).

use crate::init::boot_info::{BootInfo, BootRange};
use core::arch::global_asm;

// Bare-metal entry point.
// Placed in .text.boot so the linker script positions it first in the image.
// On entry (Armv8-A bare-metal convention):
//   x0 = DTB physical address (if provided by firmware; 0 otherwise)
//   All other GPRs are undefined.
//   SP is undefined — we set it immediately.
//   MMU/caches are off.
//   EL1 or EL2 (we do not handle EL3 here).
// We:
//   1. Park all secondary CPUs (MPIDR Aff0 != 0) in a WFE loop.
//   2. Set SP to __boot_stack_top (defined by linker_aarch64.ld).
//   3. Zero .bss.
//   4. Call kernel_main(&BOOT_INFO).
global_asm!(
    ".section .text.boot",
    ".global _start",
    "_start:",
    // Park secondary CPUs.
    "    mrs  x1, mpidr_el1",
    "    and  x1, x1, #0xff", // Aff0 field
    "    cbnz x1, .Lsecondary",
    "    adr  x1, __boot_stack_top",
    "    mov  sp, x1",
    // Zero .bss: x2 = &__bss_start (= _kernel_start offset by linker), x3 = &_end.
    // We use the standard GNU symbols; ld exports them from the SECTIONS.
    "    adr  x2, __bss_start",
    "    adr  x3, __bss_end",
    ".Lbss_loop:",
    "    cmp  x2, x3",
    "    b.ge .Lbss_done",
    "    str  xzr, [x2], #8",
    "    b    .Lbss_loop",
    ".Lbss_done:",
    // Jump to Rust — noreturn.
    "    b    aarch64_boot_main",
    // Secondary CPU park loop.
    ".Lsecondary:",
    "    wfe",
    "    b    .Lsecondary",
);

// Provide __bss_start/__bss_end as weak symbols so the asm above links even
// when the linker script does not define them explicitly.  The real values
// come from linker_aarch64.ld via the .bss section bounds.
extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
    static __boot_stack_top: u8;
}

#[no_mangle]
static mut BOOT_INFO: BootInfo = BootInfo::empty();

#[no_mangle]
pub extern "C" fn aarch64_boot_main(fdt_phys: usize) -> ! {
    unsafe {
        BOOT_INFO = BootInfo {
            fdt: BootRange::new(fdt_phys, 0),
            ..BootInfo::empty()
        };
        crate::kernel_main::kernel_main(&BOOT_INFO)
    }
}
