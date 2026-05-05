//! RISC-V SBI boot entry.
//!
//! OpenSBI hands off to us in S-mode with:
//!   a0 = hart ID
//!   a1 = pointer to FDT (device tree blob)
//!
//! We set up a temporary boot stack, then call kernel_main.

use core::arch::asm;

/// 16 KiB boot stack (BSS, zero-initialised by OpenSBI).
#[link_section = ".bss"]
static mut BOOT_STACK: [u8; 16384] = [0u8; 16384];

/// Naked SBI entry stub.  Entered with MMU off, interrupts off.
/// Sets sp to top of BOOT_STACK, then calls kernel_main(hart_id, fdt_ptr).
#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        // Only hart 0 proceeds; all others park in wfi.
        "mv   tp, a0",               // stash hart id in tp
        "bnez a0, 1f",
        // Load boot stack pointer (la = auipc + addi, PIC-safe).
        "la   sp, {stack_top}",
        "call {kmain}",
        // kernel_main returned — should never happen.
        "1: wfi",
        "j 1b",
        stack_top = sym BOOT_STACK_TOP,
        kmain     = sym kernel_main,
        options(noreturn)
    );
}

/// Symbol at the top of the boot stack (referenced by _start).
#[no_mangle]
#[link_section = ".bss"]
pub static BOOT_STACK_TOP: [u8; 0] = [];
