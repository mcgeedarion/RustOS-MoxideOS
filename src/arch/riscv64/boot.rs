//! RISC-V SBI boot entry.
//!
//! OpenSBI hands off to us in S-mode with:
//!   a0 = hart ID
//!   a1 = pointer to FDT (device tree blob)
//!
//! We stash both registers in globals, set up a temporary boot stack,
//! then call kernel_main(hart_id, fdt_ptr).

use core::arch::asm;

/// Hart ID saved by _start before any Rust code runs.
pub static mut BOOT_HART_ID: usize = 0;

/// Physical address of the FDT blob passed in a1 by OpenSBI.
/// 0 = not available.
pub static mut FDT_PHYS: usize = 0;

/// 16 KiB boot stack (BSS, zero-initialised by OpenSBI).
#[link_section = ".bss"]
static mut BOOT_STACK: [u8; 16384] = [0u8; 16384];

/// Symbol at the top of the boot stack.
#[no_mangle]
#[link_section = ".bss"]
pub static BOOT_STACK_TOP: [u8; 0] = [];

/// Naked SBI entry stub.  Entered with MMU off, interrupts off.
/// Saves a0/a1, sets sp, then calls kernel_main(hart_id, fdt_ptr).
#[no_mangle]
#[naked]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        // Only hart 0 proceeds; all others park in wfi.
        "mv   tp, a0",
        "bnez a0, 1f",

        // Stash hart ID and FDT pointer into globals.
        "la   t0, {hart_id}",
        "sd   a0, 0(t0)",
        "la   t0, {fdt_phys}",
        "sd   a1, 0(t0)",

        // Load boot stack pointer.
        "la   sp, {stack_top}",

        // Call kernel_main(hart_id=a0, fdt_ptr=a1) — args already in a0/a1.
        "call {kmain}",

        // kernel_main returned — should never happen.
        "1: wfi",
        "j 1b",

        hart_id   = sym BOOT_HART_ID,
        fdt_phys  = sym FDT_PHYS,
        stack_top = sym BOOT_STACK_TOP,
        kmain     = sym crate::kernel_main::kernel_main_riscv64,
        options(noreturn)
    );
}
