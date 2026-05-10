//! RISC-V SBI boot entry.
//!
//! OpenSBI hands off to us in S-mode with:
//!   a0 = hart ID
//!   a1 = pointer to FDT (device tree blob)
//!
//! We stash both registers in globals, set up the boot stack (sp = BOOT_STACK_TOP,
//! the highest address of the 32 KiB .bss boot stack region), then call
//! kernel_main_riscv64(hart_id, fdt_ptr).
//!
//! ## Stack layout
//!
//! RISC-V stacks grow **downward**: sp must point to the *highest* address of
//! the reserved region on entry.  The linker places symbols in the order they
//! appear in the object file, so we must declare the stack array **before**
//! BOOT_STACK_TOP so that the top symbol ends up at `base + size`:
//!
//!   [BOOT_STACK  .................. BOOT_STACK_TOP]
//!    ^low                                    ^high
//!    .bss                                sp on entry
//!
//! The repr(align(16)) satisfies the RISC-V ABI 16-byte stack-alignment
//! invariant that the hardware enforces at `call` instructions.

use core::arch::asm;

/// Hart ID saved by _start before any Rust code runs.
pub static mut BOOT_HART_ID: usize = 0;

/// Physical address of the FDT blob passed in a1 by OpenSBI.
/// 0 = not available.
pub static mut FDT_PHYS: usize = 0;

/// 32 KiB boot stack (BSS, zero-initialised by OpenSBI / firmware).
///
/// `repr(align(16))` ensures the region starts on a 16-byte boundary so
/// that the initial `sp = BOOT_STACK_TOP` value is also 16-byte aligned
/// (BOOT_STACK_TOP is placed at `base + 32768` by the linker).
#[repr(align(16))]
struct BootStackStorage([u8; 32768]);

/// The stack storage itself.  MUST be declared **before** BOOT_STACK_TOP so
/// the linker places BOOT_STACK_TOP immediately above it (higher address).
#[link_section = ".bss"]
static mut BOOT_STACK: BootStackStorage = BootStackStorage([0u8; 32768]);

/// Zero-size symbol immediately above BOOT_STACK.  `sp` is set to this
/// address on entry — it is the valid first push address (stack is empty).
#[no_mangle]
#[link_section = ".bss"]
pub static BOOT_STACK_TOP: [u8; 0] = [];

/// Naked SBI entry stub.  Entered with MMU off, interrupts off.
/// Saves a0/a1, sets sp = BOOT_STACK_TOP, then calls kernel_main_riscv64.
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

        // Load boot stack pointer (top = highest address of BOOT_STACK).
        "la   sp, {stack_top}",

        // Call kernel_main_riscv64(hart_id=a0, fdt_ptr=a1) — args already in a0/a1.
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
