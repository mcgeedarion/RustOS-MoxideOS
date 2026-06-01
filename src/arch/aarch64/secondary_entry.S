//
// AArch64 secondary CPU entry stub.
//
// PSCI CPU_ON sets PC to this label and X0 to the context argument (unused;
// we pass 0).  SP_EL1 is not yet valid so we must initialise it before
// entering Rust.
//
// `SECONDARY_STACK_TOP` (exported from smp.rs) holds the physical/virtual
// address of the top of the pre-allocated kernel stack.
//

.section .text.secondary_entry, "ax"
.global secondary_entry

secondary_entry:
    // Disable interrupts while we set up the CPU.
    msr  daifset, #0xf

    // Load the stack top written by the BSP into SP_EL1.
    adrp x9,  SECONDARY_STACK_TOP
    add  x9,  x9, :lo12:SECONDARY_STACK_TOP
    ldar x10, [x9]              // atomic load-acquire
    mov  sp,  x10

    // Align SP to 16 bytes (should already be, but be explicit).
    and  sp,  sp, #~15

    // Zero the frame pointer so backtraces terminate cleanly.
    mov  x29, xzr
    mov  x30, xzr

    // Branch to Rust.  secondary_rust_main() -> !
    bl   secondary_rust_main

    // Should never reach here.
1:  wfi
    b    1b
