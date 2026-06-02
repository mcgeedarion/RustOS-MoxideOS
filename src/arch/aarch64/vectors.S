// AArch64 exception vector table  (VBAR_EL1).
// Layout (Armv8-A §D1.10.2): 16 entries × 128 bytes each = 2 KiB.
// The table must be placed at a 2 KiB-aligned address.
// Each entry saves the full ExceptionFrame (x0-x30, sp_el0, elr_el1,
// spsr_el1) on the EL1 stack, calls the corresponding Rust handler, then
// restores the frame and executes `eret`.
// We only wire up the four groups we need:
//   – Current EL with SP_EL1  (the kernel is executing, SP = SP_EL1)
//   – Lower EL AArch64        (user-space trap → kernel)
// The other two (SP_EL0 and Lower EL AArch32) just spin — we don't use them.

.section .text.vectors, "ax"
.global __exception_vectors
.align 11                           // 2^11 = 2048 byte alignment

// exception_entry: saves all GPRs + sp_el0/elr_el1/spsr_el1, then passes
//   x0 = &ExceptionFrame to the Rust handler.
// exception_return: restores the frame and executes eret.

.macro exception_entry handler
    // Make room for ExceptionFrame (272 bytes).  sub before stp so that x29/x30
    // are saved relative to the new SP.
    sub  sp,  sp,  #272
    stp  x0,  x1,  [sp, #0]
    stp  x2,  x3,  [sp, #16]
    stp  x4,  x5,  [sp, #32]
    stp  x6,  x7,  [sp, #48]
    stp  x8,  x9,  [sp, #64]
    stp  x10, x11, [sp, #80]
    stp  x12, x13, [sp, #96]
    stp  x14, x15, [sp, #112]
    stp  x16, x17, [sp, #128]
    stp  x18, x19, [sp, #144]
    stp  x20, x21, [sp, #160]
    stp  x22, x23, [sp, #176]
    stp  x24, x25, [sp, #192]
    stp  x26, x27, [sp, #208]
    stp  x28, x29, [sp, #224]
    str  x30,      [sp, #240]       // x30 (LR)
    mrs  x9,  sp_el0
    mrs  x10, elr_el1
    mrs  x11, spsr_el1
    stp  x9,  x10, [sp, #248]       // sp_el0, elr_el1
    str  x11,      [sp, #264]       // spsr_el1
    mov  x0,  sp                    // x0 = &ExceptionFrame
    bl   \handler
.endm

.macro exception_return
    ldr  x11,      [sp, #264]       // spsr_el1
    ldp  x9,  x10, [sp, #248]       // sp_el0, elr_el1
    msr  spsr_el1, x11
    msr  elr_el1,  x10
    msr  sp_el0,   x9
    ldp  x28, x29, [sp, #224]
    ldr  x30,      [sp, #240]
    ldp  x26, x27, [sp, #208]
    ldp  x24, x25, [sp, #192]
    ldp  x22, x23, [sp, #176]
    ldp  x20, x21, [sp, #160]
    ldp  x18, x19, [sp, #144]
    ldp  x16, x17, [sp, #128]
    ldp  x14, x15, [sp, #112]
    ldp  x12, x13, [sp, #96]
    ldp  x10, x11, [sp, #80]
    ldp  x8,  x9,  [sp, #64]
    ldp  x6,  x7,  [sp, #48]
    ldp  x4,  x5,  [sp, #32]
    ldp  x2,  x3,  [sp, #16]
    ldp  x0,  x1,  [sp, #0]
    add  sp,  sp,  #272
    eret
.endm

.macro dead_entry
    b .
    .align 7
.endm

__exception_vectors:

.align 7
    dead_entry          // Synchronous
.align 7
    dead_entry          // IRQ
.align 7
    dead_entry          // FIQ
.align 7
    dead_entry          // SError

.align 7
current_sync:
    exception_entry aarch64_sync_handler
    exception_return

.align 7
current_irq:
    exception_entry aarch64_irq_handler
    exception_return

.align 7
current_fiq:
    exception_entry aarch64_fiq_handler
    exception_return

.align 7
current_serror:
    exception_entry aarch64_serror_handler
    exception_return

.align 7
lower_sync_a64:
    exception_entry aarch64_sync_handler
    exception_return

.align 7
lower_irq_a64:
    exception_entry aarch64_irq_handler
    exception_return

.align 7
lower_fiq_a64:
    exception_entry aarch64_fiq_handler
    exception_return

.align 7
lower_serror_a64:
    exception_entry aarch64_serror_handler
    exception_return

.align 7
    dead_entry
.align 7
    dead_entry
.align 7
    dead_entry
.align 7
    dead_entry
