//! RISC-V supervisor-mode syscall entry trampoline.
//!
//! The naked function `riscv_trap_entry` is set as the stvec target by
//! trap_init().  It saves all caller-saved and callee-saved registers,
//! calls riscv_trap_handler (in trap.rs), then restores and srets.
//!
//! RISC-V Linux syscall ABI:
//!   a7 = NR,  a0-a5 = args,  a0 = return value
//!
//! Note: we use a single trap vector (not vectored mode) so all traps
//! (interrupts + exceptions) funnel through riscv_trap_entry.

/// Naked trap entry: save all regs → call riscv_trap_handler → restore → sret.
#[naked]
#[no_mangle]
pub unsafe extern "C" fn riscv_trap_entry() {
    // Stack layout: 33 × 8 bytes = 264 bytes = 0x108
    // Slot assignments match TrapFrame field order.
    core::arch::asm!(
        "addi sp, sp, -272",     // 34 slots × 8 = 272 (extra for sepc/sstatus)
        "sd   ra,   0(sp)",
        "sd   sp,   8(sp)",      // saves pre-trap sp (sp before sub)
        "sd   gp,  16(sp)",
        "sd   tp,  24(sp)",
        "sd   t0,  32(sp)",
        "sd   t1,  40(sp)",
        "sd   t2,  48(sp)",
        "sd   s0,  56(sp)",
        "sd   s1,  64(sp)",
        "sd   a0,  72(sp)",
        "sd   a1,  80(sp)",
        "sd   a2,  88(sp)",
        "sd   a3,  96(sp)",
        "sd   a4, 104(sp)",
        "sd   a5, 112(sp)",
        "sd   a6, 120(sp)",
        "sd   a7, 128(sp)",
        "sd   s2, 136(sp)",
        "sd   s3, 144(sp)",
        "sd   s4, 152(sp)",
        "sd   s5, 160(sp)",
        "sd   s6, 168(sp)",
        "sd   s7, 176(sp)",
        "sd   s8, 184(sp)",
        "sd   s9, 192(sp)",
        "sd  s10, 200(sp)",
        "sd  s11, 208(sp)",
        "sd   t3, 216(sp)",
        "sd   t4, 224(sp)",
        "sd   t5, 232(sp)",
        "sd   t6, 240(sp)",
        // sepc and sstatus
        "csrr t0, sepc",
        "sd   t0, 248(sp)",
        "csrr t0, sstatus",
        "sd   t0, 256(sp)",
        // call Rust handler
        "mv   a0, sp",
        "call riscv_trap_handler",
        // restore sepc and sstatus
        "ld   t0, 248(sp)",
        "csrw sepc, t0",
        "ld   t0, 256(sp)",
        "csrw sstatus, t0",
        // restore general-purpose registers
        "ld   ra,   0(sp)",
        // skip sp for now
        "ld   gp,  16(sp)",
        "ld   tp,  24(sp)",
        "ld   t0,  32(sp)",
        "ld   t1,  40(sp)",
        "ld   t2,  48(sp)",
        "ld   s0,  56(sp)",
        "ld   s1,  64(sp)",
        "ld   a0,  72(sp)",
        "ld   a1,  80(sp)",
        "ld   a2,  88(sp)",
        "ld   a3,  96(sp)",
        "ld   a4, 104(sp)",
        "ld   a5, 112(sp)",
        "ld   a6, 120(sp)",
        "ld   a7, 128(sp)",
        "ld   s2, 136(sp)",
        "ld   s3, 144(sp)",
        "ld   s4, 152(sp)",
        "ld   s5, 160(sp)",
        "ld   s6, 168(sp)",
        "ld   s7, 176(sp)",
        "ld   s8, 184(sp)",
        "ld   s9, 192(sp)",
        "ld  s10, 200(sp)",
        "ld  s11, 208(sp)",
        "ld   t3, 216(sp)",
        "ld   t4, 224(sp)",
        "ld   t5, 232(sp)",
        "ld   t6, 240(sp)",
        // restore sp last
        "ld   sp,   8(sp)",
        "sret",
        options(noreturn)
    );
}
