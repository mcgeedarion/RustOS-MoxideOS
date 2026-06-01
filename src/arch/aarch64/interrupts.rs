//! AArch64 synchronous/IRQ/FIQ/SError exception dispatch.
//!
//! ## Exception vector table
//!
//! `init()` loads the address of `__exception_vectors` (defined in
//! `vectors.S`) into VBAR_EL1.  The table must be 2 KiB-aligned
//! (Armv8-A spec §D1.10.2).
//!
//! ## ExceptionFrame layout
//!
//! The assembly stubs save:
//!   x0-x30  (31 × u64 = 248 bytes)
//!   sp_el0  (u64)
//!   elr_el1 (u64)   — faulting / returning PC
//!   spsr_el1(u64)
//! Total: 272 bytes, 16-byte aligned.

#![allow(dead_code)]

use core::arch::asm;

/// Saved general-purpose + exception-state registers.
///
/// Field order MUST match the `stp` sequence in `vectors.S`.
#[repr(C)]
pub struct ExceptionFrame {
    pub x: [u64; 31],
    pub sp_el0:   u64,
    pub elr_el1:  u64,
    pub spsr_el1: u64,
}

// Exception Syndrome Register — Class field.
const ESR_EC_SHIFT: u64 = 26;
const ESR_EC_MASK:  u64 = 0x3f;

const EC_SVC64:            u64 = 0x15; // SVC from AArch64
const EC_INST_ABORT_LOWER: u64 = 0x20; // instruction abort from EL0
const EC_INST_ABORT_SAME:  u64 = 0x21; // instruction abort from EL1
const EC_DATA_ABORT_LOWER: u64 = 0x24; // data abort from EL0
const EC_DATA_ABORT_SAME:  u64 = 0x25; // data abort from EL1

extern "C" {
    /// Defined in `vectors.S`; must be 2 KiB-aligned.
    static __exception_vectors: u8;
}

/// Install the exception vector table into VBAR_EL1.
///
/// # Safety
/// Must be called at EL1 with interrupts disabled.  `__exception_vectors`
/// must be correctly linked at a 2 KiB-aligned virtual address.
#[inline]
pub unsafe fn init() {
    let base = core::ptr::addr_of!(__exception_vectors) as usize;
    asm!(
        "msr vbar_el1, {vbar}",
        "isb",
        vbar = in(reg) base,
        options(nostack, nomem)
    );
}

// ── Rust-side exception handlers ─────────────────────────────────────────────
//
// Called by the assembly trampolines in vectors.S.
// Each receives a mutable reference to the saved register frame so that
// signal delivery / syscall return can modify ELR / SPSR before eret.

#[no_mangle]
extern "C" fn aarch64_sync_handler(frame: &mut ExceptionFrame) {
    let esr = super::hal::read_esr_el1() as u64;
    match (esr >> ESR_EC_SHIFT) & ESR_EC_MASK {
        EC_SVC64 => {
            super::syscall::handle(frame);
        }
        EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME |
        EC_INST_ABORT_LOWER | EC_INST_ABORT_SAME => {
            let far = super::hal::read_far_el1();
            crate::mm::page_fault::handle(
                far,
                esr as usize,
                frame.elr_el1 as usize,
            );
        }
        ec => {
            panic!(
                "aarch64: unhandled exception ec={:#x} esr={:#x} elr={:#x}",
                ec, esr, frame.elr_el1
            );
        }
    }
}

#[no_mangle]
extern "C" fn aarch64_irq_handler(_frame: &mut ExceptionFrame) {
    // Dispatch to the GIC-level IRQ handler registered during gic::init().
    crate::irq::aarch64::gic::handle_irq();

    // Timer accounting and scheduler preemption point.
    crate::proc::scheduler::schedule();
}

#[no_mangle]
extern "C" fn aarch64_fiq_handler(_frame: &mut ExceptionFrame) {
    // FIQ is not used — GICv3 can route everything as IRQ in non-secure EL1.
    panic!("aarch64: unexpected FIQ");
}

#[no_mangle]
extern "C" fn aarch64_serror_handler(frame: &mut ExceptionFrame) {
    let esr = super::hal::read_esr_el1();
    panic!(
        "aarch64: SError esr={:#x} elr={:#x} spsr={:#x}",
        esr, frame.elr_el1, frame.spsr_el1
    );
}
