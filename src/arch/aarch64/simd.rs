//! AArch64 FP/SIMD (NEON/Advanced SIMD) context save and restore.
//!
//! Each task that uses floating-point or NEON instructions needs its own
//! `FpState`.  The scheduler saves/restores this on context switch.
//!
//! ## Layout
//!
//!   q[0..32]  — 128-bit SIMD registers Q0-Q31 (= D0-D31 / S0-S31 overlaid)
//!   fpsr      — Floating-point status register
//!   fpcr      — Floating-point control register
//!
//! The struct is 16-byte aligned so that `stp q0, q1` can be used without
//! an unaligned access fault.

#![allow(dead_code)]

use core::arch::asm;

/// Saved NEON / FP register state for one task.
#[repr(C, align(16))]
pub struct FpState {
    pub q: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
    pub _pad: u64,
}

impl FpState {
    pub const fn new() -> Self {
        Self {
            q: [0u128; 32],
            fpsr: 0,
            fpcr: 0,
            _pad: 0,
        }
    }
}

/// Save the current FP/SIMD state into `state`.
///
/// # Safety
/// FP/SIMD access must be enabled (CPACR_EL1.FPEN = 0b11).
/// `state` must be valid for write and 16-byte aligned.
#[inline]
pub unsafe fn save(state: &mut FpState) {
    let ptr = state as *mut FpState as *mut u8;
    asm!(
        "stp q0,  q1,  [{p}, #0]",
        "stp q2,  q3,  [{p}, #32]",
        "stp q4,  q5,  [{p}, #64]",
        "stp q6,  q7,  [{p}, #96]",
        "stp q8,  q9,  [{p}, #128]",
        "stp q10, q11, [{p}, #160]",
        "stp q12, q13, [{p}, #192]",
        "stp q14, q15, [{p}, #224]",
        "stp q16, q17, [{p}, #256]",
        "stp q18, q19, [{p}, #288]",
        "stp q20, q21, [{p}, #320]",
        "stp q22, q23, [{p}, #352]",
        "stp q24, q25, [{p}, #384]",
        "stp q26, q27, [{p}, #416]",
        "stp q28, q29, [{p}, #448]",
        "stp q30, q31, [{p}, #480]",
        p = in(reg) ptr,
        options(nostack)
    );
    let fpsr_ptr = ptr.add(512) as *mut u32;
    let fpcr_ptr = ptr.add(516) as *mut u32;
    let mut fpsr: u32;
    let mut fpcr: u32;
    asm!(
        "mrs {fpsr}, fpsr",
        "mrs {fpcr}, fpcr",
        fpsr = out(reg) fpsr,
        fpcr = out(reg) fpcr,
        options(nostack, nomem)
    );
    fpsr_ptr.write_volatile(fpsr);
    fpcr_ptr.write_volatile(fpcr);
}

/// Restore FP/SIMD state from `state`.
///
/// # Safety
/// Same requirements as `save`.
#[inline]
pub unsafe fn restore(state: &FpState) {
    let ptr = state as *const FpState as *const u8;
    asm!(
        "ldp q0,  q1,  [{p}, #0]",
        "ldp q2,  q3,  [{p}, #32]",
        "ldp q4,  q5,  [{p}, #64]",
        "ldp q6,  q7,  [{p}, #96]",
        "ldp q8,  q9,  [{p}, #128]",
        "ldp q10, q11, [{p}, #160]",
        "ldp q12, q13, [{p}, #192]",
        "ldp q14, q15, [{p}, #224]",
        "ldp q16, q17, [{p}, #256]",
        "ldp q18, q19, [{p}, #288]",
        "ldp q20, q21, [{p}, #320]",
        "ldp q22, q23, [{p}, #352]",
        "ldp q24, q25, [{p}, #384]",
        "ldp q26, q27, [{p}, #416]",
        "ldp q28, q29, [{p}, #448]",
        "ldp q30, q31, [{p}, #480]",
        p = in(reg) ptr,
        options(nostack)
    );
    let fpsr_ptr = ptr.add(512) as *const u32;
    let fpcr_ptr = ptr.add(516) as *const u32;
    let fpsr = fpsr_ptr.read_volatile();
    let fpcr = fpcr_ptr.read_volatile();
    asm!(
        "msr fpsr, {fpsr}",
        "msr fpcr, {fpcr}",
        fpsr = in(reg) fpsr as u64,
        fpcr = in(reg) fpcr as u64,
        options(nostack, nomem)
    );
}
