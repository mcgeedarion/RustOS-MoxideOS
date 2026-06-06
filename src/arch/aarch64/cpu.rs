//! AArch64 per-CPU helpers: EL control, DAIF, FP/SIMD enable, MPIDR.

#![allow(dead_code)]

use core::arch::asm;

/// Returns the Aff0 field of MPIDR_EL1 as the logical CPU id.
#[inline]
pub fn cpu_id() -> usize {
    // hal.rs already has cpu_id(); re-export the same logic here for use
    // inside arch-internal modules without importing hal.
    let mpidr: usize;
    unsafe {
        asm!("mrs {m}, mpidr_el1", m = out(reg) mpidr, options(nostack, nomem));
    }
    mpidr & 0xff_ff
}

/// Enable FP/SIMD access at EL0/EL1 via CPACR_EL1.FPEN = 0b11.
///
/// Must be called before any NEON/FP instruction, typically in early arch init.
#[inline]
pub unsafe fn enable_fp_simd() {
    let mut cpacr: u64;
    asm!("mrs {c}, cpacr_el1", c = out(reg) cpacr, options(nostack, nomem));
    cpacr |= 0b11 << 20;
    asm!("msr cpacr_el1, {c}", c = in(reg) cpacr, options(nostack, nomem));
    asm!("isb", options(nostack, nomem));
}

/// Read TTBR0_EL1 (user page-table base for the current CPU).
#[inline]
pub fn read_ttbr0() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {v}, ttbr0_el1", v = out(reg) v, options(nostack, nomem));
    }
    v
}

/// Write TTBR0_EL1 and issue ISB.
#[inline]
pub unsafe fn write_ttbr0(val: u64) {
    asm!(
        "msr ttbr0_el1, {v}",
        "isb",
        v = in(reg) val,
        options(nostack, nomem)
    );
}

/// Read TTBR1_EL1 (kernel page-table base).
#[inline]
pub fn read_ttbr1() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {v}, ttbr1_el1", v = out(reg) v, options(nostack, nomem));
    }
    v
}

/// Write TTBR1_EL1 and issue ISB.
#[inline]
pub unsafe fn write_ttbr1(val: u64) {
    asm!(
        "msr ttbr1_el1, {v}",
        "isb",
        v = in(reg) val,
        options(nostack, nomem)
    );
}

/// Read the physical counter frequency (CNTFRQ_EL0).
#[inline]
pub fn counter_freq() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {v}, cntfrq_el0", v = out(reg) v, options(nostack, nomem));
    }
    v
}

/// Read the virtual count (CNTVCT_EL0).
#[inline]
pub fn read_virtual_count() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {v}, cntvct_el0", v = out(reg) v, options(nostack, nomem));
    }
    v
}

/// Return the current Exception Level (0–3).
#[inline]
pub fn current_el() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {v}, CurrentEL", v = out(reg) v, options(nostack, nomem));
    }
    (v >> 2) & 0b11
}
