//! SMEP / SMAP / UMIP enforcement.
//!
//! ## C4 fix - UMIP must be gated on CPUID
//! CR4 bit 11 (UMIP) is reserved on pre-Skylake CPUs and some hypervisors.
//! Writing a reserved CR4 bit causes a #GP, crashing the kernel at boot.
//! Fix: cpuid_cr4_features() returns (smep, smap, umip) by checking
//! CPUID leaf 7, sub-leaf 0, EBX bit 2. enforce() only sets CR4_UMIP
//! when umip == true.

use core::sync::atomic::{AtomicBool, Ordering};

pub static SMEP_ENABLED: AtomicBool = AtomicBool::new(false);
pub static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
pub const CR4_UMIP: u64 = 1 << 11;

/// Query CPUID leaf 7, sub-leaf 0 for SMEP (EBX[7]), SMAP (EBX[20]),
/// and UMIP (EBX[2]).
///
/// C4 fix: exposes UMIP so enforce() can gate the CR4 write on the flag.
#[cfg(target_arch = "x86_64")]
pub fn cpuid_cr4_features() -> (bool, bool, bool) {
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 7", "xor ecx, ecx", "cpuid",
            out("ebx") ebx, out("eax") _, out("ecx") _, out("edx") _,
            options(nostack)
        );
    }
    let smep = (ebx >> 7) & 1 != 0;
    let umip = (ebx >> 2) & 1 != 0; // C4 fix: was never checked
    let smap = (ebx >> 20) & 1 != 0;
    (smep, smap, umip)
}

/// Compatibility shim for callers that only need (smep, smap).
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn cpuid_smep_smap() -> (bool, bool) {
    let (s, m, _) = cpuid_cr4_features();
    (s, m)
}

/// Enable SMEP, SMAP, and (if supported) UMIP in CR4.
///
/// # Safety
/// Must be called with interrupts disabled.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enforce() {
    let (has_smep, has_smap, has_umip) = cpuid_cr4_features();
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    if has_smep {
        cr4 |= CR4_SMEP;
        SMEP_ENABLED.store(true, Ordering::Relaxed);
    } else {
        log::warn!("smep_smap: CPU does not support SMEP");
    }
    if has_smap {
        cr4 |= CR4_SMAP;
        SMAP_ENABLED.store(true, Ordering::Relaxed);
    } else {
        log::warn!("smep_smap: CPU does not support SMAP");
    }
    // C4 fix: only set UMIP when the CPU advertises support.
    if has_umip {
        cr4 |= CR4_UMIP;
        log::info!("smep_smap: UMIP enabled");
    } else {
        log::warn!("smep_smap: CPU does not support UMIP - skipping");
    }
    core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    log::info!(
        "smep_smap: CR4 updated: SMEP={} SMAP={} UMIP={}",
        has_smep,
        has_smap,
        has_umip
    );
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn enforce() {}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn stac() {
    if SMAP_ENABLED.load(Ordering::Relaxed) {
        core::arch::asm!("stac", options(nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn clac() {
    if SMAP_ENABLED.load(Ordering::Relaxed) {
        core::arch::asm!("clac", options(nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn stac() {}
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn clac() {}

#[cfg(all(target_arch = "x86_64", debug_assertions))]
#[inline]
pub unsafe fn assert_smep_smap_set() {
    let cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    if SMEP_ENABLED.load(Ordering::Relaxed) {
        debug_assert!(cr4 & CR4_SMEP != 0, "CR4.SMEP was cleared!");
    }
    if SMAP_ENABLED.load(Ordering::Relaxed) {
        debug_assert!(cr4 & CR4_SMAP != 0, "CR4.SMAP was cleared!");
    }
}

#[cfg(not(all(target_arch = "x86_64", debug_assertions)))]
#[inline(always)]
pub unsafe fn assert_smep_smap_set() {}

pub mod pfec {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const RSVD: u64 = 1 << 3;
    pub const INSTR_FETCH: u64 = 1 << 4;
    pub const PK: u64 = 1 << 5;
    pub const SHADOW_STACK: u64 = 1 << 6;
    pub const SGX: u64 = 1 << 15;
}

pub fn classify_violation(error_code: u64, fault_va: u64) -> Option<&'static str> {
    use pfec::*;
    if error_code & (PRESENT | INSTR_FETCH) == (PRESENT | INSTR_FETCH)
        && error_code & USER == 0
        && fault_va < 0x0000_8000_0000_0000
    {
        return Some("SMEP");
    }
    if error_code & (PRESENT | USER) == PRESENT
        && error_code & INSTR_FETCH == 0
        && fault_va < 0x0000_8000_0000_0000
    {
        return Some("SMAP");
    }
    None
}
