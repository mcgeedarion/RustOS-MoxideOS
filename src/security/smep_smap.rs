//! SMEP (Supervisor Mode Execution Prevention) and
//! SMAP (Supervisor Mode Access Prevention) enforcement.
//!
//! SMEP (CR4.SMEP, bit 20): prevents the CPU from executing code at
//! user-space virtual addresses while in ring 0.  Any #PF with
//! PFEC.I/D=fetch and the faulting VA in userspace triggers #GP instead.
//!
//! SMAP (CR4.SMAP, bit 21): prevents ring-0 code from *reading or writing*
//! user-space memory without explicitly setting RFLAGS.AC first (via STAC).
//! After the access, CLAC clears AC, re-arming the protection.
//!
//! This module:
//!   - Sets CR4.SMEP and CR4.SMAP at boot (and on every AP in `ap_entry`).
//!   - Provides `stac()` / `clac()` intrinsics used by `src/uaccess.rs`.
//!   - Hooks the page-fault handler to log SMEP/SMAP violations distinctly.
//!   - Asserts that SMEP/SMAP remain set on every context switch (debug).

use core::sync::atomic::{AtomicBool, Ordering};

/// Set to `true` once SMEP has been confirmed active on the BSP.
pub static SMEP_ENABLED: AtomicBool = AtomicBool::new(false);
/// Set to `true` once SMAP has been confirmed active on the BSP.
pub static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

// ───── CR4 bit positions ─────────────────────────────────────────────────────────
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
pub const CR4_UMIP: u64 = 1 <<  11; // User-Mode Instruction Prevention (bonus)

// ───── Capability probing ──────────────────────────────────────────────────────

/// Returns `(smep_supported, smap_supported)` by probing CPUID leaf 7.
#[cfg(target_arch = "x86_64")]
pub fn cpuid_smep_smap() -> (bool, bool) {
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            out("ebx") ebx,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack)
        );
    }
    let smep = (ebx >> 7) & 1 != 0;  // CPUID[7,0].EBX bit 7
    let smap = (ebx >> 20) & 1 != 0; // CPUID[7,0].EBX bit 20
    (smep, smap)
}

// ───── Enforcement init ──────────────────────────────────────────────────────────

/// Enable SMEP, SMAP, and UMIP in CR4 on the current CPU.
/// Called once on BSP from `security::init()` and once per AP from
/// `ap_entry()` (via `smep_smap::enforce()`).
///
/// # Safety
/// Must be called with interrupts disabled.  CR4 write serialises the
/// pipeline so no fence is needed before the function returns.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enforce() {
    let (has_smep, has_smap) = cpuid_smep_smap();
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
    // UMIP: prevents SGDT/SIDT/SLDT/SMSW/STR from userspace (info leak).
    cr4 |= CR4_UMIP;

    core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    log::info!("smep_smap: CR4 updated: SMEP={} SMAP={} UMIP=1", has_smep, has_smap);
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn enforce() { /* SMEP/SMAP are x86-64 specific */ }

// ───── STAC / CLAC wrappers for uaccess ────────────────────────────────────────

/// Set AC flag (RFLAGS.AC = 1): permit supervisor access to user pages.
/// Must be paired with an immediate `clac()` after the access window.
///
/// Usage pattern in uaccess.rs:
/// ```rust
/// unsafe {
///     stac();
///     let val = ptr::read_volatile(user_ptr);
///     clac();
/// }
/// ```
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn stac() {
    if SMAP_ENABLED.load(Ordering::Relaxed) {
        core::arch::asm!("stac", options(nostack, preserves_flags));
    }
}

/// Clear AC flag (RFLAGS.AC = 0): re-arm SMAP protection.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn clac() {
    if SMAP_ENABLED.load(Ordering::Relaxed) {
        core::arch::asm!("clac", options(nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)] pub unsafe fn stac() {}
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)] pub unsafe fn clac() {}

// ───── Context-switch integrity check (debug builds) ───────────────────────────

/// Assert that SMEP and SMAP are still set in CR4.  Called from the
/// context-switch path in debug builds to catch accidental CR4 corruption.
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

// ───── Page-fault classification helper ────────────────────────────────────────

/// Bit definitions for the x86_64 page-fault error code (pushed by CPU).
pub mod pfec {
    pub const PRESENT:      u64 = 1 << 0;
    pub const WRITE:        u64 = 1 << 1;
    pub const USER:         u64 = 1 << 2; // fault from CPL=3
    pub const RSVD:         u64 = 1 << 3;
    pub const INSTR_FETCH:  u64 = 1 << 4;
    pub const PK:           u64 = 1 << 5; // Protection Key violation
    pub const SHADOW_STACK: u64 = 1 << 6;
    pub const SGX:          u64 = 1 << 15;
}

/// Classify a page-fault error code as SMEP or SMAP violation.
/// Returns `Some("SMEP")`, `Some("SMAP")`, or `None`.
pub fn classify_violation(error_code: u64, fault_va: u64) -> Option<&'static str> {
    use pfec::*;
    // SMEP: supervisor instruction fetch from user page.
    if error_code & (PRESENT | INSTR_FETCH) == (PRESENT | INSTR_FETCH)
        && error_code & USER == 0
        && fault_va < 0x0000_8000_0000_0000
    {
        return Some("SMEP");
    }
    // SMAP: supervisor data access to user page without AC set.
    if error_code & (PRESENT | USER) == PRESENT
        && error_code & INSTR_FETCH == 0
        && fault_va < 0x0000_8000_0000_0000
    {
        return Some("SMAP");
    }
    None
}
