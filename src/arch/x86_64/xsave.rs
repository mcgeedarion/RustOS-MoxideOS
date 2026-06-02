//! XSAVE / XRSTOR — save and restore x87/SSE/AVX floating-point state
//! on the signal stack.
//!
//! ## Why this matters
//!   The x86-64 ABI requires that signal handlers preserve XMM registers.
//!   If the kernel doesn't save/restore the FP context around signal
//!   delivery, a signal that fires inside a floating-point loop corrupts
//!   the computation silently.
//!
//! ## Feature detection
//!   We use CPUID to check for XSAVE (bit 26 of ECX from leaf 1).
//!   If absent we fall back to FXSAVE (always available on x86-64).
//!   XSAVE state size is queried via CPUID leaf 0xD, sub-leaf 0.
//!
//! ## Integration with signal delivery
//!   check_pending_signal() calls xsave_to_stack(sp) before redirecting
//!   rip, and rt_sigreturn() calls xrstor_from_stack(sp) after restoring
//!   the register frame.
//!
//! ## Stack layout addition
//!   The xsave area is placed immediately below the ucontext_t:
//!
//!     [xsave area]   XSAVE_SIZE bytes  ← 64-byte aligned
//!     [ucontext_t]   256 bytes
//!     [siginfo_t]     80 bytes
//!     [retaddr]        8 bytes
//!     ─── new rsp ───

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static XSAVE_SUPPORTED: AtomicBool = AtomicBool::new(false);
static XSAVE_SIZE:      AtomicU32  = AtomicU32::new(512); // FXSAVE default

/// Detect XSAVE support and measure the required state area size.
/// Call once during arch init, before any signal can be delivered.
pub fn xsave_init() {
    let (ecx, _edx) = cpuid_leaf1();
    let has_xsave = (ecx >> 26) & 1 != 0;

    if has_xsave {
        // CPUID leaf 0xD, sub-leaf 0, EBX = max XSAVE area size for current XCR0.
        let size = cpuid_xsave_size();
        XSAVE_SUPPORTED.store(true, Ordering::Relaxed);
        XSAVE_SIZE.store(size, Ordering::Relaxed);
        // Enable OSXSAVE in CR4 so XSAVE/XRSTOR are usable from supervisor mode.
        unsafe {
            core::arch::asm!(
                "mov rax, cr4",
                "or  rax, {cr4_osxsave}",
                "mov cr4, rax",
                cr4_osxsave = const 1usize << 18,
                out("rax") _,
            );
            // Set XCR0 to save x87 + SSE + AVX if available.
            // Bits: 0=x87, 1=SSE, 2=AVX
            let xcr0_current = xgetbv(0);
            let xcr0_new = xcr0_current | 0x7; // x87 + SSE + AVX
            xsetbv(0, xcr0_new);
        }
    }
}

/// Returns the number of bytes the XSAVE area needs, rounded up to 64.
pub fn xsave_area_size() -> usize {
    let base = XSAVE_SIZE.load(Ordering::Relaxed) as usize;
    (base + 63) & !63
}

/// Save the current thread's FP/SSE/AVX state to `dst`.
/// `dst` must be 64-byte aligned and at least `xsave_area_size()` bytes.
pub unsafe fn xsave_to(dst: *mut u8) {
    if XSAVE_SUPPORTED.load(Ordering::Relaxed) {
        core::arch::asm!(
            "xsave64 [{dst}]",
            dst = in(reg) dst,
            in("eax") 0xFFFF_FFFFu32,  // save all state components
            in("edx") 0xFFFF_FFFFu32,
        );
    } else {
        core::arch::asm!(
            "fxsave64 [{dst}]",
            dst = in(reg) dst,
        );
    }
}

/// Restore the FP/SSE/AVX state from `src`.
pub unsafe fn xrstor_from(src: *const u8) {
    if XSAVE_SUPPORTED.load(Ordering::Relaxed) {
        core::arch::asm!(
            "xrstor64 [{src}]",
            src = in(reg) src,
            in("eax") 0xFFFF_FFFFu32,
            in("edx") 0xFFFF_FFFFu32,
        );
    } else {
        core::arch::asm!(
            "fxrstor64 [{src}]",
            src = in(reg) src,
        );
    }
}

fn cpuid_leaf1() -> (u32, u32) {
    let ecx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "cpuid",
            in("eax") 1u32,
            lateout("ecx") ecx,
            lateout("edx") edx,
            lateout("ebx") _,
            lateout("eax") _,
        );
    }
    (ecx, edx)
}

fn cpuid_xsave_size() -> u32 {
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "cpuid",
            in("eax") 0xDu32,
            in("ecx") 0u32,
            lateout("ebx") ebx,
            lateout("eax") _,
            lateout("ecx") _,
            lateout("edx") _,
        );
    }
    ebx.max(512)
}

unsafe fn xgetbv(xcr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!("xgetbv", in("ecx") xcr, lateout("eax") lo, lateout("edx") hi);
    (hi as u64) << 32 | lo as u64
}

unsafe fn xsetbv(xcr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    core::arch::asm!("xsetbv", in("ecx") xcr, in("eax") lo, in("edx") hi);
}
