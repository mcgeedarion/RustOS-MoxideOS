//! CPU feature detection and MSR helpers.

use core::sync::atomic::{AtomicU32, Ordering};

pub const MSR_IA32_APIC_BASE: u32 = 0x1B;
pub const MSR_EFER: u32 = 0xC000_0080;
pub const MSR_STAR: u32 = 0xC000_0081;
pub const MSR_LSTAR: u32 = 0xC000_0082;
pub const MSR_FMASK: u32 = 0xC000_0084;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub const MSR_FS_BASE: u32 = 0xC000_0100;

#[inline(always)]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack));
    (hi as u64) << 32 | lo as u64
}

/// Read two MSRs in a single `asm!` block to avoid double serialization.
///
/// Each `rdmsr` has ~35-cycle latency and serializes the pipeline.  Two
/// back-to-back Rust calls to `rdmsr()` produce two separate `asm!` barriers
/// with no opportunity for any overlap.  Batching them in one block lets the
/// out-of-order engine start fetching `m2`'s result while `m1`'s `edx:eax`
/// merge is still propagating.
#[inline(always)]
pub unsafe fn rdmsr2(m1: u32, m2: u32) -> (u64, u64) {
    let (lo1, hi1, lo2, hi2): (u32, u32, u32, u32);
    core::arch::asm!(
        "mov ecx, {m1:e}",
        "rdmsr",
        "mov {lo1:e}, eax",
        "mov {hi1:e}, edx",
        "mov ecx, {m2:e}",
        "rdmsr",
        m1   = in(reg)  m1,
        m2   = in(reg)  m2,
        lo1  = out(reg) lo1,
        hi1  = out(reg) hi1,
        out("eax") lo2,
        out("edx") hi2,
        out("ecx") _,
        options(nostack)
    );
    (
        (hi1 as u64) << 32 | lo1 as u64,
        (hi2 as u64) << 32 | lo2 as u64,
    )
}

#[inline(always)]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    core::arch::asm!("wrmsr",
        in("ecx") msr, in("eax") val as u32, in("edx") (val >> 32) as u32,
        options(nostack));
}

/// Cached `cpuid` leaf-1 ECX result (bits used by `has_xsave` / `has_avx`).
/// Initialised to `u32::MAX` as a sentinel meaning "not yet read".
/// Set once at boot before SMP bring-up — no race possible.
static CPUID1_ECX: AtomicU32 = AtomicU32::new(u32::MAX);

/// Execute a raw `cpuid` instruction.  Avoid calling this in hot paths;
/// use the cached helpers below instead.
#[inline(always)]
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx);
    unsafe {
        core::arch::asm!("cpuid",
            inout("eax") leaf => eax, out("ebx") ebx,
            out("ecx") ecx,  out("edx") edx, options(nostack));
    }
    (eax, ebx, ecx, edx)
}

/// Return the cached ECX value for `cpuid(1)`.
///
/// The first call executes `cpuid` and stores the result; subsequent calls
/// return the cached value without touching the serializing instruction.
/// `cpuid` drains the entire reorder buffer (~200 cycles); caching avoids
/// paying that cost more than once.
#[inline]
fn cpuid1_ecx() -> u32 {
    let cached = CPUID1_ECX.load(Ordering::Relaxed);
    if cached != u32::MAX {
        return cached;
    }
    let ecx = cpuid(1).2;
    CPUID1_ECX.store(ecx, Ordering::Relaxed);
    ecx
}

pub fn has_xsave() -> bool {
    cpuid1_ecx() & (1 << 26) != 0
}
pub fn has_avx() -> bool {
    cpuid1_ecx() & (1 << 28) != 0
}
