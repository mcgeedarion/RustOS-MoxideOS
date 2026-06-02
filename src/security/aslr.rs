//! Address Space Layout Randomisation (ASLR).
//!
//! Produces per-process random offsets for:
//!   - stack base     (`aslr_stack_offset`)  — randomised in full [STACK_MIN, STACK_TOP)
//!   - heap base      (`aslr_heap_base`)     — randomised in [HEAP_MIN, HEAP_MAX)
//!   - mmap region    (`aslr_mmap_base`)     — randomised in [MMAP_MIN, MMAP_MAX)
//!   - vDSO / vvar    (`aslr_vdso_base`)     — 1-page slot inside mmap window
//!
//! ## Entropy
//!
//! All four functions call `rand::arch_entropy()` (RDRAND on x86_64,
//! hardware CSR mix on RISC-V) rather than the xorshift PRNG.  This ensures
//! ASLR offsets are derived from hardware entropy and cannot be predicted
//! from observed program output.
//!
//! ## Stack entropy improvement
//!
//! Previous implementation used `STACK_RAND_PAGES = 4` (units of 2 MiB),
//! giving only 4 possible stack positions = 2 bits of entropy.
//!
//! The new implementation draws from the full
//! `[STACK_MIN, STACK_TOP_DEFAULT)` window in 2 MiB steps:
//!
//!   window = STACK_TOP_DEFAULT - STACK_MIN = 0x0FFF_FFFF_0000 bytes
//!   slots  = window / 2 MiB = 8191
//!   bits   = floor(log2(8191)) ≈ 13 bits of stack ASLR entropy
//!
//! This is a large improvement over 2 bits, though still below Linux's
//! 28-bit figure (which uses a 1-page = 4 KiB step granularity).  Moving
//! to 4 KiB steps would give ~22 bits but requires ensuring huge-page
//! backing does not break at non-2MiB-aligned stack tops.
//!
//! ## Alignment
//! All returned addresses remain 2 MiB aligned so huge-pages can back
//! the regions without ASLR defeating the alignment requirement.

use crate::rand::arch_entropy;

/// Default stack top (top of user VA space minus a guard gap).
pub const STACK_TOP_DEFAULT: u64 = 0x0000_7FFF_FFFF_0000;

/// Lower bound of the stack randomisation window.
/// Stack positions are chosen uniformly from [STACK_MIN, STACK_TOP_DEFAULT).
const STACK_MIN: u64 = 0x0000_7000_0000_0000;

/// Randomised heap start: [HEAP_MIN, HEAP_MAX).
const HEAP_MIN: u64 = 0x0000_0010_0000_0000;
const HEAP_MAX: u64 = 0x0000_0040_0000_0000;

/// Randomised mmap base: [MMAP_MIN, MMAP_MAX).
const MMAP_MIN: u64 = 0x0000_0100_0000_0000;
const MMAP_MAX: u64 = 0x0000_0500_0000_0000;

/// Granularity of all random offsets (2 MiB = huge-page size).
const ALIGN: u64 = 2 * 1024 * 1024;

/// Returns a random downward offset to subtract from `STACK_TOP_DEFAULT`.
///
/// Draws uniformly from the full `[STACK_MIN, STACK_TOP_DEFAULT)` window
/// in 2 MiB steps, giving ~13 bits of entropy (8191 possible positions)
/// compared to the previous 2 bits (4 positions).
pub fn aslr_stack_offset() -> u64 {
    // Number of 2 MiB slots between STACK_MIN and STACK_TOP_DEFAULT.
    // This is a compile-time constant: 8191.
    const STACK_SLOTS: u64 = (STACK_TOP_DEFAULT - STACK_MIN) / ALIGN;
    (arch_entropy() % STACK_SLOTS) * ALIGN
}

/// Returns a randomised heap start address, 2 MiB aligned.
pub fn aslr_heap_base() -> u64 {
    rand_in_range(HEAP_MIN, HEAP_MAX)
}

/// Returns a randomised mmap region base address, 2 MiB aligned.
pub fn aslr_mmap_base() -> u64 {
    rand_in_range(MMAP_MIN, MMAP_MAX)
}

/// Returns a randomised vDSO base within the mmap window.
/// Chosen from `mmap_base + [0, 256 MiB)` in 2 MiB steps (128 slots).
pub fn aslr_vdso_base(mmap_base: u64) -> u64 {
    const VDSO_SLOTS: u64 = 256 * 1024 * 1024 / ALIGN; // 128
    let off = (arch_entropy() % VDSO_SLOTS) * ALIGN;
    mmap_base + off
}

/// Per-process ASLR layout produced at `execve` time.
#[derive(Debug, Clone, Copy)]
pub struct AslrLayout {
    /// Actual stack top = `STACK_TOP_DEFAULT - stack_offset`.
    pub stack_top: u64,
    /// Heap starts here; `brk` is initially equal to this.
    pub heap_base: u64,
    /// `mmap(NULL, ...)` allocations start searching from here (downwards).
    pub mmap_base: u64,
    /// vDSO mapping address.
    pub vdso_base: u64,
}

impl AslrLayout {
    /// Generate a fresh randomised layout for a new process.
    pub fn generate() -> Self {
        let stack_top = STACK_TOP_DEFAULT - aslr_stack_offset();
        let heap_base = aslr_heap_base();
        let mmap_base = aslr_mmap_base();
        let vdso_base = aslr_vdso_base(mmap_base);
        AslrLayout { stack_top, heap_base, mmap_base, vdso_base }
    }

    /// Fixed layout for the kernel-thread / idle process (no user stack).
    pub const fn kernel_fixed() -> Self {
        AslrLayout {
            stack_top: STACK_TOP_DEFAULT,
            heap_base: HEAP_MIN,
            mmap_base: MMAP_MIN,
            vdso_base: MMAP_MIN,
        }
    }
}

/// Return a uniformly-random, 2 MiB-aligned address in `[lo, hi)`.
#[inline]
fn rand_in_range(lo: u64, hi: u64) -> u64 {
    debug_assert!(hi > lo);
    let slots = (hi - lo) / ALIGN;
    lo + (arch_entropy() % slots) * ALIGN
}
