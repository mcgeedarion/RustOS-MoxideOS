//! Address Space Layout Randomisation (ASLR).
//!
//! Produces per-process random offsets for:
//!   - stack base     (`aslr_stack_offset`)       — up to 8 MiB (2 MiB aligned)
//!   - heap base      (`aslr_heap_base`)           — randomised in [HEAP_MIN, HEAP_MAX)
//!   - mmap region    (`aslr_mmap_base`)           — randomised in [MMAP_MIN, MMAP_MAX)
//!   - vDSO / vvar    (`aslr_vdso_base`)           — 1-page slot inside mmap window
//!
//! Entropy source: `rand::rdrand64()` (RDRAND on x86_64, reading `mcycle`
//! XOR `minstret` on RISC-V).  Falls back to a LCG seeded from TSC if
//! RDRAND is unavailable.
//!
//! Alignment: all returned addresses are 2 MiB aligned so huge-pages can
//! back the regions without ASLR defeating the alignment requirement.

use crate::rand::rdrand64;

// ───── Virtual address regions (userspace, 48-bit canonical) ──────────────────

/// Lowest allowed userspace stack base.
const STACK_MIN: u64 = 0x0000_7000_0000_0000;
/// Highest allowed userspace stack base (below kernel half).
const STACK_MAX: u64 = 0x0000_7FFF_FFFF_0000;
/// Maximum random stack shift: 8 MiB in 2 MiB steps → 4 choices.
const STACK_RAND_PAGES: u64 = 4; // units of 2 MiB

/// Default stack top (top of user VA space minus a gap).
pub const STACK_TOP_DEFAULT: u64 = 0x0000_7FFF_FFFF_0000;

/// Randomised heap start: [0x10_0000_0000, 0x40_0000_0000).
const HEAP_MIN: u64 = 0x0000_0010_0000_0000;
const HEAP_MAX: u64 = 0x0000_0040_0000_0000;

/// Randomised mmap base: [0x100_0000_0000, 0x500_0000_0000).
const MMAP_MIN: u64 = 0x0000_0100_0000_0000;
const MMAP_MAX: u64 = 0x0000_0500_0000_0000;

/// Granularity of all random offsets (2 MiB = huge-page size).
const ALIGN: u64 = 2 * 1024 * 1024;

// ───── Public API ──────────────────────────────────────────────────────────────

/// Returns a random downward offset to subtract from the default stack top.
/// Result is a multiple of 2 MiB, in [0, 8 MiB].
pub fn aslr_stack_offset() -> u64 {
    let r = rdrand64();
    (r % STACK_RAND_PAGES) * ALIGN
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
/// Always `mmap_base + [0, 256 MiB)` so it stays near the mmap region.
pub fn aslr_vdso_base(mmap_base: u64) -> u64 {
    let slots = 256 * 1024 * 1024 / ALIGN; // 128 slots
    let off = (rdrand64() % slots) * ALIGN;
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

    /// For the initial kernel-thread / idle process: fixed layout, no
    /// randomisation (the kernel does not have a user stack).
    pub const fn kernel_fixed() -> Self {
        AslrLayout {
            stack_top: STACK_TOP_DEFAULT,
            heap_base: HEAP_MIN,
            mmap_base: MMAP_MIN,
            vdso_base: MMAP_MIN,
        }
    }
}

// ───── Internal helpers ───────────────────────────────────────────────────────

/// Return a uniformly-random, 2 MiB-aligned address in `[lo, hi)`.
fn rand_in_range(lo: u64, hi: u64) -> u64 {
    debug_assert!(hi > lo);
    let slots = (hi - lo) / ALIGN;
    lo + (rdrand64() % slots) * ALIGN
}
