//! Kernel stack allocator.
//!
//! Layout for each kernel stack (addresses grow downward):
//!
//!   [guard_page]  4 KiB  mapped PROT_NONE (not present) — overflow sentinel
//!   [page0]       4 KiB  supervisor R/W
//!   [page1]       4 KiB  supervisor R/W   ← RSP starts here (kstack_top)
//!
//! Each physical frame is allocated from the PMM (which guarantees zero-fill)
//! and mapped at its kernel-virtual address via the architecture's flat
//! physmap (PHYS_OFFSET on x86-64, KERNEL_PHYS_BASE on RISC-V).
//!
//! `alloc_kstack()` returns a `KstackInfo` that records both the physical
//! addresses (for PMM free) and the virtual addresses (for unmap_page and
//! the initial RSP).  `free_kstack()` uses those records directly — never
//! pointer arithmetic — so the allocator is correct even when VA != PA.

use crate::arch::{Arch, api::{Paging, PageFlags}};

const PAGE: usize = 4096;

// ── Physical-to-virtual translation (physmap window) ──────────────────────────
//
// Kernel stack frames are accessed through the same flat-offset physmap used
// by heap.rs and cow_fault.rs.  No separate map_page() call is needed for
// the data pages on either architecture because the physmap covers all of
// physical RAM from boot.  The guard page is mapped explicitly at its physmap
// VA with PageFlags::empty() so that any overflow faults immediately.

#[cfg(target_arch = "x86_64")]
#[inline]
fn phys_to_virt(pa: usize) -> usize {
    const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;
    pa + PHYS_OFFSET
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn phys_to_virt(pa: usize) -> usize {
    extern "C" { static KERNEL_PHYS_BASE: usize; }
    unsafe { pa + KERNEL_PHYS_BASE }
}

// ── Public types ───────────────────────────────────────────────────────────────────

/// Opaque handle returned by `alloc_kstack`.
///
/// Records both the physical addresses (needed by `pmm::free_page`) and the
/// virtual addresses (needed by `unmap_page` and the initial RSP) so that
/// `free_kstack` never has to recompute either.
pub struct KstackInfo {
    /// Initial RSP value: one byte past the top of the second stack page.
    pub top: usize,

    // Virtual addresses (physmap window) — passed to unmap_page.
    va_guard: usize,
    va0:      usize,
    va1:      usize,

    // Physical addresses — passed to pmm::free_page.
    pa_guard: usize,
    pa0:      usize,
    pa1:      usize,
}

// ── Public API ───────────────────────────────────────────────────────────────────

/// Allocate a new kernel stack with a guard page.
/// Returns `None` on OOM.
///
/// The three pages are allocated from the PMM (already zero-filled) and mapped
/// at their physmap virtual addresses.  The guard page is mapped not-present
/// so any stack overflow triggers an immediate page fault.
pub fn alloc_kstack() -> Option<KstackInfo> {
    // Allocate three physical frames.  Roll back on partial OOM.
    let pa_guard = crate::mm::pmm::alloc_page()?;
    let pa0 = match crate::mm::pmm::alloc_page() {
        Some(p) => p,
        None => {
            crate::mm::pmm::free_page(pa_guard);
            return None;
        }
    };
    let pa1 = match crate::mm::pmm::alloc_page() {
        Some(p) => p,
        None => {
            crate::mm::pmm::free_page(pa_guard);
            crate::mm::pmm::free_page(pa0);
            return None;
        }
    };

    // Derive kernel-virtual addresses through the physmap window.
    // These are the VAs that map_page / unmap_page / the scheduler use.
    let va_guard = phys_to_virt(pa_guard);
    let va0      = phys_to_virt(pa0);
    let va1      = phys_to_virt(pa1);

    let cr3          = <Arch as Paging>::kernel_cr3();
    let kstack_flags = PageFlags::PRESENT | PageFlags::WRITE; // supervisor R/W, no USER

    // Guard page: PageFlags::empty() → not-present → overflow faults immediately.
    <Arch as Paging>::map_page(cr3, va_guard, pa_guard, PageFlags::empty());
    <Arch as Paging>::map_page(cr3, va0,      pa0,      kstack_flags);
    <Arch as Paging>::map_page(cr3, va1,      pa1,      kstack_flags);

    Some(KstackInfo {
        top: va1 + PAGE, // RSP starts one byte past the top of va1
        va_guard,
        va0,
        va1,
        pa_guard,
        pa0,
        pa1,
    })
}

/// Free a kernel stack previously returned by `alloc_kstack`.
///
/// Unmaps the three virtual pages (using the recorded VAs) and returns the
/// physical frames to the PMM (using the recorded PAs).  No pointer arithmetic
/// is used; the VAs and PAs are stored independently in `KstackInfo`.
pub fn free_kstack(info: KstackInfo) {
    let cr3 = <Arch as Paging>::kernel_cr3();

    // Unmap using virtual addresses (what map_page recorded in the page table).
    <Arch as Paging>::unmap_page(cr3, info.va_guard);
    <Arch as Paging>::unmap_page(cr3, info.va0);
    <Arch as Paging>::unmap_page(cr3, info.va1);

    // Return physical frames to the PMM.
    crate::mm::pmm::free_page(info.pa_guard);
    crate::mm::pmm::free_page(info.pa0);
    crate::mm::pmm::free_page(info.pa1);
}
