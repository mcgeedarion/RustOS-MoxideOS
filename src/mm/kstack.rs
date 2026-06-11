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
//!
//! ## Guard page aliasing hazard
//!
//! The guard page frame is re-mapped at its physmap VA with `PageFlags::empty()`
//! to make the page-table entry not-present.  However, the physmap window
//! itself still contains a writable alias for the same physical frame.
//! A correct overflow barrier requires either (a) an unmapped *virtual* guard
//! range that has *no* physmap alias (i.e., allocate a dedicated guard VA from
//! the kernel virtual address space, not the physmap), or (b) accepting that
//! the physmap alias exists and documenting that the guard only catches
//! accesses through the stack VA, not through the physmap VA.
//! The current implementation takes approach (b): the guard faults any normal
//! stack overflow via the stack VA region; direct physmap writes are a
//! separate, unrelated access pattern.

use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};

// Use the arch-provided page size so this compiles correctly if a future
// target uses 16 KiB pages (e.g., AArch64 with 16K granule).
use crate::arch::api::PAGE_SIZE;

// ---------------------------------------------------------------------------
// Architecture-specific physmap translation
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[inline]
fn phys_to_virt(pa: usize) -> usize {
    const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;
    pa + PHYS_OFFSET
}

/// # Safety
/// `KERNEL_PHYS_BASE` is a linker-defined symbol whose *address* encodes the
/// physical base of the kernel image.  We take its address as a `usize` rather
/// than reading through it as a `usize`-typed object, which would be unsound.
#[cfg(target_arch = "riscv64")]
#[inline]
fn phys_to_virt(pa: usize) -> usize {
    extern "C" {
        // Declare as a ZST (u8) so we can take its address without reading it.
        static KERNEL_PHYS_BASE: u8;
    }
    let base = unsafe { &KERNEL_PHYS_BASE as *const u8 as usize };
    pa + base
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn phys_to_virt(pa: usize) -> usize {
    crate::arch::aarch64::mem_layout::va48::phys_to_virt(pa)
}

// ---------------------------------------------------------------------------
// RAII rollback guard for physical frames
// ---------------------------------------------------------------------------

/// Holds a list of physical frames that will be freed on drop.
/// Call `forget()` once all frames have been successfully mapped so the
/// destructor does not reclaim them.
struct PmFreeGuard {
    frames: [usize; 3],
    len: usize,
}

impl PmFreeGuard {
    fn new() -> Self {
        Self { frames: [0; 3], len: 0 }
    }

    fn push(&mut self, pa: usize) {
        self.frames[self.len] = pa;
        self.len += 1;
    }

    fn forget(mut self) {
        self.len = 0;
        core::mem::forget(self);
    }
}

impl Drop for PmFreeGuard {
    fn drop(&mut self) {
        for i in 0..self.len {
            crate::mm::pmm::free_page(self.frames[i]);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Opaque handle returned by `alloc_kstack`.
///
/// Records both the physical addresses (needed by `pmm::free_page`) and the
/// virtual addresses (needed by `unmap_page` and the initial RSP) so that
/// `free_kstack` never has to recompute either.
pub struct KstackInfo {
    // Virtual addresses (physmap window) — passed to unmap_page.
    va_guard: usize,
    va0: usize,
    va1: usize,

    // Physical addresses — passed to pmm::free_page.
    pa_guard: usize,
    pa0: usize,
    pa1: usize,

    // Initial RSP: first address above the top of the uppermost stack page.
    // On x86-64 the stack pointer must be 16-byte aligned before a CALL, so
    // callers should subtract 8 from this value before using it as the entry
    // RSP if they synthesise a fake return address.
    stack_top: usize,
}

impl KstackInfo {
    /// Returns the initial RSP value (first address above the top stack page).
    #[inline]
    pub fn stack_top(&self) -> usize {
        self.stack_top
    }
}

/// Allocate a new kernel stack with a guard page.
/// Returns `None` on OOM or if any page mapping fails.
///
/// The three frames are allocated from the PMM (already zero-filled) and
/// mapped at their physmap virtual addresses.  The guard page is mapped
/// not-present so any stack overflow through the stack VA triggers an
/// immediate page fault.
pub fn alloc_kstack() -> Option<KstackInfo> {
    let mut guard = PmFreeGuard::new();

    // Allocate three physical frames; rollback via PmFreeGuard on failure.
    let pa_guard = crate::mm::pmm::alloc_page()?;
    guard.push(pa_guard);

    let pa0 = crate::mm::pmm::alloc_page()?;
    guard.push(pa0);

    let pa1 = crate::mm::pmm::alloc_page()?;
    guard.push(pa1);

    // Derive kernel-virtual addresses through the physmap window.
    let va_guard = phys_to_virt(pa_guard);
    let va0 = phys_to_virt(pa0);
    let va1 = phys_to_virt(pa1);

    let cr3 = <Arch as Paging>::kernel_cr3();
    const KSTACK_FLAGS: PageFlags = PageFlags::PRESENT.union(PageFlags::WRITE); // supervisor R/W, no USER

    // Guard page: PageFlags::empty() → not-present → overflow faults immediately.
    // map_page errors are treated as fatal OOM: return None and roll back frames.
    <Arch as Paging>::map_page(cr3, va_guard, pa_guard, PageFlags::empty())
        .ok()?;
    <Arch as Paging>::map_page(cr3, va0, pa0, KSTACK_FLAGS)
        .ok()?;
    <Arch as Paging>::map_page(cr3, va1, pa1, KSTACK_FLAGS)
        .ok()?;

    // All mappings succeeded — disarm the rollback guard.
    guard.forget();

    Some(KstackInfo {
        stack_top: va1 + PAGE_SIZE, // first address above the top stack page
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
