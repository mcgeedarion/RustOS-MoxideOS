//! Physical memory manager (PMM) — Phase 2: real memory map support.
//!
//! ## Two-tier design (unchanged externally)
//!
//! Tier 1 — Static bootstrap pool (64 MiB hardcoded).
//!   Used for all allocations that happen before pmm_add_region() is called
//!   (heap init, page tables, GDT/IDT structures).  The bump index walks
//!   forward; pages freed during this phase go to the free list.
//!
//! Tier 2 — Free list fed by the boot memory map.
//!   pmm_add_region(base, size) is called once per usable memory range
//!   from the UEFI memory map or Multiboot2 mmap tag.  It pushes every
//!   4 KiB-aligned page that doesn't overlap the kernel image onto the
//!   free list, making all available RAM accessible to alloc_page().
//!
//! ## Kernel image reservation
//!   We skip pages in [_KERNEL_START, _kernel_end) so we don't hand out
//!   pages that the kernel binary currently occupies.
//!   _KERNEL_START = 0x400000 (load address from x86_64.ld).
//!   _kernel_end   = extern symbol set by the linker.
//!
//! ## New functions added
//!   pmm_add_region(base: u64, size: u64)  — feed a usable RAM range
//!   total_pages() -> usize                — total pages known to PMM
//!   free_pages()  -> usize                — pages currently free

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

// ── Bootstrap pool ────────────────────────────────────────────────────────

const POOL_PAGES: usize = 16_384;   // 64 MiB static pool
const PAGE_SIZE:  usize = 4096;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);

// ── Free list (tier 2) ────────────────────────────────────────────────────

static FREE_LIST:   Mutex<Vec<usize>> = Mutex::new(Vec::new());
static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(POOL_PAGES);

// ── Kernel image extent ───────────────────────────────────────────────────

const KERNEL_START_PA: usize = 0x400000;
extern "C" { static _end: u8; } // provided by x86_64.ld

#[inline]
fn kernel_end_pa() -> usize {
    unsafe { &_end as *const u8 as usize }
}

// ── Core allocator ────────────────────────────────────────────────────────

/// Allocate one 4096-byte page. Returns the physical (identity-mapped) address.
pub fn alloc_page() -> Option<usize> {
    // Try free list first (tier 2 pages + returned tier 1 pages).
    if let Some(pa) = FREE_LIST.lock().pop() {
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        return Some(pa);
    }
    // Fall back to bump pool.
    let idx = BUMP.fetch_add(1, Ordering::Relaxed);
    if idx >= POOL_PAGES {
        BUMP.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    let pa = POOL.0.as_ptr() as usize + idx * PAGE_SIZE;
    Some(pa)
}

/// Return a page to the free list for reuse.
pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    FREE_LIST.lock().push(pa);
}

// ── Memory map ingestion (Phase 2) ────────────────────────────────────────

/// Register a usable physical memory region with the PMM.
///
/// Call once per "usable" entry from:
///   - UEFI memory map  (EfiConventionalMemory, type 7)
///   - Multiboot2 mmap  (entry type 1 = available)
///
/// Skips pages that overlap the static bootstrap pool or the kernel image.
/// Safe to call multiple times with overlapping ranges (deduplication is
/// not done — callers should only pass non-overlapping usable ranges).
pub fn pmm_add_region(base: u64, size: u64) {
    let pool_start = POOL.0.as_ptr() as u64;
    let pool_end   = pool_start + (POOL_PAGES * PAGE_SIZE) as u64;
    let kern_start = KERNEL_START_PA as u64;
    let kern_end   = kernel_end_pa() as u64;

    // Align base up, end down to 4 KiB boundaries.
    let start = (base + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let end   = (base + size) & !(PAGE_SIZE as u64 - 1);
    if start >= end { return; }

    let mut added = 0usize;
    let mut pa = start;
    while pa + PAGE_SIZE as u64 <= end {
        let pa_end = pa + PAGE_SIZE as u64;
        // Skip bootstrap pool.
        let in_pool = pa < pool_end && pa_end > pool_start;
        // Skip kernel image.
        let in_kern = pa < kern_end  && pa_end > kern_start;
        if !in_pool && !in_kern {
            FREE_LIST.lock().push(pa as usize);
            added += 1;
        }
        pa += PAGE_SIZE as u64;
    }
    TOTAL_PAGES.fetch_add(added, Ordering::Relaxed);
}

// ── Diagnostics ───────────────────────────────────────────────────────────

/// Total pages known to the PMM (pool + all added regions).
pub fn total_pages() -> usize {
    TOTAL_PAGES.load(Ordering::Relaxed)
}

/// Pages currently on the free list.
pub fn free_pages() -> usize {
    FREE_LIST.lock().len()
}

/// Bump pages allocated so far (from the static pool).
pub fn pages_allocated() -> usize {
    BUMP.load(Ordering::Relaxed)
}
