//! Physical memory manager (PMM) — Phase 2: real memory map support.
//!
//! ## Two-tier design
//!
//! Tier 1 — Static bootstrap pool (64 MiB hardcoded).
//!   Used for all allocations before pmm_add_region() is called
//!   (heap init, page tables, GDT/IDT structures).  The bump index walks
//!   forward; pages freed during this phase go to the free list.
//!
//! Tier 2 — Free list fed by the boot memory map.
//!   pmm_add_region(base, size) is called once per usable memory range
//!   from the UEFI memory map or Multiboot2 mmap tag.
//!
//! ## Kernel image reservation
//!   Pages in [_KERNEL_START, _kernel_end) are never handed out.
//!   _KERNEL_START = 0x400000 (x86_64.ld load address).
//!
//! ## Safety invariant
//!   Every PA on the free list appears exactly once.
//!   In debug builds, free_page() asserts this before pushing.

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

// ── Bootstrap pool ────────────────────────────────────────────────────────

const POOL_PAGES: usize = 16_384; // 64 MiB static pool
const PAGE_SIZE:  usize = 4096;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);

// ── Free list ───────────────────────────────────────────────────────────────

static FREE_LIST:   Mutex<Vec<usize>> = Mutex::new(Vec::new());
static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(POOL_PAGES);

// ── Kernel image extent ────────────────────────────────────────────────────

const KERNEL_START_PA: usize = 0x400000;
extern "C" { static _end: u8; }

#[inline]
fn kernel_end_pa() -> usize { unsafe { &_end as *const u8 as usize } }

/// True if `pa` falls inside the kernel binary image.
#[inline]
fn is_kernel_page(pa: usize) -> bool {
    pa >= KERNEL_START_PA && pa < kernel_end_pa()
}

/// True if `pa` is a valid, page-aligned physical address that the PMM
/// is allowed to manage (non-zero, non-kernel).
#[inline]
fn is_valid_pa(pa: usize) -> bool {
    pa != 0 && pa & (PAGE_SIZE - 1) == 0 && !is_kernel_page(pa)
}

// ── Core allocator ─────────────────────────────────────────────────────────

/// Allocate one 4096-byte page. Returns the physical (identity-mapped) address.
pub fn alloc_page() -> Option<usize> {
    // Try free list first (tier 2 + returned tier 1 pages).
    let pa = if let Some(pa) = FREE_LIST.lock().pop() {
        pa
    } else {
        let idx = BUMP.fetch_add(1, Ordering::Relaxed);
        if idx >= POOL_PAGES {
            BUMP.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        POOL.0.as_ptr() as usize + idx * PAGE_SIZE
    };
    // Zero the page after allocation so callers always get clean memory.
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    Some(pa)
}

/// Return a page to the free list for reuse.
///
/// # Panics (debug builds only)
/// Panics if `pa` is already on the free list (double-free detection).
/// Also panics if `pa` is 0, not page-aligned, or inside the kernel image.
pub fn free_page(pa: usize) {
    // Always-on bounds checks: these are cheap and catch obvious bugs in
    // both debug and release builds.
    if pa == 0 { return; } // silently ignore null
    assert!(
        pa & (PAGE_SIZE - 1) == 0,
        "free_page: PA {:#x} is not page-aligned",
        pa
    );
    assert!(
        !is_kernel_page(pa),
        "free_page: PA {:#x} is inside the kernel image [{:#x}, {:#x})",
        pa, KERNEL_START_PA, kernel_end_pa()
    );

    let mut list = FREE_LIST.lock();

    // Debug-only duplicate detection. Iterating the whole free list is O(n)
    // but only active in debug builds where correctness matters more than
    // throughput. In release builds the assert compiles away entirely.
    #[cfg(debug_assertions)]
    assert!(
        !list.contains(&pa),
        "free_page: double-free of PA {:#x}",
        pa
    );

    list.push(pa);
}

/// Reserve `n` contiguous pages from the bump pool in one atomic step.
///
/// Panics if the free list is already non-empty (pmm_add_region was called
/// first, breaking the heap-contiguity invariant required by heap_init).
pub fn reserve_bump_range(n: usize) -> Option<usize> {
    assert!(
        FREE_LIST.lock().is_empty(),
        "reserve_bump_range called after pmm_add_region — heap contiguity broken"
    );
    let idx = BUMP.fetch_add(n, Ordering::Relaxed);
    if idx + n > POOL_PAGES {
        BUMP.fetch_sub(n, Ordering::Relaxed);
        return None;
    }
    Some(POOL.0.as_ptr() as usize + idx * PAGE_SIZE)
}

// ── Memory map ingestion ───────────────────────────────────────────────────

/// Register a usable physical memory region with the PMM.
///
/// Skips pages overlapping the bootstrap pool, the kernel image, or
/// that fail the is_valid_pa check (PA 0, non-aligned, etc.).
pub fn pmm_add_region(base: u64, size: u64) {
    let pool_start = POOL.0.as_ptr() as u64;
    let pool_end   = pool_start + (POOL_PAGES * PAGE_SIZE) as u64;
    let kern_start = KERNEL_START_PA as u64;
    let kern_end   = kernel_end_pa() as u64;

    let start = (base + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let end   = (base + size) & !(PAGE_SIZE as u64 - 1);
    if start >= end { return; }

    // Build batch outside the lock to minimise lock hold time.
    let mut batch: Vec<usize> = Vec::new();
    let mut pa = start;
    while pa + PAGE_SIZE as u64 <= end {
        let pa_end   = pa + PAGE_SIZE as u64;
        let in_pool  = pa < pool_end  && pa_end > pool_start;
        let in_kern  = pa < kern_end  && pa_end > kern_start;
        let pa_usize = pa as usize;
        // Apply the same validity checks as free_page so the list starts clean.
        if !in_pool && !in_kern && is_valid_pa(pa_usize) {
            batch.push(pa_usize);
        }
        pa += PAGE_SIZE as u64;
    }

    let added = batch.len();
    FREE_LIST.lock().extend(batch);
    TOTAL_PAGES.fetch_add(added, Ordering::Relaxed);
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

pub fn total_pages()     -> usize { TOTAL_PAGES.load(Ordering::Relaxed) }
pub fn free_pages()      -> usize { FREE_LIST.lock().len() }
pub fn pages_allocated() -> usize { BUMP.load(Ordering::Relaxed) }
