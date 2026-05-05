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
//!   Pages in [_kernel_start, _end) are never handed out.
//!   Both symbols are exported by x86_64.ld; the load address is defined
//!   in exactly one place (the linker script) and flows here automatically.
//!
//! ## Safety invariant
//!   Every PA on the free list appears exactly once.
//!   In debug builds, free_page() asserts this before pushing.

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

// ── Bootstrap pool ───────────────────────────────────────────────────────────────────────────────────

const POOL_PAGES: usize = 16_384; // 64 MiB static pool
const PAGE_SIZE:  usize = 4096;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);

// ── Free list ─────────────────────────────────────────────────────────────────────────────────────

static FREE_LIST:   Mutex<Vec<usize>> = Mutex::new(Vec::new());
static TOTAL_PAGES: AtomicUsize      = AtomicUsize::new(POOL_PAGES);
/// Lock-free counter mirroring FREE_LIST.len(); avoids locking just for diagnostics.
static FREE_COUNT:  AtomicUsize      = AtomicUsize::new(0);

// ── Kernel image extent ──────────────────────────────────────────────────────────────────────────

// Both symbols are provided by x86_64.ld.
// Taking the address of a linker symbol gives its VA (= PA in identity-mapped
// kernels); the u8 value at that address is meaningless.
extern "C" {
    static _kernel_start: u8;
    static _end:          u8;
}

#[inline]
fn kernel_start_pa() -> usize { unsafe { &_kernel_start as *const u8 as usize } }

#[inline]
fn kernel_end_pa()   -> usize { unsafe { &_end as *const u8 as usize } }

/// True if `pa` falls inside the kernel binary image.
#[inline]
fn is_kernel_page(pa: usize) -> bool {
    pa >= kernel_start_pa() && pa < kernel_end_pa()
}

/// True if `pa` is a valid, page-aligned physical address that the PMM
/// is allowed to manage (non-zero, non-kernel).
#[inline]
fn is_valid_pa(pa: usize) -> bool {
    pa != 0 && pa & (PAGE_SIZE - 1) == 0 && !is_kernel_page(pa)
}

// ── Initialisation ────────────────────────────────────────────────────────────────────────────────

/// Initialise the physical memory manager.
///
/// The static bootstrap pool (`POOL`) is self-initialising — `BUMP` and
/// `FREE_LIST` are valid the moment the BSS is zeroed by the boot stub.
/// This function exists as a named call-site for `kernel_main` so that a
/// future DTB/UEFI memory-map walk can be wired in here without touching
/// the boot sequence.
///
/// Call this once, before any heap allocation.
pub fn init() {
    // Bootstrap pool needs no runtime init.
    // When DTB parsing is available, call pmm_add_region() for each
    // usable range discovered from the FDT passed in a1 by OpenSBI.
}

// ── Core allocator ─────────────────────────────────────────────────────────────────────────────────

/// Allocate one 4096-byte page. Returns the physical (identity-mapped) address.
/// The returned page is always zero-filled.
pub fn alloc_page() -> Option<usize> {
    let pa = if let Some(pa) = FREE_LIST.lock().pop() {
        FREE_COUNT.fetch_sub(1, Ordering::Relaxed);
        pa
    } else {
        let idx = BUMP.fetch_add(1, Ordering::Relaxed);
        if idx >= POOL_PAGES {
            BUMP.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        POOL.0.as_ptr() as usize + idx * PAGE_SIZE
    };
    // Zero the page so callers always receive clean memory.
    // This is the single authoritative zero; callers must NOT zero again.
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    Some(pa)
}

/// Return a page to the free list for reuse.
///
/// # Panics (debug builds only)
/// Panics if `pa` is already on the free list (double-free detection).
/// Also panics if `pa` is 0, not page-aligned, or inside the kernel image.
pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    assert!(
        pa & (PAGE_SIZE - 1) == 0,
        "free_page: PA {:#x} is not page-aligned",
        pa
    );
    assert!(
        !is_kernel_page(pa),
        "free_page: PA {:#x} is inside the kernel image [{:#x}, {:#x})",
        pa, kernel_start_pa(), kernel_end_pa()
    );

    let mut list = FREE_LIST.lock();

    #[cfg(debug_assertions)]
    assert!(
        !list.contains(&pa),
        "free_page: double-free of PA {:#x}",
        pa
    );

    list.push(pa);
    // Increment after the push so FREE_COUNT never exceeds FREE_LIST.len().
    FREE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Reserve `n` contiguous pages from the bump pool in one atomic step.
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

// ── Memory map ingestion ─────────────────────────────────────────────────────────────────────────

/// Register a usable physical memory region with the PMM.
pub fn pmm_add_region(base: u64, size: u64) {
    let pool_start = POOL.0.as_ptr() as u64;
    let pool_end   = pool_start + (POOL_PAGES * PAGE_SIZE) as u64;
    let kern_start = kernel_start_pa() as u64;
    let kern_end   = kernel_end_pa()   as u64;

    let start = (base + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let end   = (base + size) & !(PAGE_SIZE as u64 - 1);
    if start >= end { return; }

    let mut batch: Vec<usize> = Vec::new();
    let mut pa = start;
    while pa + PAGE_SIZE as u64 <= end {
        let pa_end   = pa + PAGE_SIZE as u64;
        let in_pool  = pa < pool_end  && pa_end > pool_start;
        let in_kern  = pa < kern_end  && pa_end > kern_start;
        let pa_usize = pa as usize;
        if !in_pool && !in_kern && is_valid_pa(pa_usize) {
            batch.push(pa_usize);
        }
        pa += PAGE_SIZE as u64;
    }

    let added = batch.len();
    FREE_LIST.lock().extend(batch);
    FREE_COUNT.fetch_add(added, Ordering::Relaxed);
    TOTAL_PAGES.fetch_add(added, Ordering::Relaxed);
}

// ── Diagnostics ────────────────────────────────────────────────────────────────────────────────────

pub fn total_pages()     -> usize { TOTAL_PAGES.load(Ordering::Relaxed) }
/// Lock-free: reads FREE_COUNT atomic instead of locking FREE_LIST.
pub fn free_pages()      -> usize { FREE_COUNT.load(Ordering::Relaxed) }
pub fn pages_allocated() -> usize { BUMP.load(Ordering::Relaxed) }
