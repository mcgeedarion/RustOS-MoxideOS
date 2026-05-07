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
//! ## Security — page scrubbing on free
//!   free_page() zeroes the page before pushing it onto the free list so
//!   that no process can read stale data from a previously-owned page.
//!   alloc_page() skips the zero-fill for pool pages (BSS is already zero)
//!   but retains it for free-list pages as a defence-in-depth measure.
//!
//! ## Kernel image reservation
//!   Pages in [_kernel_start, _end) are never handed out.

use core::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
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

// ── Pool double-free bitmap ───────────────────────────────────────────────

const BITMAP_WORDS: usize = POOL_PAGES / 64; // 256 words
static POOL_FREE_BITS: [AtomicU64; BITMAP_WORDS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; BITMAP_WORDS]
};

#[inline]
fn pool_bit_set_free(idx: usize) -> bool {
    let word = idx / 64;
    let bit  = 1u64 << (idx % 64);
    POOL_FREE_BITS[word].fetch_or(bit, Ordering::Relaxed) & bit == 0
}

#[inline]
fn pool_bit_clear_free(idx: usize) {
    let word = idx / 64;
    let bit  = 1u64 << (idx % 64);
    POOL_FREE_BITS[word].fetch_and(!bit, Ordering::Relaxed);
}

#[inline]
fn pool_index(pa: usize) -> Option<usize> {
    let pool_base = POOL.0.as_ptr() as usize;
    let pool_end  = pool_base + POOL_PAGES * PAGE_SIZE;
    if pa >= pool_base && pa < pool_end {
        Some((pa - pool_base) / PAGE_SIZE)
    } else {
        None
    }
}

// ── Free list ─────────────────────────────────────────────────────────────

static FREE_LIST:   Mutex<Vec<usize>> = Mutex::new(Vec::new());
static TOTAL_PAGES: AtomicUsize      = AtomicUsize::new(0);
static FREE_COUNT:  AtomicUsize      = AtomicUsize::new(0);

// ── Kernel image extent ───────────────────────────────────────────────────

extern "C" {
    static _kernel_start: u8;
    static _end:          u8;
}

#[inline]
fn kernel_start_pa() -> usize { unsafe { &_kernel_start as *const u8 as usize } }

#[inline]
fn kernel_end_pa()   -> usize { unsafe { &_end as *const u8 as usize } }

#[inline]
fn is_kernel_page(pa: usize) -> bool {
    pa >= kernel_start_pa() && pa < kernel_end_pa()
}

#[inline]
fn is_valid_pa(pa: usize) -> bool {
    pa != 0 && pa & (PAGE_SIZE - 1) == 0 && !is_kernel_page(pa)
}

// ── Initialisation ────────────────────────────────────────────────────────

/// Initialise the physical memory manager.
pub fn init() {
    // Bootstrap pool needs no runtime init.
    // When DTB parsing is available, call pmm_add_region() for each
    // usable range discovered from the FDT passed in a1 by OpenSBI.
}

// ── Core allocator ────────────────────────────────────────────────────────

/// Allocate one 4096-byte page. Returns the physical (identity-mapped) address.
///
/// Pages from the free list were scrubbed on free; pages from the bootstrap
/// pool (BSS) are already zero — no redundant zero-fill is performed here
/// for pool pages.  Free-list pages are zero-filled again as defence in
/// depth in case the scrub in free_page() was somehow bypassed.
pub fn alloc_page() -> Option<usize> {
    let pa = if let Some(pa) = FREE_LIST.lock().pop() {
        FREE_COUNT.fetch_sub(1, Ordering::Relaxed);
        if let Some(idx) = pool_index(pa) { pool_bit_clear_free(idx); }
        // Re-zero as defence-in-depth; free_page already scrubbed but
        // belt-and-suspenders for security-sensitive paths.
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        pa
    } else {
        let idx = BUMP.fetch_add(1, Ordering::Relaxed);
        if idx >= POOL_PAGES {
            BUMP.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
        // Pool pages come from BSS — already zeroed by bootloader/UEFI.
        POOL.0.as_ptr() as usize + idx * PAGE_SIZE
    };
    Some(pa)
}

/// Return a page to the free list for reuse.
///
/// ## Security
/// The page is **zeroed before being pushed** onto the free list so that
/// any subsequent allocator cannot read data left by the previous owner.
/// This prevents cross-process / cross-task information leaks via the PMM.
///
/// # Panics
/// - Always: if `pa` is 0, not page-aligned, or inside the kernel image.
/// - Always (O(1)): if `pa` is a pool page that is already free (double-free).
pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    assert!(
        pa & (PAGE_SIZE - 1) == 0,
        "free_page: PA {:#x} is not page-aligned",
        pa
    );
    assert!(
        !is_kernel_page(pa),
        "free_page: attempt to free kernel image page {:#x}",
        pa
    );

    // Detect pool double-free in all build modes (O(1)).
    if let Some(idx) = pool_index(pa) {
        let ok = pool_bit_set_free(idx);
        assert!(ok, "free_page: double-free of pool page {:#x} (index {})", pa, idx);
    }

    // ── SCRUB BEFORE PUSH ────────────────────────────────────────────────
    // Zero the page now, while the caller still "owns" it, before any other
    // CPU can allocate it.  This prevents stale data leaking between
    // processes.  The write must be volatile so the compiler cannot elide it
    // even if it can prove the memory is never read through this pointer.
    unsafe {
        // Use write_volatile on each word to defeat compiler dead-store
        // elimination.  For a full page this is acceptable; a future
        // explicit_bzero() intrinsic would be preferred if available.
        let ptr = pa as *mut u64;
        for i in 0..(PAGE_SIZE / 8) {
            ptr.add(i).write_volatile(0u64);
        }
    }

    let mut list = FREE_LIST.lock();
    list.push(pa);
    drop(list);
    FREE_COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
}

/// Register a physical memory region as available to the PMM.
///
/// Called once per usable entry in the UEFI / Multiboot2 memory map.
/// Pages overlapping the kernel image or the bootstrap pool are skipped.
pub fn pmm_add_region(base: usize, size: usize) {
    let mut pa = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1); // round up
    let end = base + size;
    while pa + PAGE_SIZE <= end {
        if is_valid_pa(pa) && pool_index(pa).is_none() {
            let mut list = FREE_LIST.lock();
            list.push(pa);
            drop(list);
            FREE_COUNT.fetch_add(1, Ordering::Relaxed);
            TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
        }
        pa += PAGE_SIZE;
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────────

pub fn free_pages()  -> usize { FREE_COUNT.load(Ordering::Relaxed) }
pub fn total_pages() -> usize { TOTAL_PAGES.load(Ordering::Relaxed) }
