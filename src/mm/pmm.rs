//! Physical memory manager (PMM).
//!
//! A two-tier allocator:
//!   1. Bump allocator consuming a 64 MiB static pool (POOL[]).
//!      Used for all allocations until the pool is exhausted.
//!   2. Free list (LIFO stack) for pages returned by free_page().
//!
//! alloc_page() -> Option<usize>  — returns a 4096-byte-aligned PA or None.
//! free_page(pa: usize)           — returns a page to the free list.
//!
//! The pool is identity-mapped (PA == VA) for the kernel.

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

const POOL_PAGES: usize = 16_384;   // 64 MiB
const PAGE_SIZE:  usize = 4096;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);

static BUMP: AtomicUsize = AtomicUsize::new(0);
static FREE_LIST: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Allocate one 4096-byte page.  Returns the physical (identity-mapped) address.
pub fn alloc_page() -> Option<usize> {
    if let Some(pa) = FREE_LIST.lock().pop() {
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        return Some(pa);
    }
    let idx = BUMP.fetch_add(1, Ordering::Relaxed);
    if idx >= POOL_PAGES { BUMP.fetch_sub(1, Ordering::Relaxed); return None; }
    let pa = POOL.0.as_ptr() as usize + idx * PAGE_SIZE;
    Some(pa)
}

/// Return a page to the free list for reuse.
pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    FREE_LIST.lock().push(pa);
}

/// Total pages allocated so far (for diagnostics).
pub fn pages_allocated() -> usize { BUMP.load(Ordering::Relaxed) }
