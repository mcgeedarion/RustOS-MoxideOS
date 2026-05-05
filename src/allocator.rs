//! Global heap allocator — backed by the PMM.
//!
//! We use a simple linked-list allocator from the `linked_list_allocator`
//! crate sitting on top of a fixed-size heap carved from the PMM pool.
//!
//! ## Contiguity guarantee
//! The heap requires a single physically-contiguous region.  We obtain
//! it by computing the address directly from the PMM's static `POOL`
//! array and advancing the bump index in one atomic step, rather than
//! calling `alloc_page()` in a loop and hoping the pages are adjacent.
//!
//! ### Calling order invariant
//! `heap_init()` MUST be called before `pmm_add_region()` ever runs.
//! At that point the free list is still empty, so the bump allocator
//! is the only path — pages 0..HEAP_PAGES come out of `POOL` in
//! address order with no gaps.  An assertion enforces this.
//!
//! The heap is 8 MiB, initialised once during early boot by
//! `heap_init()`.  After that all `alloc::` calls (Vec, Box, String, …)
//! are served from here.

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_PAGES: usize = 2048; // 8 MiB
const PAGE_SIZE:  usize = 4096;

/// Initialise the heap.  Call once, early in kernel_main, **before**
/// `pmm_add_region()` and before any code that uses `alloc::`.
pub fn heap_init() {
    // Grab HEAP_PAGES pages atomically from the bump pool.
    // `pmm_reserve_bump_range` returns the base PA of a contiguous
    // run taken directly from POOL, or panics if the pool is exhausted
    // or if the free list is already non-empty (calling-order violation).
    let start = crate::mm::pmm::reserve_bump_range(HEAP_PAGES)
        .expect("heap_init: PMM pool exhausted or called after pmm_add_region");

    let size = HEAP_PAGES * PAGE_SIZE;
    unsafe {
        ALLOCATOR.lock().init(start as *mut u8, size);
    }
}
