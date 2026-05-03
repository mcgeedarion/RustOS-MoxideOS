//! Global heap allocator — backed by the PMM.
//!
//! We use a simple linked-list allocator from the `linked_list_allocator`
//! crate sitting on top of a fixed-size heap carved from the PMM pool.
//!
//! The heap is 8 MiB, initialised once during early boot by
//! `heap_init()`.  After that all `alloc::` calls (Vec, Box, String, …)
//! are served from here.

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_PAGES: usize = 2048; // 8 MiB

/// Initialise the heap.  Call once, early in kernel_main, before any
/// code that uses `alloc::`.  The PMM must be ready (it always is,
/// since it uses a static pool).
pub fn heap_init() {
    let mut start = 0usize;
    // Carve HEAP_PAGES pages from the PMM.
    for i in 0..HEAP_PAGES {
        let pa = crate::mm::pmm::alloc_page()
            .expect("OOM during heap_init");
        if i == 0 { start = pa; }
        // Pages are contiguous only if the PMM bump allocator is used
        // sequentially, which it is at this point (free list is empty).
    }
    let size = HEAP_PAGES * 4096;
    unsafe {
        ALLOCATOR.lock().init(start as *mut u8, size);
    }
}
