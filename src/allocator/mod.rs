//! Allocator sub-modules.
//!
//! ## Module layout
//!
//! ```text
//! allocator/
//!   buddy.rs            — binary buddy allocator (4 KiB–16 MiB blocks)
//!   fixed_size_block.rs — segregated free-list allocator with buddy fallback
//!   stats.rs            — runtime diagnostics (free-list depths, fragmentation)
//!   tests.rs            — unit tests (cfg(test) only)
//! ```
//!
//! ## Initialisation (called from mm::heap::init)
//!
//! ```rust
//! // After the linked_list_allocator is up:
//! crate::allocator::init(heap_virt_start, heap_pages * 4096);
//! ```
//!
//! This donates a portion of the heap to the fixed-size block allocator's
//! internal buddy fallback so it can serve requests without immediately
//! hitting the PMM for every empty slab refill.

pub mod buddy;
pub mod fixed_size_block;
pub mod stats;

#[cfg(test)]
pub mod tests;

use fixed_size_block::FIXED_BLOCK_ALLOC;

/// Initialise the fixed-size block allocator and its buddy fallback.
///
/// `region_start` and `region_size` carve a slice of already-mapped virtual
/// memory (typically from the kernel heap) and donate it to the buddy layer
/// inside `FIXED_BLOCK_ALLOC`.  The region does **not** need to be physically
/// contiguous — `BuddyAllocator::init` splits it into maximally-aligned chunks.
///
/// Call this once, after `mm::heap::init()` has made virtual memory available
/// but before any kernel subsystem that may trigger a large allocation.
///
/// # Safety
/// `region_start..region_start+region_size` must be valid, writable,
/// exclusively-owned kernel virtual memory for the lifetime of the kernel.
pub unsafe fn init(region_start: usize, region_size: usize) {
    FIXED_BLOCK_ALLOC.lock().init(region_start, region_size);
}
