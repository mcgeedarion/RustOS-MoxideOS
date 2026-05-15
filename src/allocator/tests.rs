//! Unit tests for the buddy and fixed-size block allocators.
//!
//! Run with:
//! ```sh
//! cargo test --features <arch> -- allocator
//! ```
//!
//! All tests are `#[cfg(test)]` and operate on locally-constructed allocator
//! instances backed by on-stack memory, so they do not require the PMM or any
//! kernel-specific infrastructure.

use super::buddy::{block_size, required_order, BuddyAllocator, MAX_ORDER, PAGE_SIZE};
use core::alloc::Layout;
use core::ptr::NonNull;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Heap backing store for tests: 8 MiB, page-aligned.
#[repr(C, align(4096))]
struct TestHeap([u8; TEST_HEAP_BYTES]);
const TEST_HEAP_BYTES: usize = 8 * 1024 * 1024; // 8 MiB = 2048 pages
static mut TEST_HEAP: TestHeap = TestHeap([0u8; TEST_HEAP_BYTES]);

/// Build a `BuddyAllocator` initialised over `TEST_HEAP`.
/// # Safety: only call from single-threaded test contexts.
unsafe fn make_buddy() -> BuddyAllocator {
    let mut b = BuddyAllocator::new();
    let start = TEST_HEAP.0.as_mut_ptr() as usize;
    b.init(start, TEST_HEAP_BYTES);
    b
}

// ── required_order ─────────────────────────────────────────────────────────

#[test]
fn test_required_order_tiny() {
    // A 1-byte request should land on order 0 (4 KiB block).
    assert_eq!(required_order(1, 1), Some(0));
}

#[test]
fn test_required_order_one_page() {
    assert_eq!(required_order(PAGE_SIZE, PAGE_SIZE), Some(0));
}

#[test]
fn test_required_order_two_pages() {
    // 2 pages need order 1 (8 KiB block).
    assert_eq!(required_order(PAGE_SIZE + 1, 1), Some(1));
    assert_eq!(required_order(2 * PAGE_SIZE, 1), Some(1));
}

#[test]
fn test_required_order_max() {
    // Exactly 2^MAX_ORDER pages is still valid.
    let max_bytes = block_size(MAX_ORDER);
    assert_eq!(required_order(max_bytes, 1), Some(MAX_ORDER));
}

#[test]
fn test_required_order_too_large() {
    // One byte over the max should return None.
    let too_big = block_size(MAX_ORDER) + 1;
    assert_eq!(required_order(too_big, 1), None);
}

// ── block_size ─────────────────────────────────────────────────────────────

#[test]
fn test_block_size_monotone() {
    for order in 0..MAX_ORDER {
        assert!(block_size(order) < block_size(order + 1));
    }
}

#[test]
fn test_block_size_order0_is_page() {
    assert_eq!(block_size(0), PAGE_SIZE);
}

// ── BuddyAllocator: basic alloc / free ────────────────────────────────────

#[test]
fn test_buddy_alloc_and_free_order0() {
    unsafe {
        let mut b = make_buddy();
        let layout = Layout::from_size_align(1, 1).unwrap();
        let p = b.allocate(layout).expect("OOM on order-0 alloc");
        // Pointer must be non-null and page-aligned.
        assert!(!p.as_ptr().is_null());
        assert_eq!(p.as_ptr() as usize % PAGE_SIZE, 0);
        b.deallocate(p, layout);
    }
}

#[test]
fn test_buddy_alloc_multiple_order0() {
    unsafe {
        let mut b = make_buddy();
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let mut ptrs: [Option<NonNull<u8>>; 16] = [None; 16];
        for slot in ptrs.iter_mut() {
            *slot = Some(b.allocate(layout).expect("OOM"));
        }
        // All pointers must be distinct and page-aligned.
        for i in 0..ptrs.len() {
            for j in (i + 1)..ptrs.len() {
                assert_ne!(ptrs[i].unwrap().as_ptr(), ptrs[j].unwrap().as_ptr());
            }
            assert_eq!(ptrs[i].unwrap().as_ptr() as usize % PAGE_SIZE, 0);
        }
        for slot in ptrs.iter() {
            b.deallocate(slot.unwrap(), layout);
        }
    }
}

#[test]
fn test_buddy_coalesce() {
    unsafe {
        let mut b = make_buddy();
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        // Allocate two order-0 blocks that are buddies, free them both.
        // The buddy allocator should coalesce them into an order-1 block.
        let p0 = b.allocate(layout).expect("OOM p0");
        let p1 = b.allocate(layout).expect("OOM p1");
        b.deallocate(p0, layout);
        b.deallocate(p1, layout);
        // Now allocate an order-1 block — should succeed using the merged block.
        let big_layout = Layout::from_size_align(2 * PAGE_SIZE, 2 * PAGE_SIZE).unwrap();
        let big = b.allocate(big_layout).expect("OOM: coalesce didn't work");
        b.deallocate(big, big_layout);
    }
}

#[test]
fn test_buddy_oom_returns_none() {
    unsafe {
        let mut b = make_buddy();
        // Request something larger than TEST_HEAP_BYTES — must return None.
        let too_big = Layout::from_size_align(TEST_HEAP_BYTES + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert!(b.allocate(too_big).is_none());
    }
}

// ── FixedSizeBlockAllocator ────────────────────────────────────────────────

use super::fixed_size_block::FixedSizeBlockAllocator;

/// Build a `FixedSizeBlockAllocator` backed by `TEST_HEAP`.
unsafe fn make_fixed() -> FixedSizeBlockAllocator {
    let mut a = FixedSizeBlockAllocator::new();
    let start = TEST_HEAP.0.as_mut_ptr() as usize;
    a.init(start, TEST_HEAP_BYTES);
    a
}

#[test]
fn test_fixed_alloc_8() {
    unsafe {
        let mut a = make_fixed();
        let layout = Layout::from_size_align(8, 8).unwrap();
        // Directly call the inner alloc (not via GlobalAlloc, to avoid locks).
        let p = a.fallback_alloc_pub(layout);
        assert!(!p.is_null());
    }
}

#[test]
fn test_fixed_alloc_dealloc_roundtrip() {
    use core::alloc::GlobalAlloc;
    // FixedSizeGlobalAlloc goes through FIXED_BLOCK_ALLOC; test its
    // dealloc path via the public GlobalAlloc impl.
    unsafe {
        super::init(TEST_HEAP.0.as_mut_ptr() as usize, TEST_HEAP_BYTES);
        let alloc = super::fixed_size_block::FixedSizeGlobalAlloc;
        let layout = Layout::from_size_align(64, 64).unwrap();
        let ptr = alloc.alloc(layout);
        assert!(!ptr.is_null());
        alloc.dealloc(ptr, layout);
        // After a dealloc the head of the 64-byte class list is non-None.
        // Allocate again to verify the slot was recycled.
        let ptr2 = alloc.alloc(layout);
        assert!(!ptr2.is_null());
        // The recycled pointer should be the same address we just freed.
        assert_eq!(ptr, ptr2);
        alloc.dealloc(ptr2, layout);
    }
}

#[test]
fn test_fixed_large_falls_through_to_buddy() {
    use core::alloc::GlobalAlloc;
    unsafe {
        super::init(TEST_HEAP.0.as_mut_ptr() as usize, TEST_HEAP_BYTES);
        let alloc = super::fixed_size_block::FixedSizeGlobalAlloc;
        // 8 KiB > largest class (4096) — must fall through to buddy.
        let layout = Layout::from_size_align(8192, 8192).unwrap();
        let ptr = alloc.alloc(layout);
        assert!(!ptr.is_null());
        alloc.dealloc(ptr, layout);
    }
}
