//! Fixed-size block allocator with a buddy fallback.
//!
//! ## Design
//!
//! Requests up to 4096 bytes are routed to one of 10 segregated free lists
//! whose block sizes are powers of two: 8, 16, 32, 64, 128, 256, 512,
//! 1024, 2048, 4096.  The smallest class that satisfies both `size` and
//! `align` is selected.  Requests larger than 4096 bytes fall through to
//! the embedded `BuddyAllocator`.
//!
//! ## Free-list mechanics
//!
//! Each free block stores a `ListNode` in its first bytes.  `ListNode.next`
//! is a raw `Option<&'static mut ListNode>` — a non-null tagged pointer
//! stored directly in the freed memory, requiring zero heap metadata.
//!
//! On `alloc`:
//!   1. Find the class index.
//!   2. Pop the head of that class's free list.
//!   3. If the list is empty, request one block-sized allocation from the
//!      buddy allocator to serve as the new slot.
//!
//! On `dealloc`:
//!   1. Find the class index.
//!   2. Write a fresh `ListNode` into the freed memory.
//!   3. Push it onto the head of that class's free list.
//!   4. If the layout doesn't fit any class, delegate to `BuddyAllocator`.
//!
//! ## Usage as a GlobalAlloc
//!
//! Wrap `FixedSizeBlockAllocator` in a `spin::Mutex` and implement
//! `GlobalAlloc` on a zero-sized proxy type, or call `alloc`/`dealloc`
//! directly from your existing `KernelAllocator`.

use core::{
    alloc::{GlobalAlloc, Layout},
    mem,
    ptr::NonNull,
};
use spin::Mutex;
use super::buddy::BuddyAllocator;

// ── Block-size class table ─────────────────────────────────────────────────

/// Power-of-two block sizes served by the segregated free lists.
/// Every entry must be >= `mem::size_of::<ListNode>()` (currently 8 bytes)
/// and must be a power of two so it can also serve as alignment.
const BLOCK_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

/// Intrusive singly-linked free-list node.
/// Stored in the first bytes of every free block in its class list.
struct ListNode {
    next: Option<&'static mut ListNode>,
}

/// Return the index into `BLOCK_SIZES` for `layout`, i.e. the smallest
/// class index `i` such that `BLOCK_SIZES[i] >= max(layout.size(), layout.align())`.
/// Returns `None` if the request is larger than the largest class.
#[inline]
fn list_index(layout: &Layout) -> Option<usize> {
    let required = layout.size().max(layout.align());
    BLOCK_SIZES.iter().position(|&s| s >= required)
}

// ── Allocator state ────────────────────────────────────────────────────────

/// Fixed-size block allocator with a `BuddyAllocator` fallback.
pub struct FixedSizeBlockAllocator {
    /// Per-class free-list heads; `None` means the list is empty.
    list_heads: [Option<&'static mut ListNode>; BLOCK_SIZES.len()],
    /// Fallback for oversized requests and for refilling empty class lists.
    fallback_allocator: BuddyAllocator,
}

// SAFETY: All accesses are serialised by the outer `Mutex`.
unsafe impl Send for FixedSizeBlockAllocator {}
unsafe impl Sync for FixedSizeBlockAllocator {}

impl FixedSizeBlockAllocator {
    /// Create an uninitialised allocator.  Call `init` before use.
    pub const fn new() -> Self {
        // `Option<&'static mut T>` is not `Copy`, so we cannot write
        // `[None; N]`.  Use a const to work around this.
        const EMPTY: Option<&'static mut ListNode> = None;
        Self {
            list_heads:         [EMPTY; BLOCK_SIZES.len()],
            fallback_allocator: BuddyAllocator::new(),
        }
    }

    /// Initialise the fallback buddy allocator with a kernel heap region.
    ///
    /// # Safety
    /// `heap_start..heap_start+heap_size` must be valid, unused, writable
    /// memory for the lifetime of the kernel.
    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.fallback_allocator.init(heap_start, heap_size);
    }

    /// Allocate via the fallback buddy allocator.
    /// Returns null on OOM.
    #[inline]
    unsafe fn fallback_alloc(&mut self, layout: Layout) -> *mut u8 {
        match self.fallback_allocator.allocate(layout) {
            Some(p) => p.as_ptr(),
            None    => core::ptr::null_mut(),
        }
    }
}

// ── Global singleton ───────────────────────────────────────────────────────

/// Global fixed-size block allocator instance.
/// Initialise with `FIXED_BLOCK_ALLOC.lock().init(heap_start, heap_size)`
/// during kernel startup, before the first allocation.
pub static FIXED_BLOCK_ALLOC: Mutex<FixedSizeBlockAllocator> =
    Mutex::new(FixedSizeBlockAllocator::new());

// ── GlobalAlloc proxy ──────────────────────────────────────────────────────

/// Zero-sized proxy that implements `GlobalAlloc` via `FIXED_BLOCK_ALLOC`.
pub struct FixedSizeGlobalAlloc;

unsafe impl GlobalAlloc for FixedSizeGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut allocator = FIXED_BLOCK_ALLOC.lock();

        match list_index(&layout) {
            Some(index) => {
                match allocator.list_heads[index].take() {
                    Some(node) => {
                        // Pop the head node; its memory is the returned block.
                        allocator.list_heads[index] = node.next.take();
                        node as *mut ListNode as *mut u8
                    }
                    None => {
                        // Free list for this class is empty.
                        // Ask the buddy allocator for one fresh block.
                        let block_size  = BLOCK_SIZES[index];
                        // block_size is always a power of two, so it is a
                        // valid alignment value.
                        let block_layout =
                            Layout::from_size_align(block_size, block_size)
                                .expect("fixed_size_block: internal layout error");
                        allocator.fallback_alloc(block_layout)
                    }
                }
            }
            None => {
                // Request does not fit any fixed-size class — buddy path.
                allocator.fallback_alloc(layout)
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut allocator = FIXED_BLOCK_ALLOC.lock();

        match list_index(&layout) {
            Some(index) => {
                // Build a new list node in the freed memory, pointing to
                // the current head, then make this node the new head.
                let new_node = ListNode {
                    next: allocator.list_heads[index].take(),
                };

                // Sanity-check: the block must be large enough to hold
                // a ListNode (size and alignment).
                assert!(
                    mem::size_of::<ListNode>() <= BLOCK_SIZES[index],
                    "fixed_size_block: block class {} too small for ListNode",
                    index
                );
                assert!(
                    mem::align_of::<ListNode>() <= BLOCK_SIZES[index],
                    "fixed_size_block: block class {} alignment too strict for ListNode",
                    index
                );

                let new_node_ptr = ptr as *mut ListNode;
                new_node_ptr.write(new_node);
                allocator.list_heads[index] = Some(&mut *new_node_ptr);
            }
            None => {
                // Oversized deallocation — delegate to buddy.
                let ptr = NonNull::new(ptr).unwrap();
                allocator.fallback_allocator.deallocate(ptr, layout);
            }
        }
    }

    unsafe fn realloc(
        &self,
        ptr:      *mut u8,
        layout:   Layout,
        new_size: usize,
    ) -> *mut u8 {
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l)  => l,
            Err(_) => return core::ptr::null_mut(),
        };

        // Optimisation: if both old and new sizes map to the same fixed-size
        // class, the block is already large enough — return it unchanged.
        if let (Some(old_idx), Some(new_idx)) =
            (list_index(&layout), list_index(&new_layout))
        {
            if old_idx == new_idx {
                return ptr;
            }
        }

        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            let copy_len = layout.size().min(new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_len);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}
