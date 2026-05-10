//! Fixed-size block allocator with a `BuddyAllocator` fallback.
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
//! Each free block stores a `ListNode` in its first bytes.  On `dealloc`:
//!   1. Determine class index from the layout.
//!   2. Write a `ListNode { next: current_head }` into the freed memory.
//!   3. Make this node the new class head.
//!
//! On `alloc`:
//!   1. Determine class index.
//!   2. Pop the head if non-null; otherwise request one fresh block from
//!      the buddy fallback.
//!   3. If no class matches, delegate directly to the buddy fallback.

use core::{
    alloc::{GlobalAlloc, Layout},
    mem,
    ptr::NonNull,
};
use spin::Mutex;
use super::buddy::BuddyAllocator;

// ── Block-size class table ─────────────────────────────────────────────────

const BLOCK_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

/// Intrusive singly-linked free-list node embedded in each free block.
struct ListNode {
    next: Option<&'static mut ListNode>,
}

/// Smallest class index `i` with `BLOCK_SIZES[i] >= max(size, align)`,
/// or `None` if the request exceeds 4096 bytes.
#[inline]
fn list_index(layout: &Layout) -> Option<usize> {
    let required = layout.size().max(layout.align());
    BLOCK_SIZES.iter().position(|&s| s >= required)
}

// ── Allocator state ────────────────────────────────────────────────────────

pub struct FixedSizeBlockAllocator {
    pub(crate) list_heads: [Option<&'static mut ListNode>; BLOCK_SIZES.len()],
    pub(crate) fallback_allocator: BuddyAllocator,
}

unsafe impl Send for FixedSizeBlockAllocator {}
unsafe impl Sync for FixedSizeBlockAllocator {}

impl FixedSizeBlockAllocator {
    pub const fn new() -> Self {
        const EMPTY: Option<&'static mut ListNode> = None;
        Self {
            list_heads:         [EMPTY; BLOCK_SIZES.len()],
            fallback_allocator: BuddyAllocator::new(),
        }
    }

    /// Initialise the buddy fallback with `heap_start..heap_start+heap_size`.
    ///
    /// # Safety
    /// The region must be valid, unused, writable kernel virtual memory.
    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.fallback_allocator.init(heap_start, heap_size);
    }

    /// Allocate via the fallback buddy allocator.  Returns null on OOM.
    #[inline]
    pub(crate) unsafe fn fallback_alloc(&mut self, layout: Layout) -> *mut u8 {
        match self.fallback_allocator.allocate(layout) {
            Some(p) => p.as_ptr(),
            None    => core::ptr::null_mut(),
        }
    }

    /// Public alias used by the test harness.
    #[cfg(test)]
    pub unsafe fn fallback_alloc_pub(&mut self, layout: Layout) -> *mut u8 {
        self.fallback_alloc(layout)
    }
}

// ── Global singleton ───────────────────────────────────────────────────────

pub static FIXED_BLOCK_ALLOC: Mutex<FixedSizeBlockAllocator> =
    Mutex::new(FixedSizeBlockAllocator::new());

// ── GlobalAlloc proxy ──────────────────────────────────────────────────────

/// Zero-sized proxy that routes `GlobalAlloc` calls through `FIXED_BLOCK_ALLOC`.
pub struct FixedSizeGlobalAlloc;

unsafe impl GlobalAlloc for FixedSizeGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut allocator = FIXED_BLOCK_ALLOC.lock();
        match list_index(&layout) {
            Some(index) => {
                match allocator.list_heads[index].take() {
                    Some(node) => {
                        allocator.list_heads[index] = node.next.take();
                        node as *mut ListNode as *mut u8
                    }
                    None => {
                        let sz = BLOCK_SIZES[index];
                        let block_layout = Layout::from_size_align(sz, sz)
                            .expect("fixed_size_block: internal layout");
                        allocator.fallback_alloc(block_layout)
                    }
                }
            }
            None => allocator.fallback_alloc(layout),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut allocator = FIXED_BLOCK_ALLOC.lock();
        match list_index(&layout) {
            Some(index) => {
                let new_node = ListNode {
                    next: allocator.list_heads[index].take(),
                };
                assert!(
                    mem::size_of::<ListNode>() <= BLOCK_SIZES[index],
                    "fixed_size_block: block class {} too small for ListNode", index
                );
                assert!(
                    mem::align_of::<ListNode>() <= BLOCK_SIZES[index],
                    "fixed_size_block: alignment mismatch in class {}", index
                );
                let new_node_ptr = ptr as *mut ListNode;
                new_node_ptr.write(new_node);
                allocator.list_heads[index] = Some(&mut *new_node_ptr);
            }
            None => {
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
        // Same class — block is already large enough; return it unchanged.
        if let (Some(old_idx), Some(new_idx)) = (list_index(&layout), list_index(&new_layout)) {
            if old_idx == new_idx { return ptr; }
        }
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}
