//! Fixed-size block allocator with a buddy-style fallback.

use super::buddy::BuddyAllocator;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use spin::Mutex;

const BLOCK_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];

#[repr(C)]
struct ListNode {
    next: Option<&'static mut ListNode>,
}

pub struct FixedSizeBlockAllocator {
    heads: [Option<&'static mut ListNode>; BLOCK_SIZES.len()],
    fallback: BuddyAllocator,
}

impl FixedSizeBlockAllocator {
    pub const fn new() -> Self {
        Self {
            heads: [None, None, None, None, None, None, None, None, None, None],
            fallback: BuddyAllocator::new(),
        }
    }

    pub unsafe fn init(&mut self, region_start: usize, region_size: usize) {
        self.fallback.init(region_start, region_size);
    }

    pub fn fallback_alloc_pub(&mut self, layout: Layout) -> *mut u8 {
        self.alloc_inner(layout)
    }

    fn alloc_inner(&mut self, layout: Layout) -> *mut u8 {
        match list_index(&layout) {
            Some(index) => match self.heads[index].take() {
                Some(node) => {
                    self.heads[index] = node.next.take();
                    node as *mut ListNode as *mut u8
                }
                None => self.alloc_fallback(
                    Layout::from_size_align(BLOCK_SIZES[index], BLOCK_SIZES[index]).unwrap(),
                ),
            },
            None => self.alloc_fallback(layout),
        }
    }

    unsafe fn dealloc_inner(&mut self, ptr: *mut u8, layout: Layout) {
        match list_index(&layout) {
            Some(index) => {
                let node = ptr as *mut ListNode;
                ptr::write(
                    node,
                    ListNode {
                        next: self.heads[index].take(),
                    },
                );
                self.heads[index] = Some(&mut *node);
            }
            None => {
                if let Some(ptr) = NonNull::new(ptr) {
                    self.fallback.deallocate(ptr, layout);
                }
            }
        }
    }

    fn alloc_fallback(&mut self, layout: Layout) -> *mut u8 {
        self.fallback
            .allocate(layout)
            .map_or(ptr::null_mut(), NonNull::as_ptr)
    }
}

unsafe impl Send for FixedSizeBlockAllocator {}

pub static FIXED_BLOCK_ALLOC: Mutex<FixedSizeBlockAllocator> =
    Mutex::new(FixedSizeBlockAllocator::new());

pub struct FixedSizeGlobalAlloc;

unsafe impl GlobalAlloc for FixedSizeGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        FIXED_BLOCK_ALLOC.lock().alloc_inner(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FIXED_BLOCK_ALLOC.lock().dealloc_inner(ptr, layout);
    }
}

fn list_index(layout: &Layout) -> Option<usize> {
    let required = layout.size().max(layout.align());
    BLOCK_SIZES.iter().position(|&size| size >= required)
}
