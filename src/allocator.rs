//! Global heap allocator — backed by the PMM.
//!
//! We use a simple linked-list / slab allocator on top of the physical
//! memory manager.  Nothing fancy; correctness over performance.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::mm::pmm;

/// Minimum alignment we hand out (pointer-sized).
const MIN_ALIGN: usize = core::mem::size_of::<usize>();

/// The global allocator instance registered with `#[global_allocator]`.
pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(MIN_ALIGN);
        let align = layout.align().max(MIN_ALIGN);
        match pmm::alloc_bytes(size, align) {
            Some(p) => p.as_ptr(),
            None => ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(MIN_ALIGN);
        pmm::free_bytes(core::ptr::NonNull::new_unchecked(ptr), size);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align(new_size, layout.align())
            .expect("realloc: bad layout");
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            let copy_size = layout.size().min(new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}
