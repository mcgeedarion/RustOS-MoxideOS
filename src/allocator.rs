//! Global heap allocator — thin wrapper around the physical memory manager.
//!
//! Delegates all allocations to `pmm::alloc_bytes` / `pmm::free_bytes`.  The
//! PMM itself is a simple bump + free-list allocator seeded from the memory
//! map passed by the bootloader.

use core::alloc::{GlobalAlloc, Layout};
use crate::mm::pmm;

const MIN_ALIGN: usize = 16;

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(MIN_ALIGN);
        match pmm::alloc_bytes(size, layout.align()) {
            Some(ptr) => ptr.as_ptr(),
            None      => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(MIN_ALIGN);
        pmm::free_bytes(core::ptr::NonNull::new_unchecked(ptr), size);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: layout.align() is always a valid power-of-two alignment from
        // the original allocation.  new_size is caller-supplied; the only
        // theoretical failure is size overflow, which is not possible on a
        // 64-bit target.  Return null on error — GlobalAlloc contract permits it.
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l)  => l,
            Err(_) => return core::ptr::null_mut(),
        };
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            let copy_size = layout.size().min(new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
