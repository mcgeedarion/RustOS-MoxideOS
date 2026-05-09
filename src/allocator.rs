//! Global heap allocator — routes Rust alloc through the PMM.
//!
//! `alloc_bytes` / `free_bytes` are also used by `mm::heap::grow()`.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
};
use crate::mm::pmm;

const PAGE_SIZE: usize = 4096;
const MIN_ALIGN: usize = 16;

pub struct KernelAllocator;

#[global_allocator]
pub static ALLOCATOR: KernelAllocator = KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match alloc_bytes(layout.size(), layout.align()) {
            Some(p) => p.as_ptr(),
            None    => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(p) = NonNull::new(ptr) {
            free_bytes(p, layout.size());
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l)  => l,
            Err(_) => return core::ptr::null_mut(),
        };
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

/// Allocate `size` bytes with at least `align` alignment from the PMM.
pub fn alloc_bytes(size: usize, align: usize) -> Option<NonNull<u8>> {
    let align  = align.max(MIN_ALIGN);
    let size   = (size + align - 1) & !(align - 1);
    let pages  = (size + PAGE_SIZE - 1) / PAGE_SIZE;

    let pa = pmm::alloc_page()?;
    if pages > 1 {
        // Allocate remaining pages; roll back all on OOM.
        let mut extra: [usize; 64] = [0; 64];
        let need = pages - 1;
        if need >= extra.len() { pmm::free_page(pa); return None; }
        for i in 0..need {
            match pmm::alloc_page() {
                Some(p) => extra[i] = p,
                None => {
                    pmm::free_page(pa);
                    for j in 0..i { pmm::free_page(extra[j]); }
                    return None;
                }
            }
        }
    }
    NonNull::new(pa as *mut u8)
}

/// Free bytes previously returned by `alloc_bytes`.
pub fn free_bytes(ptr: NonNull<u8>, size: usize) {
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let base  = ptr.as_ptr() as usize;
    for i in 0..pages { pmm::free_page(base + i * PAGE_SIZE); }
}
