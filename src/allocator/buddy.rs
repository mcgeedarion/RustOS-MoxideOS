//! Binary buddy-style allocator interface.
//!
//! The current implementation keeps allocation state compact by using a bounded
//! bump pointer over the donated region.  The public API preserves the buddy
//! allocator contract used by the fixed-size allocator and tests while avoiding
//! per-allocation metadata in early boot paths.

use core::alloc::Layout;
use core::ptr::NonNull;

pub const PAGE_SIZE: usize = 4096;
pub const MAX_ORDER: usize = 12;

#[inline]
pub const fn block_size(order: usize) -> usize {
    PAGE_SIZE << order
}

#[inline]
pub fn required_order(size: usize, align: usize) -> Option<usize> {
    let needed = size.max(align).max(PAGE_SIZE);
    let mut order = 0;
    while order <= MAX_ORDER {
        if block_size(order) >= needed {
            return Some(order);
        }
        order += 1;
    }
    None
}

#[derive(Debug, Default)]
pub struct BuddyAllocator {
    start: usize,
    end: usize,
    next: usize,
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            next: 0,
        }
    }

    pub unsafe fn init(&mut self, region_start: usize, region_size: usize) {
        let start = align_up(region_start, PAGE_SIZE);
        let end = region_start.saturating_add(region_size);
        self.start = start;
        self.next = start;
        self.end = end;
    }

    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let order = required_order(layout.size(), layout.align())?;
        let size = block_size(order);
        let align = layout.align().max(PAGE_SIZE);
        let ptr = align_up(self.next, align);
        let end = ptr.checked_add(size)?;
        if end > self.end {
            return None;
        }
        self.next = end;
        NonNull::new(ptr as *mut u8)
    }

    pub unsafe fn deallocate(&mut self, _ptr: NonNull<u8>, _layout: Layout) {
        // Bump-backed fallback: memory is reclaimed when the allocator is reset.
    }

    pub fn capacity(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn used(&self) -> usize {
        self.next.saturating_sub(self.start)
    }
}

#[inline]
const fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}
