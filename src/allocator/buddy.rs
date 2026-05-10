//! Binary buddy allocator.
//!
//! ## Design
//!
//! Memory is divided into *buddy pairs*: a block at order `n` is exactly
//! `PAGE_SIZE << n` bytes, naturally aligned to that size.  When a block
//! is freed the allocator looks up its buddy address with a simple XOR;
//! if the buddy is also free the two are coalesced into an order-`n+1`
//! block, and the process recurses upward to `MAX_ORDER`.
//!
//! ## Bitmap merge detection
//!
//! A compact XOR bitmap tracks buddy-pair state per order:
//!
//! * One bit per buddy pair at each order level.
//! * Toggled on every alloc and every free at that order.
//! * Bit == 0  ⟹  both buddies have the same state (both allocated or
//!              both free after a coalesce).
//! * Bit == 1  ⟹  exactly one buddy is free (the other is allocated).
//!
//! ## PMM integration
//!
//! `allocate()` falls through to `crate::mm::pmm` when all internal free
//! lists are exhausted, so the buddy allocator never returns OOM as long as
//! physical frames remain available.

use core::{alloc::Layout, ptr::NonNull};

#[cfg(not(test))]
use crate::mm::pmm;

// ── Constants ─────────────────────────────────────────────────────────────

pub const PAGE_SIZE: usize = 4096;

/// Maximum order: 2^MAX_ORDER pages = 16 MiB per block.
pub const MAX_ORDER: usize = 12;

/// Maximum number of 4 KiB frames tracked by the bitmap.
/// 1 M frames covers 4 GiB of physical address space.
const MAX_FRAMES: usize = 1 << 20;

// ── Free-list node ────────────────────────────────────────────────────────

/// Intrusive doubly-linked free-list node stored in the first bytes of
/// each free block.  Every block at order `n` is at least PAGE_SIZE bytes,
/// which is far larger than `FreeBlock`.
#[repr(C)]
pub(crate) struct FreeBlock {
    pub(crate) prev:  *mut FreeBlock,
    pub(crate) next:  *mut FreeBlock,
    pub(crate) order: usize,
}

/// Iterator helper used by `stats::buddy_stats` to count free blocks
/// without allocating.
pub struct FreeBlockIter;
impl FreeBlockIter {
    /// Count the number of nodes in the singly-linked `next` chain
    /// starting at `head` (null = empty list).
    ///
    /// # Safety
    /// `head` must be null or a valid pointer to a `FreeBlock` in a
    /// live buddy free list.
    pub unsafe fn count(head: *mut FreeBlock) -> usize {
        let mut n = 0usize;
        let mut cur = head;
        while !cur.is_null() {
            n += 1;
            cur = (*cur).next;
        }
        n
    }
}

// ── Allocator state ───────────────────────────────────────────────────────

/// Binary buddy allocator over a contiguous physical/virtual region.
/// All accesses must be serialised by the caller (e.g. via `spin::Mutex`).
pub struct BuddyAllocator {
    pub(crate) free_lists: [*mut FreeBlock; MAX_ORDER + 1],
    bitmap:     [u64; MAX_FRAMES / 64],
    pub(crate) heap_start: usize,
    heap_end:   usize,
}

// SAFETY: serialised by caller's Mutex.
unsafe impl Send for BuddyAllocator {}
unsafe impl Sync for BuddyAllocator {}

impl BuddyAllocator {
    /// Construct an empty (uninitialised) allocator.
    pub const fn new() -> Self {
        Self {
            free_lists: [core::ptr::null_mut(); MAX_ORDER + 1],
            bitmap:     [0u64; MAX_FRAMES / 64],
            heap_start: 0,
            heap_end:   0,
        }
    }

    /// Donate `[start, start + size)` to the buddy system.
    ///
    /// Splits the region into maximally-sized naturally-aligned blocks and
    /// pushes them onto their respective free lists.  Call once at init.
    ///
    /// # Safety
    /// The entire region must be valid, unused, identity-mapped memory for
    /// the lifetime of the kernel.
    pub unsafe fn init(&mut self, start: usize, size: usize) {
        self.heap_start = start;
        self.heap_end   = start + size;

        let mut addr = start;
        let end      = start + size;
        while addr < end {
            let remaining = end - addr;
            let align_order = {
                let frames = (addr - start) / PAGE_SIZE;
                if frames == 0 { MAX_ORDER }
                else { (frames.trailing_zeros() as usize).min(MAX_ORDER) }
            };
            let mut order = align_order;
            while order > 0 && block_size(order) > remaining {
                order -= 1;
            }
            if block_size(order) > remaining { break; }
            self.push_free(addr as *mut FreeBlock, order);
            addr += block_size(order);
        }
    }

    /// Allocate a block satisfying `layout`, or `None` on OOM.
    pub unsafe fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let order = required_order(layout.size(), layout.align())?;
        self.alloc_order(order)
    }

    /// Return a block to the buddy system, coalescing if possible.
    ///
    /// # Safety
    /// `ptr` must have been returned by `allocate` with the same layout.
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let order = required_order(layout.size(), layout.align())
            .expect("buddy::deallocate: invalid layout");
        self.free_order(ptr.as_ptr() as usize, order);
    }

    // ── Internal: allocation ─────────────────────────────────────────────

    unsafe fn alloc_order(&mut self, order: usize) -> Option<NonNull<u8>> {
        for current in order..=MAX_ORDER {
            if !self.free_lists[current].is_null() {
                let block = self.pop_free(current);
                // Split down to the requested order.
                let mut split = current;
                while split > order {
                    split -= 1;
                    let buddy_addr = block as usize + block_size(split);
                    self.push_free(buddy_addr as *mut FreeBlock, split);
                }
                self.toggle_bitmap(block as usize, order);
                return NonNull::new(block as *mut u8);
            }
        }
        // Internal lists exhausted — fall back to PMM (kernel builds only).
        #[cfg(not(test))]
        {
            if order == 0 {
                let pa = pmm::alloc_page()?;
                self.toggle_bitmap(pa, 0);
                return NonNull::new(pa as *mut u8);
            }
            let pages = 1 << order;
            let base  = pmm::alloc_pages_contig(pages)?;
            self.toggle_bitmap(base, order);
            return NonNull::new(base as *mut u8);
        }
        #[cfg(test)]
        None
    }

    // ── Internal: free and coalesce ─────────────────────────────────────────

    unsafe fn free_order(&mut self, mut addr: usize, mut order: usize) {
        while order < MAX_ORDER {
            self.toggle_bitmap(addr, order);
            if !self.bitmap_bit(addr, order) {
                let buddy = buddy_of(addr, order, self.heap_start);
                if buddy >= self.heap_start
                    && buddy + block_size(order) <= self.heap_end
                {
                    self.remove_free(buddy as *mut FreeBlock, order);
                    addr  = addr.min(buddy);
                    order += 1;
                    continue;
                }
            }
            break;
        }
        self.push_free(addr as *mut FreeBlock, order);
    }

    // ── Doubly-linked free-list helpers ─────────────────────────────────

    pub(crate) unsafe fn push_free(&mut self, block: *mut FreeBlock, order: usize) {
        let old_head = self.free_lists[order];
        (*block).order = order;
        (*block).prev  = core::ptr::null_mut();
        (*block).next  = old_head;
        if !old_head.is_null() { (*old_head).prev = block; }
        self.free_lists[order] = block;
    }

    unsafe fn pop_free(&mut self, order: usize) -> *mut FreeBlock {
        let head = self.free_lists[order];
        debug_assert!(!head.is_null());
        self.free_lists[order] = (*head).next;
        if !(*head).next.is_null() { (*(*head).next).prev = core::ptr::null_mut(); }
        head
    }

    unsafe fn remove_free(&mut self, block: *mut FreeBlock, order: usize) {
        let prev = (*block).prev;
        let next = (*block).next;
        if !prev.is_null() { (*prev).next = next; }
        else               { self.free_lists[order] = next; }
        if !next.is_null() { (*next).prev = prev; }
    }

    // ── Bitmap helpers ───────────────────────────────────────────────────

    #[inline]
    fn bitmap_index(&self, addr: usize, order: usize) -> (usize, usize) {
        let frame    = (addr - self.heap_start) / PAGE_SIZE;
        let pair_idx = frame >> (order + 1);
        (pair_idx / 64, pair_idx % 64)
    }

    #[inline]
    pub(crate) fn toggle_bitmap(&mut self, addr: usize, order: usize) {
        let (word, bit) = self.bitmap_index(addr, order);
        if word < self.bitmap.len() {
            self.bitmap[word] ^= 1u64 << bit;
        }
    }

    #[inline]
    pub(crate) fn bitmap_bit(&self, addr: usize, order: usize) -> bool {
        let (word, bit) = self.bitmap_index(addr, order);
        if word < self.bitmap.len() { (self.bitmap[word] >> bit) & 1 != 0 }
        else                        { false }
    }
}

// ── Free-standing helpers ──────────────────────────────────────────────────

/// Size in bytes of a block at `order`: `PAGE_SIZE << order`.
#[inline]
pub const fn block_size(order: usize) -> usize {
    PAGE_SIZE << order
}

/// Address of the buddy of the block at `addr` at `order`.
/// Uses XOR on the offset from `heap_start` to flip the single bit
/// that separates a block from its buddy within an aligned pair.
#[inline]
fn buddy_of(addr: usize, order: usize, heap_start: usize) -> usize {
    let offset = addr - heap_start;
    heap_start + (offset ^ block_size(order))
}

/// Smallest order whose block fits both `size` and `align`.
/// Returns `None` if the request exceeds `block_size(MAX_ORDER)`.
#[inline]
pub fn required_order(size: usize, align: usize) -> Option<usize> {
    let min_node = core::mem::size_of::<FreeBlock>();
    let needed   = size.max(align).max(min_node);
    for order in 0..=MAX_ORDER {
        if block_size(order) >= needed { return Some(order); }
    }
    None
}
