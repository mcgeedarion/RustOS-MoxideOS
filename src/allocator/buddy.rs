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
//! This lets `free_order` detect a mergeable buddy in O(1) without
//! walking the free list to search for it.
//!
//! ## PMM integration
//!
//! `init()` accepts a `(heap_start, heap_size)` pair and donates the
//! entire region to the buddy system by splitting it into the largest
//! naturally-aligned chunks that fit.  Individual page allocations
//! delegate to `crate::mm::pmm` when the internal free lists are empty.

use core::{alloc::Layout, ptr::NonNull};
use crate::mm::pmm;

// ── Constants ─────────────────────────────────────────────────────────────

pub const PAGE_SIZE: usize = 4096;

/// Maximum order: 2^MAX_ORDER pages = 16 MiB per block.
pub const MAX_ORDER: usize = 12;

/// Maximum number of 4 KiB frames we track in the bitmap.
/// At order 0 we need one bit per two frames, so this covers 4 GiB @ 4 KiB.
const MAX_FRAMES: usize = 1 << 20; // 1 M frames = 4 GiB

// ── Free-list node ────────────────────────────────────────────────────────

/// Intrusive doubly-linked free-list node stored in the first bytes of
/// each free block.  Every block at order `n` is at least
/// `PAGE_SIZE << n` bytes, far larger than `FreeBlock`.
#[repr(C)]
struct FreeBlock {
    prev:  *mut FreeBlock,
    next:  *mut FreeBlock,
    order: usize,
}

// ── Allocator state ───────────────────────────────────────────────────────

/// A binary buddy allocator over a contiguous physical-memory region.
///
/// All accesses must be serialised by the caller (typically via a
/// `spin::Mutex<BuddyAllocator>`).
pub struct BuddyAllocator {
    /// Heads of per-order doubly-linked free lists.
    free_lists: [*mut FreeBlock; MAX_ORDER + 1],
    /// XOR bitmap for merge detection.  Index arithmetic in `bitmap_index`.
    bitmap: [u64; MAX_FRAMES / 64],
    heap_start: usize,
    heap_end:   usize,
}

// SAFETY: All accesses are serialised by the caller's Mutex.
unsafe impl Send for BuddyAllocator {}
unsafe impl Sync for BuddyAllocator {}

impl BuddyAllocator {
    /// Construct an empty (uninitialised) buddy allocator.
    pub const fn new() -> Self {
        Self {
            free_lists: [core::ptr::null_mut(); MAX_ORDER + 1],
            bitmap:     [0u64; MAX_FRAMES / 64],
            heap_start: 0,
            heap_end:   0,
        }
    }

    /// Donate the region `[start, start + size)` to the buddy system.
    ///
    /// The region is split into maximally-sized naturally-aligned blocks
    /// and pushed onto the appropriate free lists.  Call this once after
    /// constructing the allocator.
    ///
    /// # Safety
    /// The entire region must be valid, unused, identity-mapped memory
    /// for the lifetime of the kernel.
    pub unsafe fn init(&mut self, start: usize, size: usize) {
        self.heap_start = start;
        self.heap_end   = start + size;

        let mut addr = start;
        let end      = start + size;

        while addr < end {
            let remaining = end - addr;
            // Largest order whose block is both aligned here and fits.
            let align_order = {
                let frames = (addr - start) / PAGE_SIZE;
                if frames == 0 {
                    MAX_ORDER
                } else {
                    (frames.trailing_zeros() as usize).min(MAX_ORDER)
                }
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

    /// Allocate a block satisfying `layout`, or return `None` on OOM.
    ///
    /// Falls back to the PMM (`pmm::alloc_page`) for order-0 blocks when
    /// the internal free lists are exhausted.
    pub unsafe fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let order = required_order(layout.size(), layout.align())?;
        self.alloc_order(order)
    }

    /// Return a previously allocated block to the buddy system.
    ///
    /// # Safety
    /// `ptr` must have been returned by `allocate` with a layout whose
    /// `required_order` equals `order`, and must not have been freed before.
    pub unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let order = required_order(layout.size(), layout.align())
            .expect("buddy::deallocate: invalid layout");
        self.free_order(ptr.as_ptr() as usize, order);
    }

    // ── Internal: allocation ─────────────────────────────────────────────

    unsafe fn alloc_order(&mut self, order: usize) -> Option<NonNull<u8>> {
        // Walk upward until we find a free block.
        for current in order..=MAX_ORDER {
            if !self.free_lists[current].is_null() {
                let block = self.pop_free(current);
                // Split the block down to the requested order, pushing each
                // upper half onto its own free list.
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

        // Internal free lists exhausted — ask the PMM for a fresh page and
        // split it if necessary.
        if order == 0 {
            let pa = pmm::alloc_page()?;
            self.toggle_bitmap(pa, 0);
            return NonNull::new(pa as *mut u8);
        }

        // Need more than one PMM page; ask for a contiguous run.
        let pages  = 1 << order; // 2^order pages per block at this order
        let base   = pmm::alloc_pages_contig(pages)?;
        self.toggle_bitmap(base, order);
        NonNull::new(base as *mut u8)
    }

    // ── Internal: deallocation and coalescing ────────────────────────────

    unsafe fn free_order(&mut self, mut addr: usize, mut order: usize) {
        while order < MAX_ORDER {
            self.toggle_bitmap(addr, order);

            // After the toggle, bit == 0 means both buddies are free: merge.
            if !self.bitmap_bit(addr, order) {
                let buddy = buddy_of(addr, order, self.heap_start);
                // The buddy must be within our managed region.
                if buddy >= self.heap_start
                    && buddy + block_size(order) <= self.heap_end
                {
                    self.remove_free(buddy as *mut FreeBlock, order);
                    addr = addr.min(buddy); // merged block starts at lower addr
                    order += 1;
                    continue;
                }
            }
            // Either the buddy is still allocated, or out of range — stop.
            break;
        }
        self.push_free(addr as *mut FreeBlock, order);
    }

    // ── Doubly-linked free-list helpers ──────────────────────────────────

    /// Push `block` onto the head of `free_lists[order]`.
    unsafe fn push_free(&mut self, block: *mut FreeBlock, order: usize) {
        let old_head = self.free_lists[order];
        (*block).order = order;
        (*block).prev  = core::ptr::null_mut();
        (*block).next  = old_head;
        if !old_head.is_null() {
            (*old_head).prev = block;
        }
        self.free_lists[order] = block;
    }

    /// Remove and return the head of `free_lists[order]`.
    unsafe fn pop_free(&mut self, order: usize) -> *mut FreeBlock {
        let head = self.free_lists[order];
        debug_assert!(!head.is_null(), "buddy: pop_free on empty list at order {}", order);
        self.free_lists[order] = (*head).next;
        if !(*head).next.is_null() {
            (*(*head).next).prev = core::ptr::null_mut();
        }
        head
    }

    /// Remove an arbitrary `block` from `free_lists[order]`.
    unsafe fn remove_free(&mut self, block: *mut FreeBlock, order: usize) {
        let prev = (*block).prev;
        let next = (*block).next;
        if !prev.is_null() {
            (*prev).next = next;
        } else {
            self.free_lists[order] = next;
        }
        if !next.is_null() {
            (*next).prev = prev;
        }
    }

    // ── Bitmap helpers ────────────────────────────────────────────────────

    /// Compute `(word_index, bit_index)` in `self.bitmap` for the buddy
    /// pair that contains the block at `addr` at `order`.
    ///
    /// At order `n`, each buddy pair covers `2 * (PAGE_SIZE << n)` bytes.
    /// The pair index is `frame / 2^(n+1)` where `frame` is the 0-based
    /// page-frame number relative to `heap_start`.
    #[inline]
    fn bitmap_index(&self, addr: usize, order: usize) -> (usize, usize) {
        let frame     = (addr - self.heap_start) / PAGE_SIZE;
        let pair_idx  = frame >> (order + 1);
        (pair_idx / 64, pair_idx % 64)
    }

    #[inline]
    fn toggle_bitmap(&mut self, addr: usize, order: usize) {
        let (word, bit) = self.bitmap_index(addr, order);
        if word < self.bitmap.len() {
            self.bitmap[word] ^= 1u64 << bit;
        }
    }

    #[inline]
    fn bitmap_bit(&self, addr: usize, order: usize) -> bool {
        let (word, bit) = self.bitmap_index(addr, order);
        if word < self.bitmap.len() {
            (self.bitmap[word] >> bit) & 1 != 0
        } else {
            false
        }
    }
}

// ── Free-standing helpers ──────────────────────────────────────────────────

/// Size in bytes of a buddy block at `order`.
#[inline]
pub const fn block_size(order: usize) -> usize {
    PAGE_SIZE << order
}

/// Address of the buddy of the block at `addr` at `order`, relative to
/// `heap_start`.  XOR with the block size flips the one bit that
/// distinguishes a block from its buddy within a naturally-aligned pair.
#[inline]
fn buddy_of(addr: usize, order: usize, heap_start: usize) -> usize {
    let offset = addr - heap_start;
    heap_start + (offset ^ block_size(order))
}

/// Smallest order whose block size satisfies both `size` and `align`
/// requirements.  Returns `None` if the request exceeds `MAX_ORDER`.
#[inline]
pub fn required_order(size: usize, align: usize) -> Option<usize> {
    // We need at least enough room for a FreeBlock node so the block can
    // be placed on the free list when it is later freed.
    let min_node = core::mem::size_of::<FreeBlock>();
    let needed   = size.max(align).max(min_node);
    for order in 0..=MAX_ORDER {
        if block_size(order) >= needed {
            return Some(order);
        }
    }
    None
}
