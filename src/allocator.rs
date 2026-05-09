//! Global kernel heap allocator — slab + contiguous multi-page design.
//!
//! ## Architecture
//!
//! ### Single-page slab (≤ 4 KiB requests)
//!
//! Requests that fit inside one 4 KiB page are served from a 16-class
//! power-of-two slab: size classes 16, 32, 64, 128, 256, 512, 1024, 2048,
//! 4096 bytes (9 active classes; 16 slots reserved for future sub-16 classes).
//!
//! Each slab class holds a free-list of previously freed objects stored as
//! an intrusive singly-linked list in the free memory itself.  When the
//! class list is empty a fresh page is fetched from the PMM and split into
//! fixed-size slots.
//!
//! ### Contiguous multi-page (> 4 KiB requests)
//!
//! Requests that span more than one page call `pmm::alloc_pages_contig(n)`,
//! which guarantees the returned frames are physically (and therefore
//! virtually, via the identity/physmap) contiguous.  A compact 16-byte
//! `AllocHeader` is stored in the first 16 bytes of the allocation so that
//! `dealloc` can recover the exact page count without being given it
//! externally — fixing the previous bug where `free_bytes(ptr, size)` could
//! free the wrong number of pages if the caller passed a rounded-up size.
//!
//! Header layout (stored at allocation base, invisible to the caller):
//! ```text
//!   [0..8]   magic   = ALLOC_MAGIC  (0xDEAD_C0DE_CAFE_F00D)
//!   [8..12]  pages   : u32          number of 4 KiB pages
//!   [12..16] _pad    : u32          reserved / zero
//! ```
//! The pointer returned to the caller starts at `base + HEADER_SIZE`.
//!
//! ## GlobalAlloc contract
//!
//! `alloc` returns null on OOM (never panics).
//! `dealloc` reads the header to obtain the page count; mismatched
//!   pointers will trigger a magic-mismatch panic in debug mode.
//! `realloc` allocates a new buffer, copies `min(old_usable, new_size)`
//!   bytes, then frees the old buffer — correct for both growth and shrink.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
    sync::atomic::{AtomicPtr, Ordering},
};
use spin::Mutex;
use crate::mm::pmm;

// ── Constants ─────────────────────────────────────────────────────────────

const PAGE_SIZE:    usize = 4096;
const MIN_ALIGN:    usize = 16;
/// Header stored at the base of every multi-page allocation.
const HEADER_SIZE:  usize = 16;
/// Magic sentinel used to detect header corruption in dealloc.
const ALLOC_MAGIC:  u64   = 0xDEAD_C0DE_CAFE_F00D;

// ── Multi-page header ─────────────────────────────────────────────────────

#[repr(C)]
struct AllocHeader {
    magic: u64,
    pages: u32,
    _pad:  u32,
}

impl AllocHeader {
    #[inline]
    unsafe fn write(base: *mut u8, pages: u32) {
        let h = base as *mut AllocHeader;
        (*h).magic = ALLOC_MAGIC;
        (*h).pages = pages;
        (*h)._pad  = 0;
    }

    /// Read the header preceding `user_ptr` (i.e. at `user_ptr - HEADER_SIZE`).
    /// Panics in debug mode if the magic is wrong.
    #[inline]
    unsafe fn read_pages(user_ptr: *mut u8) -> u32 {
        let base = user_ptr.sub(HEADER_SIZE);
        let h = base as *const AllocHeader;
        debug_assert_eq!(
            (*h).magic, ALLOC_MAGIC,
            "allocator: dealloc header magic mismatch at {:p} — double-free or corruption",
            user_ptr
        );
        (*h).pages
    }
}

// ── Slab free-list node ───────────────────────────────────────────────────

/// Intrusive free-list node embedded in each free slab slot.
/// The `next` pointer is stored in the first 8 bytes of the free object.
struct SlabNode {
    next: *mut SlabNode,
}

// ── Slab class table ──────────────────────────────────────────────────────

/// Number of slab size classes (powers-of-two from 16 to 4096).
const SLAB_CLASSES: usize = 9;
/// Size in bytes for slab class `i` = 16 << i.
const fn slab_size(class: usize) -> usize { MIN_ALIGN << class }

/// Global slab free lists, one per size class.
/// Each entry is the head of an intrusive singly-linked list of free slots.
struct SlabLayer {
    heads: [*mut SlabNode; SLAB_CLASSES],
}

// SAFETY: all accesses are protected by SLAB_LOCK.
unsafe impl Send for SlabLayer {}
unsafe impl Sync for SlabLayer {}

static SLAB: Mutex<SlabLayer> = Mutex::new(SlabLayer {
    heads: [core::ptr::null_mut(); SLAB_CLASSES],
});

/// Return the slab class index for `size`, or `None` if size > PAGE_SIZE.
#[inline]
fn slab_class(size: usize) -> Option<usize> {
    if size == 0 || size > PAGE_SIZE { return None; }
    // Round up to the next power-of-two >= MIN_ALIGN.
    let rounded = size.next_power_of_two().max(MIN_ALIGN);
    // class = log2(rounded / MIN_ALIGN).
    let class = (rounded / MIN_ALIGN).trailing_zeros() as usize;
    if class < SLAB_CLASSES { Some(class) } else { None }
}

/// Allocate one slot from slab class `class`.
/// Refills the free list from the PMM if the list is empty.
///
/// # Safety
/// Must be called with SLAB locked (passed as `slab`).
unsafe fn slab_alloc(slab: &mut SlabLayer, class: usize) -> Option<NonNull<u8>> {
    let slot_size = slab_size(class);

    // Pop from free list.
    let head = slab.heads[class];
    if !head.is_null() {
        slab.heads[class] = (*head).next;
        return NonNull::new(head as *mut u8);
    }

    // Free list empty — fetch a fresh page and slice it into slots.
    let pa = pmm::alloc_page()?;
    let base = pa as *mut u8;
    let slots_per_page = PAGE_SIZE / slot_size;

    // Link all slots into the free list, then pop the first one to return.
    // Build the list from the last slot backwards so the first slot is head.
    let mut list_head: *mut SlabNode = core::ptr::null_mut();
    for i in (0..slots_per_page).rev() {
        let slot = base.add(i * slot_size) as *mut SlabNode;
        (*slot).next = list_head;
        list_head = slot;
    }

    // Pop the first slot for the caller; the rest stay in the free list.
    let ret = list_head as *mut u8;
    slab.heads[class] = (*list_head).next;
    NonNull::new(ret)
}

/// Return `ptr` to slab class `class`'s free list.
///
/// # Safety
/// `ptr` must have been returned by `slab_alloc(class)` and not freed before.
unsafe fn slab_free(slab: &mut SlabLayer, class: usize, ptr: *mut u8) {
    let node = ptr as *mut SlabNode;
    (*node).next = slab.heads[class];
    slab.heads[class] = node;
}

// ── Multi-page allocation ─────────────────────────────────────────────────

/// Allocate `pages` physically contiguous pages and return a pointer to
/// the usable region (immediately after the embedded `AllocHeader`).
unsafe fn large_alloc(pages: usize) -> Option<NonNull<u8>> {
    // We need one extra page worth of space for the header if the header
    // fits within the first page (HEADER_SIZE = 16, PAGE_SIZE = 4096, so
    // the header always fits in the first page alongside the caller data).
    // We simply reduce the usable area of the first page by HEADER_SIZE.
    let base_pa = pmm::alloc_pages_contig(pages)?;
    let base    = base_pa as *mut u8;
    AllocHeader::write(base, pages as u32);
    NonNull::new(base.add(HEADER_SIZE))
}

/// Free a multi-page allocation whose user pointer is `user_ptr`.
/// Reads the page count from the embedded header.
unsafe fn large_free(user_ptr: *mut u8) {
    let pages = AllocHeader::read_pages(user_ptr) as usize;
    let base_pa = user_ptr.sub(HEADER_SIZE) as usize;
    pmm::free_pages_contig(base_pa, pages);
}

// ── GlobalAlloc impl ──────────────────────────────────────────────────────

pub struct KernelAllocator;

#[global_allocator]
pub static ALLOCATOR: KernelAllocator = KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size  = layout.size().max(MIN_ALIGN);
        let align = layout.align().max(MIN_ALIGN);

        // Slab path: fits in one page and alignment ≤ slot size.
        if let Some(class) = slab_class(size) {
            if align <= slab_size(class) {
                return match slab_alloc(&mut SLAB.lock(), class) {
                    Some(p) => p.as_ptr(),
                    None    => core::ptr::null_mut(),
                };
            }
        }

        // Multi-page path.
        // Account for the header that lives in the first HEADER_SIZE bytes.
        let usable_first_page = PAGE_SIZE - HEADER_SIZE;
        let total_bytes = if size <= usable_first_page {
            PAGE_SIZE
        } else {
            // Round up: header eats HEADER_SIZE bytes from the first page.
            HEADER_SIZE + ((size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
        };
        let pages = (total_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

        match large_alloc(pages) {
            Some(p) => p.as_ptr(),
            None    => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        let size  = layout.size().max(MIN_ALIGN);
        let align = layout.align().max(MIN_ALIGN);

        if let Some(class) = slab_class(size) {
            if align <= slab_size(class) {
                slab_free(&mut SLAB.lock(), class, ptr);
                return;
            }
        }

        large_free(ptr);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l)  => l,
            Err(_) => return core::ptr::null_mut(),
        };
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            // Copy only the bytes that exist in both old and new buffers.
            let copy_len = layout.size().min(new_size);
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_len);
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

// ── alloc_bytes / free_bytes public helpers ───────────────────────────────
// Used by mm::heap::grow() and other kernel subsystems.

/// Allocate `size` bytes with at least `align` alignment.
/// Delegates to the same slab/large-page logic as `GlobalAlloc::alloc`.
pub fn alloc_bytes(size: usize, align: usize) -> Option<NonNull<u8>> {
    let layout = Layout::from_size_align(size.max(1), align.max(MIN_ALIGN)).ok()?;
    NonNull::new(unsafe { ALLOCATOR.alloc(layout) })
}

/// Free bytes previously returned by `alloc_bytes`.
/// `size` and `align` must match the original `alloc_bytes` call.
pub fn free_bytes(ptr: NonNull<u8>, size: usize, align: usize) {
    if let Ok(layout) = Layout::from_size_align(size.max(1), align.max(MIN_ALIGN)) {
        unsafe { ALLOCATOR.dealloc(ptr.as_ptr(), layout); }
    }
}
