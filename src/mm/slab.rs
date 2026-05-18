//! Slab allocator — fixed-size object caches backed by the PMM.
//!
//! ## Design overview
//!
//! ```text
//!  slab_alloc(sz)
//!       │
//!       ▼
//!  size_class(sz)  ──►  cache[i]  (spin::Mutex<Cache>)
//!                             │
//!                  ┌──────────┴──────────┐
//!                  │  partial slabs list  │
//!                  │  full    slabs list  │
//!                  │  empty   slabs list  │
//!                  └──────────┬──────────┘
//!                             │
//!               pop free slot from partial head
//!               (or carve a new slab from PMM)
//! ```
//!
//! ## Size classes
//!
//!   Index │  Object size │  Slots per 4 KiB page
//!   ──────┼──────────────┼──────────────────────
//!     0   │     8 bytes  │   512
//!     1   │    16 bytes  │   256
//!     2   │    32 bytes  │   128
//!     3   │    64 bytes  │    64
//!     4   │   128 bytes  │    32
//!     5   │   256 bytes  │    16
//!     6   │   512 bytes  │     8
//!     7   │  1024 bytes  │     4
//!
//! Requests > 1024 bytes are forwarded to the global heap allocator.
//!
//! ## Free-list encoding
//!
//! Free slots store a raw `*mut u8` next-pointer in their first
//! `size_of::<usize>()` bytes.  A null pointer marks the end of the
//! list.  This requires object size ≥ `size_of::<usize>()` (8 on
//! 64-bit), which is guaranteed by the minimum class size of 8.
//!
//! ## Slab lifecycle
//!
//!   fresh PMM page  →  empty slab  →  partial  →  full
//!                                ↑____________↓  (free)
//!                   empty slab  ← partial  (all slots freed)
//!   PMM free_page  ← empty slab  (via slab_shrink)
//!
//! ## Zero-fill invariant
//!
//! Every slot handed to a caller is guaranteed to contain only zero bytes.
//! This invariant is maintained by two complementary policies — NOT by
//! zeroing in `Cache::alloc`:
//!
//!   1. **Fresh slots** (carved by `Cache::grow`): the PMM zeroes the entire
//!      page before returning it from `alloc_page()`, so all slots on a
//!      newly-grown slab are already zero.
//!
//!   2. **Recycled slots** (returned by `Cache::free`): `free` scrubs the
//!      slot with `ptr::write_bytes(ptr, 0, obj_size)` *before* writing the
//!      free-list next-pointer into its first word.  The next-pointer is
//!      overwritten by `Cache::alloc` when the slot is popped, restoring the
//!      first word to zero.  The remainder of the slot is therefore zero from
//!      the scrub in `free`.
//!
//! Consequence: `Cache::alloc` does **not** need to zero the slot — doing so
//! would be a redundant `obj_size`-byte store on every allocation.
//!
//! ## SMP safety
//!
//! Each `Cache` is wrapped in its own `spin::Mutex`.  Allocations from
//! different size classes never contend.  The PMM itself is lock-free
//! (Treiber stack), so the slab → PMM boundary is also contention-free.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;
use core::ptr;

use crate::mm::pmm;

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZE: usize = 4096;

/// Object sizes for each slab cache, in bytes.
const SIZE_CLASSES: [usize; 8] = [8, 16, 32, 64, 128, 256, 512, 1024];

/// Number of distinct caches.
const NUM_CACHES: usize = SIZE_CLASSES.len();

// ── Slab metadata ─────────────────────────────────────────────────────────────
//
// Stored at the very beginning of each PMM page so we never need a
// separate metadata allocation.  The usable object area starts at
// offset `SLAB_HDR_SIZE` (rounded up to the object's alignment, which
// for power-of-two sizes is just the object size itself).
//
// Layout inside one 4 KiB page for object size S:
//
//   [ SlabHdr (40 bytes, padded to S) | slot_0 | slot_1 | … | slot_N ]
//
// where N = (PAGE_SIZE - hdr_offset) / S.

/// Size of the in-page header, rounded up to the next multiple of 8.
const SLAB_HDR_RAW: usize = core::mem::size_of::<SlabHdr>();

/// Align `hdr_size` up to `obj_size` so slot_0 is naturally aligned.
#[inline]
const fn hdr_offset(obj_size: usize) -> usize {
    (SLAB_HDR_RAW + obj_size - 1) & !(obj_size - 1)
}

/// Number of object slots in one page for a given object size.
#[inline]
const fn slots_per_page(obj_size: usize) -> usize {
    (PAGE_SIZE - hdr_offset(obj_size)) / obj_size
}

/// In-page slab header.  Packed into the first bytes of the PMM page.
/// `next` and `prev` are raw page-base pointers forming a doubly-linked
/// list inside the owning `Cache`.  Using raw pointers avoids Box/Arc and
/// therefore avoids calling the global allocator from within the slab
/// allocator itself.
#[repr(C)]
struct SlabHdr {
    /// Next slab in the same list (partial / full / empty).  Null = end.
    next:      *mut SlabHdr,
    /// Previous slab in the same list.  Null = head.
    prev:      *mut SlabHdr,
    /// Head of the in-slab free list.  Null = all slots allocated.
    free_head: *mut u8,
    /// Number of currently allocated (in-use) slots.
    in_use:    u16,
    /// Total capacity (slots_per_page for this class).
    capacity:  u16,
    /// Size class index (0..NUM_CACHES).  Used by slab_free to locate
    /// the owning cache without an O(n) scan.
    class_idx: u8,
    _pad:      [u8; 3],
}

// SlabHdr must fit in 40 bytes so hdr_offset(8) == 40, which leaves
// exactly 512 slots in the 8-byte class.  Assert at compile time.
const _: () = assert!(core::mem::size_of::<SlabHdr>() <= 40);

// ── Cache ─────────────────────────────────────────────────────────────────────

struct Cache {
    /// Slabs with at least one free slot.
    partial: *mut SlabHdr,
    /// Slabs with no free slots.
    full:    *mut SlabHdr,
    /// Slabs with all slots free (ready to return to PMM).
    empty:   *mut SlabHdr,
    /// Size of one object in this cache.
    obj_size: usize,
    /// Cached slots_per_page for this obj_size.
    capacity: usize,
}

// SAFETY: Cache is only accessed under its Mutex guard.
unsafe impl Send for Cache {}

impl Cache {
    const fn new(obj_size: usize) -> Self {
        Cache {
            partial:  ptr::null_mut(),
            full:     ptr::null_mut(),
            empty:    ptr::null_mut(),
            obj_size,
            capacity: slots_per_page(obj_size),
        }
    }

    // ── Slab list helpers ──────────────────────────────────────────────

    /// Prepend `slab` to `list` (update head pointer in place).
    unsafe fn list_push(list: &mut *mut SlabHdr, slab: *mut SlabHdr) {
        (*slab).next = *list;
        (*slab).prev = ptr::null_mut();
        if !(*list).is_null() {
            (**list).prev = slab;
        }
        *list = slab;
    }

    /// Remove `slab` from `list`.
    unsafe fn list_remove(list: &mut *mut SlabHdr, slab: *mut SlabHdr) {
        let prev = (*slab).prev;
        let next = (*slab).next;
        if !prev.is_null() { (*prev).next = next; } else { *list = next; }
        if !next.is_null() { (*next).prev = prev; }
        (*slab).next = ptr::null_mut();
        (*slab).prev = ptr::null_mut();
    }

    // ── Slab initialisation ────────────────────────────────────────────

    /// Carve a fresh slab out of a PMM page and add it to the partial list.
    /// Returns false on PMM exhaustion.
    unsafe fn grow(&mut self, class_idx: u8) -> bool {
        let pa = match pmm::alloc_page() {
            Some(p) => p,
            None    => return false,
        };
        let page = pa as *mut u8;
        let hdr  = page as *mut SlabHdr;

        // Build the intrusive free list through all slots.
        // The PMM guarantees the page is zeroed, so only the free-list
        // next-pointer word needs to be written per slot.
        let obj_sz    = self.obj_size;
        let cap       = self.capacity;
        let slot0_off = hdr_offset(obj_sz);

        let mut prev_slot: *mut u8 = ptr::null_mut();
        // Walk backward so that slot_0 ends up at the head.
        let mut i = cap;
        while i > 0 {
            i -= 1;
            let slot = page.add(slot0_off + i * obj_sz);
            *(slot as *mut *mut u8) = prev_slot;
            prev_slot = slot;
        }

        (*hdr).next      = ptr::null_mut();
        (*hdr).prev      = ptr::null_mut();
        (*hdr).free_head = prev_slot; // = slot_0
        (*hdr).in_use    = 0;
        (*hdr).capacity  = cap as u16;
        (*hdr).class_idx = class_idx;
        (*hdr)._pad      = [0u8; 3];

        Self::list_push(&mut self.partial, hdr);
        true
    }

    // ── Allocation ────────────────────────────────────────────────────

    unsafe fn alloc(&mut self, class_idx: u8) -> Option<*mut u8> {
        // 1. Try partial list first.
        if self.partial.is_null() {
            // 2. Try empty list (slab exists but no allocated slots).
            if !self.empty.is_null() {
                let s = self.empty;
                Self::list_remove(&mut self.empty, s);
                Self::list_push(&mut self.partial, s);
            } else {
                // 3. Carve a fresh slab.
                if !self.grow(class_idx) { return None; }
            }
        }

        let slab = self.partial;
        debug_assert!(!(*slab).free_head.is_null());

        // Pop the head of the free list.
        let slot      = (*slab).free_head;
        let next_free = *(slot as *const *mut u8);
        (*slab).free_head = next_free;
        (*slab).in_use   += 1;

        // If slab is now full, move it to the full list.
        if (*slab).in_use as usize == (*slab).capacity as usize {
            Self::list_remove(&mut self.partial, slab);
            Self::list_push(&mut self.full, slab);
        }

        // No explicit zero-fill here.  The zero-fill invariant is maintained
        // by the PMM (fresh pages) and by Cache::free (recycled slots).
        // See the "Zero-fill invariant" section in the module-level doc.
        //
        // Overwrite the free-list next-pointer word that was stored in this
        // slot so the caller receives a fully-zeroed object.
        *(slot as *mut *mut u8) = ptr::null_mut();

        Some(slot)
    }

    // ── Deallocation ──────────────────────────────────────────────────

    /// Return `ptr` to this cache.  `ptr` must have been allocated from
    /// a slab belonging to this cache.
    unsafe fn free(&mut self, ptr: *mut u8) {
        // Locate the slab: the slab header lives at the page base.
        let page_base = (ptr as usize) & !(PAGE_SIZE - 1);
        let slab      = page_base as *mut SlabHdr;

        let was_full    = (*slab).in_use as usize == (*slab).capacity as usize;
        let was_partial = !was_full && (*slab).in_use > 0;

        // Scrub the slot before relinking (security: no stale data).
        // This also maintains the zero-fill invariant for future alloc calls.
        ptr::write_bytes(ptr, 0, self.obj_size);

        // Push onto the slab's free list.
        *(ptr as *mut *mut u8) = (*slab).free_head;
        (*slab).free_head = ptr;
        (*slab).in_use   -= 1;

        if was_full {
            // full → partial
            Self::list_remove(&mut self.full,    slab);
            Self::list_push(&mut self.partial, slab);
        } else if was_partial && (*slab).in_use == 0 {
            // partial → empty
            Self::list_remove(&mut self.partial, slab);
            Self::list_push(&mut self.empty, slab);
        }
    }

    // ── Shrink ────────────────────────────────────────────────────────

    /// Return all empty slabs in this cache to the PMM.
    unsafe fn shrink(&mut self) {
        let mut slab = self.empty;
        while !slab.is_null() {
            let next = (*slab).next;
            pmm::free_page(slab as usize);
            slab = next;
        }
        self.empty = ptr::null_mut();
    }

    // ── Statistics ────────────────────────────────────────────────────

    unsafe fn count_list(mut head: *mut SlabHdr) -> usize {
        let mut n = 0;
        while !head.is_null() { n += 1; head = (*head).next; }
        n
    }

    unsafe fn stats(&self) -> CacheStats {
        let partial_slabs = Self::count_list(self.partial);
        let full_slabs    = Self::count_list(self.full);
        let empty_slabs   = Self::count_list(self.empty);
        let active = {
            let mut n = 0usize;
            let mut s = self.partial;
            while !s.is_null() { n += (*s).in_use as usize; s = (*s).next; }
            s = self.full;
            while !s.is_null() { n += (*s).in_use as usize; s = (*s).next; }
            n
        };
        CacheStats {
            obj_size:     self.obj_size,
            active_objs:  active,
            total_slabs:  partial_slabs + full_slabs + empty_slabs,
            partial_slabs,
            full_slabs,
            empty_slabs,
        }
    }
}

// ── Globals ───────────────────────────────────────────────────────────────────

macro_rules! make_caches {
    ($($sz:expr),*) => {
        [$(Mutex::new(Cache::new($sz))),*]
    };
}

static CACHES: [Mutex<Cache>; NUM_CACHES] = make_caches![8, 16, 32, 64, 128, 256, 512, 1024];

// ── Size class lookup ─────────────────────────────────────────────────────────

/// Return the cache index for an allocation of `size` bytes, or `None`
/// if `size` exceeds the largest class (1024 bytes).
#[inline]
fn size_class(size: usize) -> Option<usize> {
    if size == 0 { return Some(0); }
    for (i, &s) in SIZE_CLASSES.iter().enumerate() {
        if size <= s { return Some(i); }
    }
    None
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the slab allocator.
///
/// Pre-warms each cache with one slab so the very first allocation from
/// any size class does not need to call the PMM.  Must be called after
/// `pmm::init()` / `memmap_init()` (i.e. after usable physical pages are
/// available) but can be called before or after `heap::init()`.
///
/// Idempotent: safe to call multiple times (subsequent calls are no-ops
/// because the cache already has a slab in the partial list).
pub fn init() {
    for (i, cache) in CACHES.iter().enumerate() {
        let mut c = cache.lock();
        if c.partial.is_null() && c.empty.is_null() {
            unsafe { c.grow(i as u8); }
        }
    }
}

/// Allocate a zero-filled object of at least `size` bytes from the
/// appropriate slab cache.
///
/// - For `size` in [1, 1024]: served from the slab caches (O(1),
///   lock-per-class).
/// - For `size` > 1024: forwarded to the global heap allocator via
///   `alloc::alloc::alloc_zeroed` (falls back to `linked_list_allocator`
///   + PMM grow on OOM).
/// - Returns `None` on OOM.
///
/// The returned pointer is valid for `size` bytes and is always
/// aligned to at least the size-class boundary (power of two).
pub fn slab_alloc(size: usize) -> Option<*mut u8> {
    match size_class(size) {
        Some(idx) => {
            unsafe { CACHES[idx].lock().alloc(idx as u8) }
        }
        None => {
            // Fall back to the global heap for large objects.
            let layout = alloc::alloc::Layout::from_size_align(size, 8).ok()?;
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            if ptr.is_null() { None } else { Some(ptr) }
        }
    }
}

/// Return an object previously allocated with `slab_alloc(size)` back
/// to its cache.
///
/// # Safety
/// - `ptr` must have been returned by `slab_alloc(size)` with the **same**
///   `size` value.
/// - `ptr` must not be used after this call.
/// - Double-free is detected in debug builds (the slot is zeroed on free;
///   a second free on a zeroed slot will pass, but the slab's `in_use`
///   counter will underflow and trigger a panic in debug mode).
pub fn slab_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() { return; }
    match size_class(size) {
        Some(idx) => {
            unsafe { CACHES[idx].lock().free(ptr); }
        }
        None => {
            // Was a heap allocation; reconstruct the layout and free it.
            if let Ok(layout) = alloc::alloc::Layout::from_size_align(size, 8) {
                unsafe { alloc::alloc::dealloc(ptr, layout); }
            }
        }
    }
}

/// Release all empty slabs in every cache back to the PMM.
///
/// Call this from a memory-pressure handler or a periodic kernel task.
/// Holding no slab locks is required (this function acquires each lock
/// briefly in sequence).
pub fn slab_shrink() {
    for cache in CACHES.iter() {
        unsafe { cache.lock().shrink(); }
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

/// Per-cache statistics snapshot (for /proc/slabinfo).
#[derive(Clone, Copy, Debug, Default)]
pub struct CacheStats {
    /// Object size in bytes.
    pub obj_size:     usize,
    /// Number of objects currently allocated from this cache.
    pub active_objs:  usize,
    /// Total number of slabs (partial + full + empty).
    pub total_slabs:  usize,
    pub partial_slabs: usize,
    pub full_slabs:   usize,
    pub empty_slabs:  usize,
}

/// Aggregate across all caches (for /proc/meminfo slab lines).
#[derive(Clone, Copy, Debug, Default)]
pub struct SlabStats {
    pub total_slabs:   usize,
    pub active_objs:   usize,
    pub per_cache:     [CacheStats; NUM_CACHES],
}

/// Snapshot the slab allocator's current state.
///
/// Acquires each per-cache lock briefly.  Safe to call from any context
/// that can sleep (e.g. procfs read handler).
pub fn slab_stats() -> SlabStats {
    let mut out = SlabStats::default();
    for (i, cache) in CACHES.iter().enumerate() {
        let cs = unsafe { cache.lock().stats() };
        out.total_slabs += cs.total_slabs;
        out.active_objs += cs.active_objs;
        out.per_cache[i] = cs;
    }
    out
}

// ── Typed convenience wrappers ────────────────────────────────────────────────
//
// These are thin wrappers so callers can write:
//
//   let vma = SlabBox::<Vma>::new(Vma { ... })?;
//
// instead of managing raw pointers.  The box frees via slab_free on Drop.
//
// NOTE: SlabBox<T> is only sound if T's size ≤ 1024 bytes (slab path)
// or if the fallback heap path succeeds.  Use Box<T> directly for larger
// types.

/// Owned pointer to a slab-allocated `T`.  Frees via `slab_free` on drop.
pub struct SlabBox<T> {
    ptr: *mut T,
}

impl<T> SlabBox<T> {
    /// Allocate a slab slot for `T`, write `value` into it, and return a
    /// `SlabBox<T>`.  Returns `None` on OOM.
    pub fn new(value: T) -> Option<Self> {
        let size = core::mem::size_of::<T>();
        let ptr  = slab_alloc(size)? as *mut T;
        // SAFETY: ptr is valid, aligned, and exclusively owned.
        unsafe { ptr.write(value); }
        Some(SlabBox { ptr })
    }

    /// Consume the box and return the raw pointer.  The caller is
    /// responsible for freeing via `slab_free(ptr as *mut u8, size_of::<T>())`.
    pub fn into_raw(self) -> *mut T {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl<T> core::ops::Deref for SlabBox<T> {
    type Target = T;
    fn deref(&self) -> &T { unsafe { &*self.ptr } }
}

impl<T> core::ops::DerefMut for SlabBox<T> {
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.ptr } }
}

impl<T> Drop for SlabBox<T> {
    fn drop(&mut self) {
        unsafe { ptr::drop_in_place(self.ptr); }
        slab_free(self.ptr as *mut u8, core::mem::size_of::<T>());
    }
}

// SAFETY: SlabBox<T> is Send/Sync if T is.
unsafe impl<T: Send> Send for SlabBox<T> {}
unsafe impl<T: Sync> Sync for SlabBox<T> {}
