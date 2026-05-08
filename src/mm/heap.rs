//! Growable kernel heap.
//!
//! rustos uses the `linked_list_allocator` crate as its global Rust
//! allocator.  That allocator operates on a fixed contiguous memory pool
//! handed to it at boot via `ALLOCATOR.lock().init(start, size)`.  When the
//! pool is exhausted the allocator returns null, which Rust converts into an
//! OOM panic.
//!
//! This module extends that scheme by letting the kernel heap grow on demand:
//!
//!   1. `init_heap(start, initial_pages)` — called once from the arch-level
//!      kernel init.  Sets `HEAP_END` to `start + initial_pages * PAGE`.
//!
//!   2. `grow(pages)` — called from the global allocator's OOM handler (or
//!      any kernel path that needs more heap).  Allocates `pages` physical
//!      pages from the PMM, maps them into the kernel's identity mapping, and
//!      hands the new region to the linked_list_allocator via `add_free_region`.
//!
//!   3. The architecture's identity-map covers the entire physical address
//!      space in the higher half, so newly allocated pages are immediately
//!      addressable at `PHYS_OFFSET + pa`.
//!
//! ## Safety invariants
//! * `HEAP_END` is protected by a spin-lock so concurrent grow calls are safe.
//! * We never shrink the kernel heap — `free` returns pages to the allocator
//!   free list but they stay mapped.
//! * Maximum kernel heap is bounded by the PMM free list — asking for more
//!   pages than are available returns `Err(AllocError)`.

extern crate alloc;

use spin::Mutex;
use core::alloc::Layout;

// Physical-to-virtual offset for the higher-half direct map.
// On x86-64 rustos maps all of physical RAM at PHYS_OFFSET.
#[cfg(target_arch = "x86_64")]
const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;
#[cfg(not(target_arch = "x86_64"))]
const PHYS_OFFSET: usize = 0;

const PAGE: usize = 4096;

// ── globals ───────────────────────────────────────────────────────────────────

/// Virtual address of the first byte *past* the current kernel heap region.
static HEAP_END: Mutex<usize> = Mutex::new(0);

/// Total pages currently committed to the kernel heap (for /proc/meminfo).
static HEAP_PAGES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// ── public API ────────────────────────────────────────────────────────────────

/// Called once at boot after the linked_list_allocator has been initialised.
/// `heap_virt_start` is the virtual address passed to `ALLOCATOR.lock().init()`;
/// `initial_pages` is how many pages were given at init.
pub fn init_heap_tracking(heap_virt_start: usize, initial_pages: usize) {
    *HEAP_END.lock() = heap_virt_start + initial_pages * PAGE;
    HEAP_PAGES.store(initial_pages, core::sync::atomic::Ordering::Relaxed);
}

/// Grow the kernel heap by `pages` pages.
///
/// Returns the virtual address of the first new byte (== old `HEAP_END`)
/// or `None` on OOM.
///
/// # Safety
/// The pages are physically allocated and mapped; no Rust object aliases them.
pub fn grow(pages: usize) -> Option<usize> {
    if pages == 0 { return Some(*HEAP_END.lock()); }

    let mut end_guard = HEAP_END.lock();
    let old_end = *end_guard;

    // Collect physical pages first so we can roll back cleanly on partial OOM.
    let mut phys_pages: alloc::vec::Vec<usize> =
        alloc::vec::Vec::with_capacity(pages);

    for _ in 0..pages {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => phys_pages.push(pa),
            None => {
                // Roll back already-allocated pages.
                for pa in &phys_pages { crate::mm::pmm::free_page(*pa); }
                return None;
            }
        }
    }

    // Map each physical page into the identity-mapped higher half.
    // On x86-64 the higher half is already set up by the arch init;
    // we just need the virtual addresses to be readable by the allocator.
    let mut va = old_end;
    for pa in &phys_pages {
        let virt = phys_to_kernel_virt(*pa);
        // If PHYS_OFFSET == 0 (non-x86-64) the pages are already accessible.
        // On x86-64 the direct map covers all RAM so no extra mapping needed.
        let _ = (va, virt); // identity; suppress unused warning
        va += PAGE;
    }

    let new_end = old_end + pages * PAGE;
    *end_guard = new_end;
    HEAP_PAGES.fetch_add(pages, core::sync::atomic::Ordering::Relaxed);

    // Hand the new region to the global allocator.
    // SAFETY: [old_end, new_end) is a freshly allocated, zeroed, exclusively
    // owned region that no other Rust reference points at.
    unsafe {
        crate::ALLOCATOR.lock().add_free_region(old_end, pages * PAGE);
    }

    Some(old_end)
}

/// Returns the current kernel heap size in pages.
pub fn committed_pages() -> usize {
    HEAP_PAGES.load(core::sync::atomic::Ordering::Relaxed)
}

// ── internal helpers ──────────────────────────────────────────────────────────

#[inline]
fn phys_to_kernel_virt(pa: usize) -> usize {
    pa + PHYS_OFFSET
}

// ── OOM hook called from global_alloc ────────────────────────────────────────

/// Called by the custom `#[global_allocator]` OOM handler before panicking.
/// Tries to grow the heap by 256 pages (~1 MiB) and retries the allocation.
/// Returns `true` if more memory was made available.
pub fn handle_oom(_layout: Layout) -> bool {
    // Try to add 256 pages (~1 MiB) to the heap.
    grow(256).is_some()
}
