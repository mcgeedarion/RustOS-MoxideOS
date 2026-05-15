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
//!   1. `init_heap_tracking(start, initial_pages)` — called once from the
//!      arch-level kernel init.  Sets `HEAP_END` to
//!      `start + initial_pages * PAGE`.
//!
//!   2. `grow(pages)` — called from the global allocator's OOM handler (or
//!      any kernel path that needs more heap).  Allocates `pages` physical
//!      pages from the PMM, derives their kernel-virtual addresses through the
//!      architecture's direct physmap, and hands that region to the
//!      linked_list_allocator via `add_free_region`.
//!
//!   3. On both supported architectures the kernel direct map covers the
//!      entire physical address space in the higher half (x86-64:
//!      `PHYS_OFFSET + pa`; RISC-V: `KERNEL_PHYS_BASE + pa`).  Newly
//!      allocated pages are therefore immediately addressable without any
//!      additional `map_page()` call.
//!
//! ## Safety invariants
//! * `HEAP_END` is **not** used as the base address handed to
//!   `add_free_region`.  It is only a monotonically-increasing watermark for
//!   `/proc/meminfo` accounting.  The actual virtual address passed to the
//!   allocator is the physmap translation of each PMM frame.
//! * `HEAP_END` is protected by a spin-lock so concurrent grow calls are safe.
//! * We never shrink the kernel heap — `free` returns pages to the allocator
//!   free list but they stay mapped.
//! * Maximum kernel heap is bounded by the PMM free list — asking for more
//!   pages than are available returns `None`.

extern crate alloc;

use core::alloc::Layout;
use spin::Mutex;

// ── Physical-to-virtual offset for the higher-half direct map ───────────────
//
// On x86-64 rustos identity-maps all of physical RAM at PHYS_OFFSET.
// On RISC-V it is mapped at KERNEL_PHYS_BASE (same role, different name).
// Both are flat-offset maps: virt = phys + BASE.
//
// If neither cfg matches the build will fail with an unresolved symbol, which
// is intentional — adding a new architecture requires explicitly defining its
// physmap base here.

#[cfg(target_arch = "x86_64")]
#[inline]
fn phys_to_kernel_virt(pa: usize) -> usize {
    const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;
    pa + PHYS_OFFSET
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn phys_to_kernel_virt(pa: usize) -> usize {
    extern "C" {
        static KERNEL_PHYS_BASE: usize;
    }
    unsafe { pa + KERNEL_PHYS_BASE }
}

const PAGE: usize = 4096;

// ── globals ─────────────────────────────────────────────────────────────────────

/// Monotonically-increasing watermark used only for `/proc/meminfo`
/// accounting.  NOT the VA passed to `add_free_region`.
static HEAP_END: Mutex<usize> = Mutex::new(0);

/// Total pages currently committed to the kernel heap (for /proc/meminfo).
static HEAP_PAGES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

// ── public API ─────────────────────────────────────────────────────────────────

/// Called once at boot after the linked_list_allocator has been initialised.
/// `heap_virt_start` is the virtual address passed to `ALLOCATOR.lock().init()`;
/// `initial_pages` is how many pages were given at init.
pub fn init_heap_tracking(heap_virt_start: usize, initial_pages: usize) {
    *HEAP_END.lock() = heap_virt_start + initial_pages * PAGE;
    HEAP_PAGES.store(initial_pages, core::sync::atomic::Ordering::Relaxed);
}

/// Grow the kernel heap by `pages` pages.
///
/// Allocates `pages` physical frames from the PMM, translates each to its
/// kernel-virtual address through the architecture's flat physmap, and hands
/// the resulting region to the global allocator via `add_free_region`.
///
/// Returns the kernel-virtual address of the first new byte, or `None` on OOM.
///
/// # Safety
/// Each frame is freshly allocated from the PMM, zero-filled, and not aliased
/// by any existing Rust reference.  The physmap makes them immediately
/// accessible at `phys_to_kernel_virt(pa)` without an explicit `map_page()`.
pub fn grow(pages: usize) -> Option<usize> {
    if pages == 0 {
        // Nothing to do; return the current heap-end VA for callers that
        // use the return value as a watermark.
        return Some(*HEAP_END.lock());
    }

    let mut end_guard = HEAP_END.lock();

    // ── Step 1: allocate physical frames ───────────────────────────────────────
    //
    // Collect all frames before touching the allocator.  If the PMM runs
    // dry partway through we roll back the already-allocated frames.
    let mut phys_pages: alloc::vec::Vec<usize> = alloc::vec::Vec::with_capacity(pages);

    for _ in 0..pages {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => phys_pages.push(pa),
            None => {
                for pa in &phys_pages {
                    crate::mm::pmm::free_page(*pa);
                }
                return None;
            }
        }
    }

    // ── Step 2: translate to kernel-virtual addresses ───────────────────────
    //
    // The architecture's direct physmap (PHYS_OFFSET / KERNEL_PHYS_BASE) covers
    // all of physical RAM from boot — no explicit map_page() call is needed.
    // We just derive the virtual address of each frame.
    //
    // NOTE: the physical frames may not be contiguous in physical address space
    // (the PMM's free-list allocator does not guarantee that).  They ARE
    // contiguous in virtual space only if we treat each one independently.
    // We add them as a single call to add_free_region only when the virtual
    // addresses happen to be laid out consecutively, which is always true for
    // a flat-offset physmap (virt = phys + BASE is monotone in the same order
    // as the physical addresses, but not necessarily adjacent).
    //
    // For simplicity and correctness we add each page separately.  The
    // linked_list_allocator merges adjacent free regions automatically.
    let first_virt = phys_to_kernel_virt(phys_pages[0]);

    // SAFETY: each pa came from pmm::alloc_page(), which returns an exclusively
    // owned, zero-filled 4 KiB frame.  phys_to_kernel_virt() maps it to a valid
    // kernel VA via the pre-established direct physmap.  No other Rust reference
    // aliases this region.
    unsafe {
        for &pa in &phys_pages {
            let virt = phys_to_kernel_virt(pa);
            crate::ALLOCATOR.lock().add_free_region(virt, PAGE);
        }
    }

    // ── Step 3: update accounting watermarks ───────────────────────────────
    *end_guard += pages * PAGE;
    HEAP_PAGES.fetch_add(pages, core::sync::atomic::Ordering::Relaxed);

    Some(first_virt)
}

/// Returns the current kernel heap size in pages.
pub fn committed_pages() -> usize {
    HEAP_PAGES.load(core::sync::atomic::Ordering::Relaxed)
}

// ── OOM hook called from global_alloc ──────────────────────────────────────────

/// Called by the custom `#[global_allocator]` OOM handler before panicking.
/// Tries to grow the heap by 256 pages (~1 MiB) and retries the allocation.
/// Returns `true` if more memory was made available.
pub fn handle_oom(_layout: Layout) -> bool {
    grow(256).is_some()
}
