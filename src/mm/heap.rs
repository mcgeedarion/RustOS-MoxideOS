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
//!      arch-level kernel init.  Sets `HEAP_BYTES` to
//!      `initial_pages * PAGE_SIZE`.
//!
//!   2. `grow(pages)` — called from the global allocator's OOM handler (or any
//!      kernel path that needs more heap).  Allocates `pages` physical pages
//!      from the PMM, derives their kernel-virtual addresses through the
//!      architecture's direct physmap, and hands that region to the
//!      linked_list_allocator via `add_free_region`.
//!
//!   3. On both supported architectures the kernel direct map covers the entire
//!      physical address space in the higher half (x86-64: `PHYS_OFFSET + pa`;
//!      RISC-V: `KERNEL_PHYS_BASE + pa`).  Newly allocated pages are therefore
//!      immediately addressable without any additional `map_page()` call.
//!
//! ## Safety invariants
//! * `HEAP_BYTES` tracks the total number of bytes committed to the heap for
//!   `/proc/meminfo` accounting. It is NOT a virtual address watermark.
//! * `HEAP_BYTES` and `HEAP_PAGES` are protected by atomics; concurrent grow
//!   calls are safe provided the PMM is independently thread-safe.
//! * We never shrink the kernel heap — `free` returns pages to the allocator
//!   free list but they stay mapped.
//! * Maximum kernel heap is bounded by the PMM free list — asking for more
//!   pages than are available returns `None`.
//! * `grow` uses a fixed-size stack array (max `MAX_GROW_PAGES` frames per
//!   call) to avoid calling the global allocator re-entrantly, which would
//!   deadlock on `ALLOCATOR`.

extern crate alloc;

use core::alloc::Layout;
use spin::Mutex;

// ---------------------------------------------------------------------------
// Architecture-specific page size
// ---------------------------------------------------------------------------
// AArch64 supports 4 KiB, 16 KiB, and 64 KiB translation granules.
// x86-64 and RISC-V only support 4 KiB pages in the configurations rustos uses.
// If a new architecture is added, define its granule size here.

#[cfg(target_arch = "x86_64")]
const PAGE_SIZE: usize = 4096;

#[cfg(target_arch = "riscv64")]
const PAGE_SIZE: usize = 4096;

#[cfg(target_arch = "aarch64")]
const PAGE_SIZE: usize = crate::arch::aarch64::mem_layout::GRANULE_SIZE;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "riscv64",
    target_arch = "aarch64",
)))]
compile_error!(
    "Unsupported architecture: define PAGE_SIZE and phys_to_kernel_virt for this target in src/mm/heap.rs"
);

// ---------------------------------------------------------------------------
// Architecture-specific physmap translation
// ---------------------------------------------------------------------------
// On x86-64 rustos identity-maps all of physical RAM at PHYS_OFFSET.
// On RISC-V it is mapped at KERNEL_PHYS_BASE (same role, different name).
// Both are flat-offset maps: virt = phys + BASE.

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

#[cfg(target_arch = "aarch64")]
#[inline]
fn phys_to_kernel_virt(pa: usize) -> usize {
    crate::arch::aarch64::mem_layout::va48::phys_to_virt(pa)
}

// ---------------------------------------------------------------------------
// Maximum frames that can be requested in a single grow() call.
// This caps the fixed-size stack array used to collect PMM frames without
// calling the global allocator (which would risk re-entrant deadlock).
// ---------------------------------------------------------------------------
const MAX_GROW_PAGES: usize = 512;

// ---------------------------------------------------------------------------
// Accounting state
// ---------------------------------------------------------------------------

/// Total bytes currently committed to the kernel heap (for /proc/meminfo).
///
/// This is a simple sum of `pages * PAGE_SIZE` across all `grow` calls.
/// It is NOT a virtual address watermark — PMM frames may be non-contiguous.
///
/// `Ordering::Relaxed` is sufficient here because HEAP_BYTES is used only for
/// informational accounting (e.g., /proc/meminfo reads). No other memory
/// operation is ordered relative to this counter, so acquire/release semantics
/// are unnecessary.
static HEAP_BYTES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Total pages currently committed to the kernel heap (for /proc/meminfo).
///
/// Same relaxed-ordering justification as `HEAP_BYTES` — purely informational.
static HEAP_PAGES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Spin-lock used to serialise concurrent `grow` calls so that the PMM
/// alloc + allocator add_free_region sequence is atomic with respect to other
/// grow callers.
static GROW_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Called once at boot after the linked_list_allocator has been initialised.
/// Records the initial heap size for accounting purposes.
///
/// `_heap_virt_start` is accepted for API compatibility but is not stored —
/// the accounting is byte-based, not watermark-based.
pub fn init_heap_tracking(_heap_virt_start: usize, initial_pages: usize) {
    // Relaxed: called from a single CPU before SMP is brought up.
    HEAP_PAGES.store(initial_pages, core::sync::atomic::Ordering::Relaxed);
    HEAP_BYTES.store(
        initial_pages * PAGE_SIZE,
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Grow the kernel heap by `pages` pages.
///
/// Allocates `pages` physical frames from the PMM, translates each to its
/// kernel-virtual address through the architecture's flat physmap, and hands
/// the resulting region to the global allocator via `add_free_region`.
///
/// Returns the kernel-virtual address of the first new byte on success.
/// Returns `None` on PMM exhaustion or if `pages` exceeds `MAX_GROW_PAGES`.
///
/// Passing `pages == 0` is a no-op and returns `None` (callers must not rely
/// on a meaningful address for a zero-page grow).
///
/// # Safety contract
/// Each frame is freshly allocated from the PMM, zero-filled, and not aliased
/// by any existing Rust reference. The physmap makes them immediately
/// accessible at `phys_to_kernel_virt(pa)` without an explicit `map_page()`.
///
/// This function uses a fixed stack array of size `MAX_GROW_PAGES` to avoid
/// calling the global allocator internally, preventing re-entrant deadlock
/// when invoked from the OOM handler.
pub fn grow(pages: usize) -> Option<usize> {
    if pages == 0 {
        return None;
    }

    if pages > MAX_GROW_PAGES {
        // Callers that need more than MAX_GROW_PAGES frames should call
        // grow() in a loop.
        return None;
    }

    let _guard = GROW_LOCK.lock();

    // Fixed-size stack array — avoids any heap allocation inside grow(),
    // which would risk re-entrant deadlock on ALLOCATOR.
    let mut phys_pages = [0usize; MAX_GROW_PAGES];
    let mut allocated = 0usize;

    for i in 0..pages {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                phys_pages[i] = pa;
                allocated += 1;
            }
            None => {
                // PMM exhausted — roll back already-allocated frames.
                for j in 0..allocated {
                    crate::mm::pmm::free_page(phys_pages[j]);
                }
                return None;
            }
        }
    }

    let first_virt = phys_to_kernel_virt(phys_pages[0]);

    // SAFETY: each pa came from pmm::alloc_page(), which returns an exclusively
    // owned, zero-filled PAGE_SIZE frame. phys_to_kernel_virt() maps it to a
    // valid kernel VA via the pre-established direct physmap. No other Rust
    // reference aliases this region.
    unsafe {
        for i in 0..allocated {
            let virt = phys_to_kernel_virt(phys_pages[i]);
            crate::ALLOCATOR.lock().add_free_region(virt, PAGE_SIZE);
        }
    }

    // Relaxed: purely informational counters, see HEAP_BYTES/HEAP_PAGES docs.
    HEAP_PAGES.fetch_add(pages, core::sync::atomic::Ordering::Relaxed);
    HEAP_BYTES.fetch_add(pages * PAGE_SIZE, core::sync::atomic::Ordering::Relaxed);

    Some(first_virt)
}

/// Returns the current kernel heap size in pages.
pub fn committed_pages() -> usize {
    HEAP_PAGES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Returns the total bytes committed to the kernel heap.
pub fn committed_bytes() -> usize {
    HEAP_BYTES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Called by the custom `#[global_allocator]` OOM handler before panicking.
///
/// Attempts to grow the heap by enough pages to satisfy `layout`, rounded up
/// to a multiple of `PAGE_SIZE`, plus a minimum of 256 pages to amortise
/// future small allocations.
///
/// Returns `true` if at least one page was successfully added so the allocator
/// can retry.  Returns `false` if the PMM is exhausted.
pub fn handle_oom(layout: Layout) -> bool {
    // Compute how many pages are needed for this specific allocation.
    let needed_pages = layout.size().div_ceil(PAGE_SIZE).max(1);
    // Always grow by at least 256 pages (1 MiB at 4 KiB granule) to amortise
    // future allocations, but cap at MAX_GROW_PAGES per grow() call.
    let grow_pages = needed_pages.max(256).min(MAX_GROW_PAGES);

    if grow(grow_pages).is_some() {
        return true;
    }

    // If the amortised batch failed (PMM near-empty), try the exact minimum.
    if needed_pages < grow_pages {
        return grow(needed_pages.min(MAX_GROW_PAGES)).is_some();
    }

    false
}
