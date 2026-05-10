//! Runtime diagnostics for the allocator sub-system.
//!
//! Provides a snapshot of the free-list state inside
//! `FIXED_BLOCK_ALLOC` without requiring any heap allocation itself.

use super::buddy::{MAX_ORDER, PAGE_SIZE, block_size};
use super::fixed_size_block::FIXED_BLOCK_ALLOC;

// ── Fixed-size block stats ─────────────────────────────────────────────────

/// Per-class free-list depth for the fixed-size block allocator.
#[derive(Debug, Clone, Copy)]
pub struct FixedBlockStats {
    /// `free_counts[i]` = number of free nodes in block-size class `i`.
    pub free_counts: [usize; 10],
    /// Block sizes corresponding to each class index.
    pub block_sizes: [usize; 10],
}

/// Snapshot the fixed-size block allocator's free-list depths.
///
/// Acquires the allocator lock briefly; safe to call from any kernel context
/// that is not already holding `FIXED_BLOCK_ALLOC`.
pub fn fixed_block_stats() -> FixedBlockStats {
    const BLOCK_SIZES: [usize; 10] = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
    let alloc = FIXED_BLOCK_ALLOC.lock();
    let mut counts = [0usize; 10];
    for (i, count) in counts.iter_mut().enumerate() {
        let mut node = alloc.list_heads[i].as_deref();
        while let Some(n) = node {
            *count += 1;
            node = n.next.as_deref();
        }
    }
    FixedBlockStats { free_counts: counts, block_sizes: BLOCK_SIZES }
}

/// Print a human-readable summary of the fixed-size block allocator to the
/// kernel console.  Each line shows: `[class_idx] size_bytes : free_count`.
///
/// Example output:
/// ```text
/// allocator stats (fixed-size block):
///   [0]    8 B : 0 free
///   [1]   16 B : 4 free
///   ...
/// ```
pub fn print_fixed_block_stats() {
    let s = fixed_block_stats();
    crate::println!("allocator stats (fixed-size block):");
    for i in 0..10 {
        crate::println!(
            "  [{}] {:>6} B : {} free",
            i,
            s.block_sizes[i],
            s.free_counts[i],
        );
    }
}

// ── Buddy allocator stats ──────────────────────────────────────────────────

/// Per-order free-list depth for the buddy allocator.
#[derive(Debug, Clone, Copy)]
pub struct BuddyStats {
    /// `free_counts[n]` = number of free blocks at order `n`.
    pub free_counts: [usize; MAX_ORDER + 1],
    /// Total free memory tracked by this buddy instance, in bytes.
    pub free_bytes:  usize,
}

/// Compute per-order free-block counts for the buddy allocator embedded
/// inside `FIXED_BLOCK_ALLOC`.
///
/// Walks each free list; O(total_free_blocks) but non-allocating.
pub fn buddy_stats() -> BuddyStats {
    use super::buddy::FreeBlockIter;
    let alloc = FIXED_BLOCK_ALLOC.lock();
    let buddy = &alloc.fallback_allocator;
    let mut counts = [0usize; MAX_ORDER + 1];
    let mut total  = 0usize;
    for order in 0..=MAX_ORDER {
        let n = unsafe { FreeBlockIter::count(buddy.free_lists[order]) };
        counts[order] = n;
        total += n * block_size(order);
    }
    BuddyStats { free_counts: counts, free_bytes: total }
}

/// Print a human-readable summary of the buddy allocator's free lists.
pub fn print_buddy_stats() {
    let s = buddy_stats();
    crate::println!("allocator stats (buddy):");
    for order in 0..=MAX_ORDER {
        let size_kib = block_size(order) / 1024;
        crate::println!(
            "  order {:>2} ({:>5} KiB) : {} free",
            order,
            size_kib,
            s.free_counts[order],
        );
    }
    crate::println!(
        "  total buddy free: {} KiB",
        s.free_bytes / 1024,
    );
}
