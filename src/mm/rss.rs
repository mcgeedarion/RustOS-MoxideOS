//! Resident Set Size (RSS) accounting.
//!
//! ## Purpose
//!
//! Tracks the number of physical pages currently mapped into a process's
//! address space and enforces `RLIMIT_RSS`.
//!
//! ## Linux semantics
//!
//! `RLIMIT_RSS` is advisory on modern Linux — the kernel does not OOM-kill
//! on RSS overcommit.  We follow the same approach: charge/check on page
//! allocation, but only return `ENOMEM` from `mmap`/`brk` when the process
//! is **strictly over** its hard limit (soft limit is informational only).
//!
//! ## Integration points
//!
//! - `mm/mmap.rs` — call `rss_charge(pid, pages)` after a new anonymous
//!   mapping is backed by physical frames; `rss_discharge(pid, pages)` on
//!   `munmap`.
//! - `mm/page_fault.rs` — call `rss_charge(pid, 1)` each time a demand-zero
//!   fault allocates a new frame.
//! - `proc/exit.rs` — call `rss_reset(pid)` on process exit.

use crate::proc::rlimit::{RLIMIT_RSS, RLIM_INFINITY};
use crate::proc::scheduler::{with_proc, with_proc_mut};

/// Charge `pages` physical pages to process `pid`.
///
/// Returns 0 on success, `-ENOMEM` (-12) if the **hard** `RLIMIT_RSS` would
/// be exceeded.  The soft limit is informational and never blocks allocation.
pub fn rss_charge(pid: usize, pages: usize) -> isize {
    with_proc_mut(pid, |p| {
        let (_, hard) = p.rlimits.get(RLIMIT_RSS);
        let new_rss = p.rss_pages.saturating_add(pages as u64);
        if hard != RLIM_INFINITY && new_rss > hard {
            return -12isize; // ENOMEM
        }
        p.rss_pages = new_rss;
        0isize
    })
    .unwrap_or(0) // if pid not found just succeed silently
}

/// Refund `pages` physical pages from process `pid`'s RSS counter.
pub fn rss_discharge(pid: usize, pages: usize) {
    let _ = with_proc_mut(pid, |p| {
        p.rss_pages = p.rss_pages.saturating_sub(pages as u64);
    });
}

/// Reset RSS counter to zero (called from `exit.rs`).
pub fn rss_reset(pid: usize) {
    let _ = with_proc_mut(pid, |p| {
        p.rss_pages = 0;
    });
}

/// Read the current RSS page count for `pid`.
pub fn rss_pages(pid: usize) -> u64 {
    with_proc(pid, |p| p.rss_pages).unwrap_or(0)
}
