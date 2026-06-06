//! close_range(2) — close all open file descriptors in [first, last].
//!
//! ## Flags
//!   CLOSE_RANGE_UNSHARE (1<<1) — unshare the fd table before closing (stub).
//!   CLOSE_RANGE_CLOEXEC (1<<2) — set FD_CLOEXEC instead of closing.

extern crate alloc;
use crate::fs::fcntl::{cloexec_range, close_fd_meta, close_fd_no_meta};
use crate::fs::process_fd;
use crate::proc::scheduler;
use alloc::vec::Vec;

pub const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// Kernel implementation of close_range(first, last, flags).
///
/// Returns 0 on success, -EINVAL (-22) if first > last or flags are unknown.
pub fn sys_close_range(first: u32, last: u32, flags: u32) -> isize {
    if first > last {
        return -22; // EINVAL
    }

    let known = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if flags & !known != 0 {
        return -22;
    }

    // CLOSE_RANGE_CLOEXEC: mark fds in range with FD_CLOEXEC instead of closing.
    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        cloexec_range(first as usize, last as usize);
        let pid = scheduler::current_pid();
        for fd in first as usize..=last as usize {
            process_fd::proc_fd_set_cloexec(pid, fd, true);
        }
        return 0;
    }

    // Collect all open fds in [first, last] for this process.
    let pid = scheduler::current_pid();
    let fds_to_close: Vec<usize> = {
        let lo = first as usize;
        let hi = last as usize;
        // Enumerate via process_fd table; fall back to all fds in range.
        process_fd::proc_fd_list(pid)
            .into_iter()
            .filter(|&fd| fd >= lo && fd <= hi)
            .collect()
    };

    for fd in fds_to_close {
        close_fd_meta(fd);
        close_fd_no_meta(fd);
    }

    0
}
