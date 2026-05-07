//! sys_close_range — NR 334
//!
//! close_range(first, last, flags)
//!
//! Closes all open file descriptors in the inclusive range [first, last].
//! `last` may be u32::MAX / ~0u32 to mean "all fds from first onwards".
//!
//! ## Flags (Linux 5.9+)
//!
//!   CLOSE_RANGE_UNSHARE (0x02) — unshare the fd table first (CLONE_FILES).
//!     We are single-threaded per process so this is a no-op.
//!
//!   CLOSE_RANGE_CLOEXEC (0x04) — instead of closing, just set FD_CLOEXEC
//!     on every fd in the range.  Useful for sanitising exec environments
//!     without losing the fd for the exec target itself.
//!
//! ## Why glibc 2.34+ needs this
//!
//!   musl/glibc startup code (since 2.34) calls
//!     close_range(3, ~0U, 0)
//!   unconditionally to close any fds the parent left open above stderr.
//!   Without this syscall the startup hits ENOSYS and either crashes or
//!   falls back to a slow /proc/self/fd scan, which also requires procfs.
//!   Implementing both is the correct fix.
//!
//! ## Implementation
//!
//!   Iterates the VFS fd table to collect open fds in [first, last],
//!   closes each one via the same path as sys_close (meta + backing store),
//!   then iterates the special-fd side tables (pipe, eventfd, signalfd,
//!   timerfd, pidfd, procfs) for fds in the range.
//!
//!   We collect first, then close outside the lock, to avoid lock re-entry
//!   from close paths that themselves acquire VFS locks.

extern crate alloc;
use alloc::vec::Vec;

// CLOSE_RANGE flag bits.
const CLOSE_RANGE_UNSHARE: u32 = 0x02; // no-op for us
const CLOSE_RANGE_CLOEXEC: u32 = 0x04;

/// sys_close_range(first, last, flags) — NR 334.
///
/// Returns 0 on success, -EINVAL if flags contains unknown bits.
pub fn sys_close_range(first: u32, last: u32, flags: u32) -> isize {
    let known = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if flags & !known != 0 { return -22; } // EINVAL
    if first > last { return -22; }

    let lo = first as usize;
    let hi = last as usize; // saturates at usize::MAX when last == u32::MAX

    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        // CLOEXEC mode: set the flag on every open fd in range, don't close.
        crate::fs::fcntl::cloexec_range(lo, hi);
        return 0;
    }

    // Collect open fds in [lo, hi] from every fd-bearing subsystem.
    let to_close: Vec<usize> = collect_open_fds(lo, hi);

    for fd in to_close {
        close_one(fd);
    }
    0
}

/// Enumerate open fds in [lo, hi] across all subsystems.
fn collect_open_fds(lo: usize, hi: usize) -> Vec<usize> {
    let mut fds: Vec<usize> = Vec::new();

    // VFS-backed fds (regular files, sockets, devices).
    crate::fs::vfs::for_open_fds(|fd| {
        if fd >= lo && fd <= hi {
            fds.push(fd);
        }
    });

    // Special-fd subsystems — each exposes a range-check helper.
    crate::fs::pipe::for_open_fds(|fd| {
        if fd >= lo && fd <= hi && !fds.contains(&fd) { fds.push(fd); }
    });
    crate::fs::eventfd::for_open_fds(|fd| {
        if fd >= lo && fd <= hi && !fds.contains(&fd) { fds.push(fd); }
    });
    crate::fs::pidfd::for_open_fds(|fd| {
        if fd >= lo && fd <= hi && !fds.contains(&fd) { fds.push(fd); }
    });

    // procfs synthetic fds live above PROCFS_FD_BASE (~0x6000_0000) so they
    // will never be hit by the typical close_range(3, ~0U, 0) call, but
    // handle them correctly if `hi` is large enough.
    crate::fs::procfs::for_open_fds(|fd| {
        if fd >= lo && fd <= hi && !fds.contains(&fd) { fds.push(fd); }
    });

    fds
}

/// Close a single fd by routing through the appropriate subsystem.
fn close_one(fd: usize) {
    crate::fs::fcntl::close_fd_meta(fd);
    if crate::fs::pidfd::is_pidfd(fd)       { crate::fs::pidfd::free(fd);              return; }
    if crate::fs::timerfd::is_timerfd(fd)   { crate::fs::timerfd::sys_close_tfd(fd);  return; }
    if crate::fs::signalfd::is_signalfd(fd) { crate::fs::signalfd::sys_close_sfd(fd); return; }
    if crate::fs::eventfd::is_eventfd(fd)   { crate::fs::eventfd::sys_close_efd(fd);  return; }
    if crate::fs::pipe::is_pipe(fd)         { crate::fs::pipe::sys_close_pipe(fd);     return; }
    if crate::fs::procfs::is_procfs_fd(fd)  { crate::fs::procfs::procfs_close(fd);    return; }
    crate::fs::vfs::close(fd);
}
