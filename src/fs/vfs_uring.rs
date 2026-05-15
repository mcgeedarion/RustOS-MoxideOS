//! VFS helpers required exclusively by io_uring.
//!
//! Split into a separate file to keep vfs.rs clean.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

// ── IoUring fd table ──────────────────────────────────────────────────────────
//
// We reserve fd numbers in [URING_FD_BASE, URING_FD_BASE + MAX_URING_FDS) for
// io_uring instances.  The number stored is the ring_idx into RING_TABLE.

const URING_FD_BASE: usize = 0x5000_0000;
const MAX_URING_FDS: usize = 256;

static URING_FD_TABLE: Mutex<[Option<usize>; MAX_URING_FDS]> = Mutex::new([None; MAX_URING_FDS]);

/// Allocate a new fd that refers to `ring_idx`.  Returns -ENFILE on overflow.
pub fn alloc_fd_for_uring(ring_idx: usize) -> Option<usize> {
    let mut tbl = URING_FD_TABLE.lock();
    for (i, slot) in tbl.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(ring_idx);
            return Some(URING_FD_BASE + i);
        }
    }
    None
}

/// Return the ring_idx associated with `fd`, if it is an io_uring fd.
pub fn uring_fd_to_ring(fd: usize) -> Option<usize> {
    if fd < URING_FD_BASE || fd >= URING_FD_BASE + MAX_URING_FDS {
        return None;
    }
    URING_FD_TABLE.lock()[fd - URING_FD_BASE]
}

/// Release an io_uring fd (called from the close path).
pub fn close_uring_fd(fd: usize) -> bool {
    if fd < URING_FD_BASE || fd >= URING_FD_BASE + MAX_URING_FDS {
        return false;
    }
    let mut tbl = URING_FD_TABLE.lock();
    if tbl[fd - URING_FD_BASE].is_some() {
        tbl[fd - URING_FD_BASE] = None;
        true
    } else {
        false
    }
}

/// Returns true if `fd` is an io_uring fd.
pub fn is_uring_fd(fd: usize) -> bool {
    uring_fd_to_ring(fd).is_some()
}

// ── fsync via VFS ─────────────────────────────────────────────────────────────

/// Flush dirty data for `fd` to backing storage.
/// Delegates to the underlying VFS fd_sync if available; otherwise a no-op
/// (returning 0) for in-memory filesystems where flushing is meaningless.
pub fn fsync(fd: usize) -> isize {
    crate::fs::fcntl::fd_sync(fd)
}

// ── pread / pwrite with kernel slice (no user-copy) ───────────────────────────

/// Positional read directly into a kernel slice — no user-space copy.
/// Used by io_uring READ/READ_FIXED where the destination buffer is
/// kernel-mapped registered memory.
pub fn pread_buf(fd: usize, buf: &mut [u8], offset: i64) -> isize {
    if buf.is_empty() {
        return 0;
    }
    let saved = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR);
    if saved < 0 {
        return saved;
    }
    let s = crate::fs::vfs::seek(fd, offset, crate::fs::vfs::SEEK_SET);
    if s < 0 {
        crate::fs::vfs::seek(fd, saved, crate::fs::vfs::SEEK_SET);
        return s;
    }
    let n = crate::fs::vfs::read(fd, buf);
    crate::fs::vfs::seek(fd, saved, crate::fs::vfs::SEEK_SET);
    n
}

/// Positional write from a kernel slice — no user-space copy.
pub fn pwrite_buf(fd: usize, buf: &[u8], offset: i64) -> isize {
    if buf.is_empty() {
        return 0;
    }
    let saved = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR);
    if saved < 0 {
        return saved;
    }
    let s = crate::fs::vfs::seek(fd, offset, crate::fs::vfs::SEEK_SET);
    if s < 0 {
        crate::fs::vfs::seek(fd, saved, crate::fs::vfs::SEEK_SET);
        return s;
    }
    let n = crate::fs::vfs::write(fd, buf);
    crate::fs::vfs::seek(fd, saved, crate::fs::vfs::SEEK_SET);
    n
}
