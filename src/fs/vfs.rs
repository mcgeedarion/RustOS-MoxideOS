//! VFS kernel-internal helpers.
//!
//! The full per-fd dispatch layer lives in the individual fs modules
//! (ext2, devfs, pipe, etc.) and is wired through the fd table in fcntl.rs.
//! This file exposes the thin wrappers that kernel subsystems (page_fault,
//! ELF loader, etc.) use to read/write files without going through syscall
//! user-space copy paths.

extern crate alloc;
use alloc::vec::Vec;

// Re-export the seek constants used by callers.
pub use crate::fs::fcntl::{SEEK_SET, SEEK_CUR};

// ── fd-table dispatch stubs ───────────────────────────────────────────────
// These are thin forwarders into fcntl's fd table. They exist so callers
// can write `vfs::read(fd, buf)` without importing fcntl directly.

pub fn read(fd: usize, buf: &mut [u8]) -> isize {
    crate::fs::fcntl::fd_read(fd, buf)
}

pub fn write(fd: usize, buf: &[u8]) -> isize {
    crate::fs::fcntl::fd_write(fd, buf)
}

pub fn open(path: &str, flags: u32) -> Result<usize, isize> {
    crate::fs::fcntl::fd_open(path, flags)
}

pub fn close(fd: usize) -> isize {
    crate::fs::fcntl::fd_close(fd)
}

pub fn seek(fd: usize, offset: i64, whence: i32) -> isize {
    crate::fs::fcntl::fd_seek(fd, offset, whence)
}

// ── pread ────────────────────────────────────────────────────────────────
// Kernel-internal positional read. Saves and restores the file offset so
// pread has no side-effect on the fd's seek position (POSIX pread64).
//
// `buf` must be a kernel virtual address (e.g. a freshly allocated page
// frame). Unlike sys_pread64, no user-space copy is performed.
//
// Returns:
//   >= 0   number of bytes read
//   <  0   negative errno (-9 EBADF, -5 EIO, etc.)
//
// Called from:
//   - mm/page_fault.rs: FileBacked VMA demand fault
//   - fs/elf.rs:        ELF segment loading
pub fn pread(fd: usize, buf: *mut u8, len: usize, offset: i64) -> isize {
    if len == 0 { return 0; }

    // Save current position.
    let saved = seek(fd, 0, SEEK_CUR);
    if saved < 0 { return saved; }   // fd doesn't support seek (pipe, socket)

    // Seek to the requested offset.
    let seeked = seek(fd, offset, SEEK_SET);
    if seeked < 0 {
        // Restore and bail.
        seek(fd, saved, SEEK_SET);
        return seeked;
    }

    // Read directly into the caller-supplied kernel buffer.
    // SAFETY: caller guarantees `buf` points to `len` bytes of valid
    // kernel-mapped writable memory (alloc_page() return value).
    let kbuf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let n = read(fd, kbuf);

    // Restore position regardless of read result.
    seek(fd, saved, SEEK_SET);

    n
}
