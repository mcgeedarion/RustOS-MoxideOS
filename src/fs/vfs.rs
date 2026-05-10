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
pub use crate::fs::fcntl::{SEEK_SET, SEEK_CUR, SEEK_END};

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
    crate::fs::fcntl::fd_open(path, flags as i32)
}

pub fn close(fd: usize) -> isize {
    crate::fs::fcntl::fd_close(fd);
    0
}

pub fn seek(fd: usize, offset: i64, whence: i32) -> isize {
    crate::fs::fcntl::fd_seek(fd, offset, whence)
}

// ── file_size ─────────────────────────────────────────────────────────────
//
// Returns the size in bytes of the file backing `fd`, or None if the fd
// is not a regular VFS file (pipe, socket, device, synthetic fd).
// Used by RLIMIT_FSIZE enforcement in io_syscalls::check_fsize_limit.

pub fn file_size(fd: usize) -> Option<usize> {
    crate::fs::fcntl::fd_size(fd)
}

// ── fd path / debug-name helpers ─────────────────────────────────────────────

/// Return the VFS path registered for `fd`, if any.
pub fn fd_to_path(fd: usize) -> Option<alloc::string::String> {
    crate::fs::fcntl::fd_get_path(fd)
}

/// Tag an fd with a human-readable name for /proc/<pid>/fd/<n> readlink.
pub fn fd_set_debug_name(fd: usize, name: alloc::string::String) {
    crate::fs::fcntl::fd_set_debug_name(fd, name);
}

/// Retrieve the debug name set by fd_set_debug_name, if any.
pub fn fd_get_debug_name(fd: usize) -> Option<alloc::string::String> {
    crate::fs::fcntl::fd_get_debug_name(fd)
}

/// Duplicate `old_fd` as `new_fd`.
pub fn dup_as(old_fd: usize, new_fd: usize) -> isize {
    crate::fs::fcntl::dup_as_raw(old_fd, new_fd)
}

/// Duplicate `fd` using the lowest available fd >= `min_fd`.
pub fn dup_from(fd: usize, min_fd: usize) -> isize {
    crate::fs::fcntl::dup_from_raw(fd, min_fd)
}

/// Create a new file at `path`.
pub fn create(path: &str) -> Result<(), isize> {
    crate::fs::fcntl::fd_create(path)
}

/// Remove a file.
pub fn unlink(path: &str) -> Result<(), isize> {
    crate::fs::fcntl::fd_unlink(path)
}

/// Create a hard link.
pub fn link(old: &str, new: &str) -> Result<(), isize> {
    crate::fs::fcntl::fd_link(old, new)
}

/// Remove a directory.
pub fn rmdir(path: &str) -> Result<(), isize> {
    crate::fs::fcntl::fd_rmdir(path)
}

// ── pread ────────────────────────────────────────────────────────────────
// Kernel-internal positional read.  Saves and restores the file offset so
// pread has no side-effect on the fd's seek position (POSIX pread64).
//
// `buf` must be a kernel virtual address (e.g. a freshly allocated page
// frame). Unlike sys_pread64, no user-space copy is performed.
//
// Returns:
//   >= 0   number of bytes read
//   <  0   negative errno (-9 EBADF, -5 EIO, etc.)
//
// # Reentrancy caveat
// The seek-save / seek-to-offset / read / seek-restore sequence is not
// atomic.  Concurrent calls on the *same* fd will race.  All current
// callers (ELF loader, page-fault handler) either hold the scheduler
// lock or operate on fds not shared between concurrently runnable threads,
// so this is safe in practice.  A proper per-fd position lock is the
// correct long-term fix.
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

// ── pwrite ───────────────────────────────────────────────────────────────
// Kernel-internal positional write.  Saves and restores the file offset so
// pwrite has no side-effect on the fd's seek position (POSIX pwrite64).
//
// `buf` must be a kernel virtual address.  Unlike sys_pwrite64, no
// user-space copy is performed by this function.
//
// Returns:
//   >= 0   number of bytes written
//   <  0   negative errno (-9 EBADF, -28 ENOSPC, etc.)
//
// # Reentrancy caveat
// Same as pread: the seek-save/restore sequence is not atomic.  Concurrent
// calls on the same fd race.  sys_pwrite64 serialises through the scheduler
// at syscall entry, so it is safe for the current single-CPU implementation.
//
// Called from:
//   - fs/io_syscalls.rs: sys_pwrite64
pub fn pwrite(fd: usize, buf: *const u8, len: usize, offset: i64) -> isize {
    if len == 0 { return 0; }

    // Save current position.
    let saved = seek(fd, 0, SEEK_CUR);
    if saved < 0 { return saved; }   // fd doesn't support seek (pipe, socket)

    // Seek to the requested offset.
    let seeked = seek(fd, offset, SEEK_SET);
    if seeked < 0 {
        seek(fd, saved, SEEK_SET);
        return seeked;
    }

    // Write directly from the caller-supplied kernel buffer.
    // SAFETY: caller guarantees `buf` points to `len` bytes of valid
    // kernel-mapped readable memory.
    let kbuf = unsafe { core::slice::from_raw_parts(buf, len) };
    let n = write(fd, kbuf);

    // Restore position regardless of write result.
    seek(fd, saved, SEEK_SET);

    n
}
