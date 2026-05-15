//! VFS kernel-internal helpers.
//!
//! The full per-fd dispatch layer lives in the individual fs modules
//! (ext2, devfs, pipe, etc.) and is wired through the fd table in fcntl.rs.
//! This file exposes the thin wrappers that kernel subsystems (page_fault,
//! ELF loader, etc.) use to read/write files without going through syscall
//! user-space copy paths.

extern crate alloc;
use alloc::{string::String, vec::Vec};

// Re-export the seek constants used by callers.
pub use crate::fs::fcntl::{SEEK_CUR, SEEK_END, SEEK_SET};

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
pub fn fd_to_path(fd: usize) -> Option<String> {
    crate::fs::fcntl::fd_get_path(fd)
}

/// Same as fd_to_path but named fd_path for callers in time_ns / vfs_extras.
#[inline(always)]
pub fn fd_path(fd: usize) -> Option<String> {
    crate::fs::fcntl::fd_get_path(fd)
}

/// Tag an fd with a human-readable name for /proc/<pid>/fd/<n> readlink.
pub fn fd_set_debug_name(fd: usize, name: String) {
    crate::fs::fcntl::fd_set_debug_name(fd, name);
}

/// Retrieve the debug name set by fd_set_debug_name, if any.
pub fn fd_get_debug_name(fd: usize) -> Option<String> {
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

// ── inode_id_of_fd ───────────────────────────────────────────────────────────
//
// Resolves fd → path → stat().ino.  Used by flock(2) to key the advisory
// lock table on inode identity so two fds opened on the same file (or two
// hard links) share a single lock entry, matching POSIX semantics.
//
// Returns None when:
//   - the fd is not a VFS file (pipe, socket, anonymous, etc.)
//   - the path is no longer resolvable (file was unlinked)
//   - stat fails for any reason
pub fn inode_id_of_fd(fd: usize) -> Option<u64> {
    let path = crate::fs::fcntl::fd_get_path(fd)?;
    let st = crate::fs::vfs_ops::stat(&path).ok()?;
    Some(st.ino)
}

// ── flush_fd / flush_all_dirty ───────────────────────────────────────────────
//
// Called by vfs_extras::{fsync_fd, fdatasync_fd, sync_all} which are the
// implementations of fsync(2), fdatasync(2), and sync(2).
//
// Our write paths are effectively write-through on all current backends:
//
//   ext2     – fd_write calls ext2::write_data which writes directly to the
//              block layer; no page cache sits in front.  ext2::sync_inode
//              is called here as a belt-and-suspenders flush.
//   tmpfs    – purely in-memory; flushing is a no-op.
//   ext4     – read-only mount; no dirty data to flush.
//   fat32    – cluster writes go straight to the block device.
//   overlayfs– writes land on the upper layer (tmpfs); no-op.
//   devfs / procfs / sysfs – no persistent data.
//
// `include_metadata`:  true → fsync (data + metadata),
//                     false → fdatasync (data only, skip metadata flush).
//
// Returns 0 on success, negative errno on error.
pub fn flush_fd(fd: usize, include_metadata: bool) -> isize {
    let path = match crate::fs::fcntl::fd_get_path(fd) {
        Some(p) => p,
        None => return -9, // EBADF
    };

    // Resolve the mount to pick the right flush strategy.
    let h = match crate::fs::mount::resolve(&path) {
        Ok(h) => h,
        Err(e) => return e,
    };

    use crate::fs::mount::FsType;
    match h.fstype {
        FsType::Ext2 => {
            // Ask ext2 to write any pending inode/bitmap blocks.
            // The _include_metadata flag distinguishes fsync vs fdatasync;
            // for now both paths call the same ext2 entry because our
            // ext2 driver tracks data and metadata together.
            let _ = include_metadata; // reserved for future split accounting
            crate::fs::ext2::sync_inode(&path);
            0
        }
        // All other current backends are write-through or read-only.
        // Returning 0 is correct per POSIX ("shall not fail" for sync on
        // write-through systems).
        _ => 0,
    }
}

/// Flush every VFS file that has a resolvable path.
/// Called by sync(2) / syncfs(2) via vfs_extras::sync_all.
pub fn flush_all_dirty() {
    // Iterate the 256 lowest file descriptors of the current process.  A
    // proper implementation would walk the global open-file table; for the
    // current single-process-aware design this covers all active files.
    const MAX_FD: usize = 256;
    for fd in 0..MAX_FD {
        // flush_fd returns -9 (EBADF) for fds not in use; ignore errors.
        let _ = flush_fd(fd, true);
    }
}

// ── with_inode_mut ────────────────────────────────────────────────────────────
//
// Thin abstraction that lets vfs_extras::set_times update inode timestamps
// without duplicating mount-dispatch logic.  The closure receives an
// InodeMeta view; mutations to atime_ns / mtime_ns are written back to the
// backing filesystem on return.
//
// Currently only ext2 and tmpfs support mutable timestamps.  For read-only
// or virtual filesystems the closure still runs but writes are silently
// discarded (same behaviour as Linux on read-only mounts with noatime).

/// Minimal mutable view of an inode, passed to the with_inode_mut closure.
pub struct InodeMeta {
    pub atime_ns: u64,
    pub mtime_ns: u64,
    // Internal routing: the path, so we know where to write back.
    pub(crate) _path: String,
}

/// Run `f` with a mutable view of the inode for `path`, then write timestamps
/// back to the backing filesystem.  Returns without error if `path` does not
/// resolve (e.g. virtual filesystems that have no persistent inodes).
pub fn with_inode_mut<F>(path: &str, f: F)
where
    F: FnOnce(&mut InodeMeta),
{
    // Fetch current timestamps via stat so we start from real values.
    let st = match crate::fs::vfs_ops::stat(path) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut meta = InodeMeta {
        atime_ns: st.atime,
        mtime_ns: st.mtime,
        _path: alloc::string::ToString::to_string(path),
    };

    f(&mut meta);

    // Write back: delegate to the per-filesystem utimens implementation.
    // Errors are intentionally ignored (same contract as Linux on noatime /
    // read-only mounts — the syscall succeeds even if the write fails).
    let _ = crate::fs::vfs_ops::utimens(path, meta.atime_ns, meta.mtime_ns);
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
    if len == 0 {
        return 0;
    }

    // Save current position.
    let saved = seek(fd, 0, SEEK_CUR);
    if saved < 0 {
        return saved;
    } // fd doesn't support seek (pipe, socket)

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
    if len == 0 {
        return 0;
    }

    // Save current position.
    let saved = seek(fd, 0, SEEK_CUR);
    if saved < 0 {
        return saved;
    } // fd doesn't support seek (pipe, socket)

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
