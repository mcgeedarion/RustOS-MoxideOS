//! Filesystem syscalls — `sys_open`, `sys_read`, `sys_write`, `sys_close`,
//! `sys_seek`, `sys_ioctl`.
//!
//! `sys_open` is the key dispatch point: it now understands scheme URLs
//! (e.g. `"net:eth0"`, `"blk:vda"`) and routes them through `SCHEME_TABLE`.
//! Classic POSIX paths (starting with `/`) continue to go through the
//! legacy VFS path resolver unchanged.
//!
//! # Fd table layout
//!
//! Each open file descriptor is one of:
//!
//! - `FdEntry::Legacy(Arc<VfsNode>)` — classic VFS file/dir/pipe/socket.
//! - `FdEntry::Scheme { handler: Arc<dyn Scheme>, fid: SchemeFileId }` —
//!   resource backed by a scheme handler (in-kernel or userspace proxy).
//!
//! Both variants expose the same `read`/`write`/`close`/`seek`/`ioctl`
//! interface; the dispatch in each syscall below is a trivial match.

use alloc::sync::Arc;

use scheme_api::{OpenFlags, SchemeError};

use crate::{
    fs::{
        scheme_table::{is_scheme_url, Scheme, SCHEME_TABLE},
        vfs_ops,
    },
    proc::{
        current_process,
        fd_table::{FdEntry, RawFd},
    },
};

/// Open a file, device, or scheme resource.
///
/// `path` is a NUL-terminated string in userspace.  `flags` is a bitfield
/// of `OpenFlags` values.
///
/// Returns a non-negative raw file descriptor on success, or a negative
/// errno value on failure.
pub fn sys_open(path: &str, flags: u32) -> i64 {
    let flags = match OpenFlags::from_bits(flags) {
        Some(f) => f,
        None => return -22, // EINVAL
    };

    if is_scheme_url(path) {
        match SCHEME_TABLE.open(path, flags) {
            Ok((handler, fid)) => {
                let proc = current_process();
                let fd = proc.fd_table().alloc(FdEntry::Scheme { handler, fid });
                fd as i64
            },
            Err(e) => e.to_errno(),
        }
    } else {
        match vfs_ops::open(path, flags) {
            Ok(node) => {
                let proc = current_process();
                let fd = proc.fd_table().alloc(FdEntry::Legacy(node));
                fd as i64
            },
            Err(e) => e.to_errno(),
        }
    }
}

/// Read up to `len` bytes from `fd` into `buf`.
///
/// Returns bytes read (>= 0) or a negative errno.
pub fn sys_read(fd: RawFd, buf: &mut [u8]) -> i64 {
    let proc = current_process();
    let entry = match proc.fd_table().get(fd) {
        Some(e) => e,
        None => return -9, // EBADF
    };

    match entry {
        FdEntry::Legacy(node) => vfs_ops::read(&node, buf)
            .map(|n| n as i64)
            .unwrap_or_else(|e| e.to_errno()),
        FdEntry::Scheme { handler, fid } => handler
            .read(fid, buf)
            .map(|n| n as i64)
            .unwrap_or_else(|e| e.to_errno()),
    }
}

/// Write `buf` to `fd`.
///
/// Returns bytes written (>= 0) or a negative errno.
pub fn sys_write(fd: RawFd, buf: &[u8]) -> i64 {
    let proc = current_process();
    let entry = match proc.fd_table().get(fd) {
        Some(e) => e,
        None => return -9, // EBADF
    };

    match entry {
        FdEntry::Legacy(node) => vfs_ops::write(&node, buf)
            .map(|n| n as i64)
            .unwrap_or_else(|e| e.to_errno()),
        FdEntry::Scheme { handler, fid } => handler
            .write(fid, buf)
            .map(|n| n as i64)
            .unwrap_or_else(|e| e.to_errno()),
    }
}

/// Close `fd` and release associated resources.
pub fn sys_close(fd: RawFd) -> i64 {
    let proc = current_process();
    let entry = match proc.fd_table().remove(fd) {
        Some(e) => e,
        None => return -9, // EBADF
    };

    match entry {
        FdEntry::Legacy(node) => vfs_ops::close(&node)
            .map(|_| 0i64)
            .unwrap_or_else(|e| e.to_errno()),
        FdEntry::Scheme { handler, fid } => handler
            .close(fid)
            .map(|_| 0i64)
            .unwrap_or_else(|e| e.to_errno()),
    }
}

/// Reposition the file offset of `fd`.
///
/// `whence`: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END.
pub fn sys_seek(fd: RawFd, offset: i64, whence: u8) -> i64 {
    let proc = current_process();
    let entry = match proc.fd_table().get(fd) {
        Some(e) => e,
        None => return -9, // EBADF
    };

    match entry {
        FdEntry::Legacy(node) => vfs_ops::seek(&node, offset, whence)
            .map(|pos| pos as i64)
            .unwrap_or_else(|e| e.to_errno()),
        FdEntry::Scheme { handler, fid } => handler
            .seek(fid, offset, whence)
            .unwrap_or_else(|e| e.to_errno()),
    }
}

/// Device control.
pub fn sys_ioctl(fd: RawFd, cmd: u64, arg: usize) -> i64 {
    let proc = current_process();
    let entry = match proc.fd_table().get(fd) {
        Some(e) => e,
        None => return -9, // EBADF
    };

    match entry {
        FdEntry::Legacy(node) => vfs_ops::ioctl(&node, cmd, arg)
            .map(|n| n as i64)
            .unwrap_or_else(|e| e.to_errno()),
        FdEntry::Scheme { handler, fid } => handler
            .ioctl(fid, cmd, arg)
            .map(|n| n as i64)
            .unwrap_or_else(|e| e.to_errno()),
    }
}
