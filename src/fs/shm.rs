//! POSIX shared memory: shm_open(3) and shm_unlink(3).
//!
//! ## Linux implementation
//! Linux backs POSIX shm with a dedicated tmpfs instance mounted (internally)
//! at "/dev/shm".  We do exactly the same: our ramfs already mounts a TmpFs
//! instance at "/dev/shm" via `ensure_defaults()`.  shm_open simply:
//!   1. Normalises the name ("/foo" → "/dev/shm/foo").
//!   2. Applies O_CREAT / O_EXCL / O_TRUNC semantics against that tmpfs.
//!   3. Opens an FD via `vfs::open`.
//!
//! ## syscall numbers
//! Linux 5.17+ added memfd_secret (NR 447) and rseq (NR 334); shm_open /
//! shm_unlink are glibc/musl library functions that are implemented in terms
//! of open(2)/unlink(2) — so there is no separate NR_SHM_OPEN kernel number
//! on x86-64.  We expose `sys_shm_open` / `sys_shm_unlink` here for the
//! syscall dispatch table in case a statically linked binary invokes them
//! directly, but musl will reach us via the open/unlink paths automatically.

extern crate alloc;
use crate::fs::vfs;
use crate::fs::vfs_ops;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::copy_to_user;
use alloc::string::{String, ToString};

// O_* flags (Linux x86-64 ABI)
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_CLOEXEC: u32 = 0o2000000;

/// Normalise a POSIX shm name into an absolute /dev/shm path.
///
/// POSIX requires the name to start with '/'.  We strip any extra leading
/// slashes and prepend "/dev/shm".
fn shm_path(name: &str) -> Option<String> {
    let name = name.trim_start_matches('/');
    if name.is_empty() {
        return None;
    }
    // Reject names with embedded slashes (subdirectories not allowed by POSIX).
    if name.contains('/') {
        return None;
    }
    Some(alloc::format!("/dev/shm/{}", name))
}

/// Open (or create) a POSIX shared memory object.
///
/// Equivalent to `open("/dev/shm/<name>", oflag, mode)` with some
/// extra POSIX checks (name must be a single component, etc.).
///
/// Returns a non-negative FD on success, or a negative errno on failure.
pub fn shm_open(name: &str, oflag: u32, _mode: u32) -> isize {
    // Ensure the /dev/shm tmpfs instance is ready.
    crate::fs::ramfs::tmpfs_mount("/dev/shm", 64 * 1024 * 1024);

    let path = match shm_path(name) {
        Some(p) => p,
        None => return -22, // EINVAL
    };

    let exists = vfs::exists(&path);

    // O_CREAT | O_EXCL: must not already exist.
    if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 && exists {
        return -17; // EEXIST
    }

    // O_CREAT: create if absent.
    if oflag & O_CREAT != 0 && !exists {
        if let Err(e) = crate::fs::ramfs::tmpfs_create(&path) {
            return e;
        }
    }

    // File must now exist.
    if !vfs::exists(&path) {
        return -2; // ENOENT
    }

    // O_TRUNC: reset size to zero.
    if oflag & O_TRUNC != 0 {
        let _ = vfs_ops::truncate(&path, 0);
    }

    // Open via VFS.  Pass the original oflag so the FD table records the
    // access mode (O_RDONLY / O_RDWR) correctly.
    match vfs::open(&path, oflag) {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

/// Remove a POSIX shared memory object.
///
/// The backing file is deleted from /dev/shm; any still-open FDs retain
/// access until they are closed (nlink-based deferred free in ramfs).
pub fn shm_unlink(name: &str) -> isize {
    let path = match shm_path(name) {
        Some(p) => p,
        None => return -22,
    };
    match vfs_ops::unlink(&path) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ── Syscall-layer wrappers (for direct invocation by statically linked
// binaries)

/// sys_shm_open(name_va, oflag, mode)  — called when a binary invokes the
/// open(2) path with a /dev/shm/ prefix (musl does this); kept here for
/// completeness and for any ABI path that jumps directly.
pub fn sys_shm_open(name_va: usize, oflag: u32, mode: u32) -> isize {
    let name = match read_cstr_safe(name_va) {
        Some(s) => s,
        None => return -14,
    };
    shm_open(&name, oflag, mode)
}

pub fn sys_shm_unlink(name_va: usize) -> isize {
    let name = match read_cstr_safe(name_va) {
        Some(s) => s,
        None => return -14,
    };
    shm_unlink(&name)
}
