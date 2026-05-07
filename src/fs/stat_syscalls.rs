//! stat / path syscalls.
//!
//! ## New in this revision
//!   sys_readlink and sys_readlinkat now route /proc/* paths through
//!   procfs::procfs_readlink() before falling back to the VFS symlink table.
//!   This makes `readlink /proc/self/exe` return the correct executable path
//!   for any binary that calls it during startup (ld.so, musl, glibc).

extern crate alloc;
use alloc::string::String;
use crate::uaccess::{copy_to_user, copy_from_user, validate_user_ptr, USER_SPACE_END};
use crate::fs::vfs;

// AT_* dirfd constants
const AT_FDCWD:       i32 = -100;
const AT_EMPTY_PATH:  u32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

// ── helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn read_path(va: usize) -> Option<String> {
    if va == 0 || va >= USER_SPACE_END { return None; }
    let mut buf = [0u8; 4096];
    copy_from_user(&mut buf, va).ok()?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).ok().map(|s| String::from(s))
}

#[repr(C)]
struct Stat {
    st_dev:     u64,
    st_ino:     u64,
    st_nlink:   u64,
    st_mode:    u32,
    st_uid:     u32,
    st_gid:     u32,
    _pad0:      u32,
    st_rdev:    u64,
    st_size:    i64,
    st_blksize: i64,
    st_blocks:  i64,
    st_atime:   i64, _atimensec: i64,
    st_mtime:   i64, _mtimensec: i64,
    st_ctime:   i64, _ctimensec: i64,
    _reserved:  [i64; 3],
}

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;

// ── stat family ──────────────────────────────────────────────────────────────

pub fn sys_stat(path_va: usize, stat_va: usize) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None    => return -14,
    };
    if stat_va == 0 || stat_va >= USER_SPACE_END { return -14; }
    fill_stat(&path, stat_va, false)
}

pub fn sys_lstat(path_va: usize, stat_va: usize) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None    => return -14,
    };
    if stat_va == 0 || stat_va >= USER_SPACE_END { return -14; }
    fill_stat(&path, stat_va, true)
}

pub fn sys_fstat(fd: usize, stat_va: usize) -> isize {
    if stat_va == 0 || stat_va >= USER_SPACE_END { return -14; }
    let mut s = Stat {
        st_dev: 1, st_ino: fd as u64 + 1, st_nlink: 1,
        st_mode: S_IFREG | 0o644, st_uid: 0, st_gid: 0,
        _pad0: 0, st_rdev: 0,
        st_size: vfs::file_size(fd) as i64,
        st_blksize: 4096, st_blocks: 8,
        st_atime: 0, _atimensec: 0,
        st_mtime: 0, _mtimensec: 0,
        st_ctime: 0, _ctimensec: 0,
        _reserved: [0; 3],
    };
    if crate::fs::pipe::is_pipe(fd) {
        s.st_mode = S_IFIFO | 0o666;
        s.st_size = 0;
    }
    let buf = unsafe { core::slice::from_raw_parts(
        &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
    if copy_to_user(stat_va, buf).is_err() { return -14; }
    0
}

const S_IFIFO: u32 = 0o010000;

fn fill_stat(path: &str, stat_va: usize, lstat: bool) -> isize {
    let mut s = Stat {
        st_dev: 2, st_ino: 1, st_nlink: 1,
        st_mode: S_IFREG | 0o644, st_uid: 0, st_gid: 0,
        _pad0: 0, st_rdev: 0, st_size: 0,
        st_blksize: 4096, st_blocks: 0,
        st_atime: 0, _atimensec: 0,
        st_mtime: 0, _mtimensec: 0,
        st_ctime: 0, _ctimensec: 0,
        _reserved: [0; 3],
    };

    // /proc/* paths — always treat as regular file (or symlink for readlink).
    if path.starts_with("/proc/") || path == "/proc" {
        s.st_mode = if lstat && is_proc_symlink(path) {
            S_IFLNK | 0o777
        } else if is_proc_dir(path) {
            S_IFDIR | 0o555
        } else {
            S_IFREG | 0o444
        };
        let buf = unsafe { core::slice::from_raw_parts(
            &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
        if copy_to_user(stat_va, buf).is_err() { return -14; }
        return 0;
    }

    if path.starts_with("/dev/") {
        s.st_mode = S_IFCHR | 0o666;
        s.st_rdev = crate::fs::devfs::dev_rdev(path);
        let buf = unsafe { core::slice::from_raw_parts(
            &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
        if copy_to_user(stat_va, buf).is_err() { return -14; }
        return 0;
    }

    // Real VFS path.
    match vfs::stat(path) {
        None     => -2, // ENOENT
        Some(vs) => {
            s.st_ino     = vs.ino;
            s.st_mode    = vs.mode;
            s.st_size    = vs.size as i64;
            s.st_blocks  = ((vs.size + 511) / 512) as i64;
            s.st_nlink   = vs.nlink as u64;
            let buf = unsafe { core::slice::from_raw_parts(
                &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
            if copy_to_user(stat_va, buf).is_err() { return -14; }
            0
        }
    }
}

/// True for /proc entries that behave like symlinks (readlink returns a target).
fn is_proc_symlink(path: &str) -> bool {
    path.ends_with("/exe")
    || path == "/proc/self"
    || (path.contains("/fd/") && !path.ends_with("/fd"))
}

/// True for /proc entries that are directories.
fn is_proc_dir(path: &str) -> bool {
    path == "/proc"
    || path == "/proc/self"
    || path.ends_with("/fd")
    || {
        // /proc/<pid> with no trailing slash
        if let Some(rest) = path.strip_prefix("/proc/") {
            rest.parse::<usize>().is_ok()
        } else {
            false
        }
    }
}

// ── sys_lseek ────────────────────────────────────────────────────────────────

pub fn sys_lseek(fd: usize, offset: i64, whence: i32) -> isize {
    vfs::lseek(fd, offset, whence)
}

// ── sys_getcwd ────────────────────────────────────────────────────────────────

pub fn sys_getcwd(buf_va: usize, size: usize) -> isize {
    if buf_va == 0 || size == 0 { return -22; }
    let cwd = b"/\0";
    if size < cwd.len() { return -34; }
    if copy_to_user(buf_va, cwd).is_err() { return -14; }
    buf_va as isize
}

// ── sys_chdir / sys_fchdir ────────────────────────────────────────────────────

pub fn sys_chdir(_path_va: usize) -> isize { 0 }
pub fn sys_fchdir(_fd: usize)     -> isize { 0 }

// ── sys_access / sys_faccessat ────────────────────────────────────────────────

pub fn sys_access(path_va: usize, mode: u32) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None    => return -14,
    };
    if path.starts_with("/proc/") || path.starts_with("/dev/") || path.starts_with("/sys/") {
        return 0;
    }
    if vfs::exists(&path) { 0 } else { -2 }
}

pub fn sys_faccessat(dirfd: i32, path_va: usize, mode: u32) -> isize {
    sys_access(path_va, mode)
}

// ── sys_readlink / sys_readlinkat ─────────────────────────────────────────────
//
// Routes /proc/* paths through procfs_readlink first, then falls back to
// the VFS symlink table (vfs::readlink).  This ensures `readlink
// /proc/self/exe` works correctly without a real filesystem.

pub fn sys_readlink(path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    if buf_va == 0 || bufsz == 0 { return -14; }
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };

    let mut kbuf = alloc::vec![0u8; bufsz.min(4096)];

    // /proc/* — always handled by procfs regardless of VFS state.
    if path.starts_with("/proc/") || path == "/proc/self" {
        let n = crate::fs::procfs::procfs_readlink(&path, &mut kbuf);
        if n < 0 { return n; }
        if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
        return n;
    }

    // VFS symlink fallback.
    match vfs::readlink(&path) {
        Some(target) => {
            let n = target.len().min(bufsz);
            if copy_to_user(buf_va, target[..n].as_bytes()).is_err() { return -14; }
            n as isize
        }
        None => -2, // ENOENT
    }
}

pub fn sys_readlinkat(dirfd: i32, path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    // We only support absolute paths and AT_FDCWD-relative paths (treated as absolute).
    sys_readlink(path_va, buf_va, bufsz)
}

// ── sys_rename / sys_mkdir / sys_unlink ───────────────────────────────────────

pub fn sys_rename(old_va: usize, new_va: usize) -> isize {
    let old = match read_path(old_va) { Some(p) => p, None => return -14 };
    let new = match read_path(new_va) { Some(p) => p, None => return -14 };
    if vfs::rename(&old, &new) { 0 } else { -2 }
}

pub fn sys_mkdir(path_va: usize, mode: u32) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if vfs::mkdir(&path) { 0 } else { -17 } // EEXIST
}

pub fn sys_unlink(path_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if vfs::unlink(&path) { 0 } else { -2 }
}

// ── sys_newfstatat ────────────────────────────────────────────────────────────

pub fn sys_newfstatat(dirfd: i32, path_va: usize, stat_va: usize, flags: u32) -> isize {
    if path_va == 0 {
        if flags & AT_EMPTY_PATH != 0 && dirfd != AT_FDCWD {
            return sys_fstat(dirfd as usize, stat_va);
        }
        return -14;
    }
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        sys_lstat(path_va, stat_va)
    } else {
        sys_stat(path_va, stat_va)
    }
}
