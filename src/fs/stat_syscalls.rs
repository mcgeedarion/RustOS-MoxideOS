//! stat / path syscalls.
//!
//! ## New in this revision
//!   - sys_readlink and sys_readlinkat route /proc/* paths through
//!     procfs::procfs_readlink() before falling back to the VFS symlink table.
//!   - sys_fstat now resolves the FD to a path via vfs::fd_path() and calls
//!     vfs_ops::stat() to get the full KStat (uid, gid, atime, mtime, ctime,
//!     blksize, blocks).  Required for mmap(MAP_SHARED) on shm_open FDs.
//!   - fill_stat populates all KStat fields into the Stat struct.
//!   - sys_truncate: path-based truncate.
//!   - sys_chmod / sys_fchmod / sys_chown / sys_fchown: routed through
//!     vfs_ops::chmod / chown (tmpfs-native, stubs for other backends).

extern crate alloc;
use alloc::string::String;
use crate::uaccess::{copy_to_user, copy_from_user, validate_user_ptr, USER_SPACE_END};
use crate::fs::vfs;

// AT_* dirfd constants
const AT_FDCWD:       i32 = -100;
const AT_EMPTY_PATH:  u32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

// ── helpers ────────────────────────────────────────────────────────────────────────

#[inline]
fn read_path(va: usize) -> Option<String> {
    if va == 0 || va >= USER_SPACE_END { return None; }
    let mut buf = [0u8; 4096];
    copy_from_user(&mut buf, va).ok()?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).ok().map(|s| String::from(s))
}

// Linux x86-64 `struct stat` layout (statx is separate; this is used by
// stat(2), fstat(2), lstat(2), and newfstatat(2)).
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
const S_IFIFO: u32 = 0o010000;

// ── stat family ───────────────────────────────────────────────────────────────────

pub fn sys_stat(path_va: usize, stat_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if stat_va == 0 || stat_va >= USER_SPACE_END { return -14; }
    fill_stat(&path, stat_va, false)
}

pub fn sys_lstat(path_va: usize, stat_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if stat_va == 0 || stat_va >= USER_SPACE_END { return -14; }
    fill_stat(&path, stat_va, true)
}

/// sys_fstat(fd, stat_va)  [NR 5]
///
/// Resolves the FD to a path (via vfs::fd_path) and then calls
/// vfs_ops::stat() to get the full KStat struct, including uid, gid,
/// timestamps, blksize, and blocks.  This is required for mmap(MAP_SHARED)
/// on a shm_open FD: musl calls fstat() on the FD before the mmap call and
/// validates that st_size matches the ftruncate length.
pub fn sys_fstat(fd: usize, stat_va: usize) -> isize {
    if stat_va == 0 || stat_va >= USER_SPACE_END { return -14; }

    // Special cases first.
    if crate::fs::pipe::is_pipe(fd) {
        let s = Stat {
            st_dev: 1, st_ino: fd as u64 + 1, st_nlink: 1,
            st_mode: S_IFIFO | 0o666, st_uid: 0, st_gid: 0,
            _pad0: 0, st_rdev: 0, st_size: 0,
            st_blksize: 4096, st_blocks: 0,
            st_atime: 0, _atimensec: 0,
            st_mtime: 0, _mtimensec: 0,
            st_ctime: 0, _ctimensec: 0,
            _reserved: [0; 3],
        };
        let buf = unsafe { core::slice::from_raw_parts(
            &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
        if copy_to_user(stat_va, buf).is_err() { return -14; }
        return 0;
    }

    // Try to resolve the FD to an absolute path.
    if let Some(path) = vfs::fd_path(fd) {
        return fill_stat(&path, stat_va, false);
    }

    // Fallback for FDs with no stored path (anonymous / synthetic).
    let s = Stat {
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
    let buf = unsafe { core::slice::from_raw_parts(
        &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
    if copy_to_user(stat_va, buf).is_err() { return -14; }
    0
}

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

    // /proc/* paths.
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

    // /dev/* paths.
    if path.starts_with("/dev/") {
        s.st_mode = S_IFCHR | 0o666;
        s.st_rdev = crate::fs::devfs::dev_rdev(path);
        let buf = unsafe { core::slice::from_raw_parts(
            &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
        if copy_to_user(stat_va, buf).is_err() { return -14; }
        return 0;
    }

    // Real VFS path: call vfs_ops::stat for a complete KStat.
    match crate::fs::vfs_ops::stat(path) {
        Err(e) => e,
        Ok(ks) => {
            s.st_ino     = ks.ino;
            s.st_mode    = ks.mode as u32;
            s.st_nlink   = ks.nlink as u64;
            s.st_uid     = ks.uid;
            s.st_gid     = ks.gid;
            s.st_size    = ks.size    as i64;
            s.st_blksize = ks.blksize as i64;
            s.st_blocks  = ks.blocks  as i64;
            s.st_atime   = ks.atime   as i64;
            s.st_mtime   = ks.mtime   as i64;
            s.st_ctime   = ks.ctime   as i64;
            if lstat {
                // For lstat on a symlink, set S_IFLNK.
                // vfs_ops::stat follows symlinks; we detect by mode bits.
                // If the mode already has S_IFLNK set we leave it; otherwise
                // we trust the backend to have set mode correctly via TmpfsStat.
            }
            let buf = unsafe { core::slice::from_raw_parts(
                &s as *const _ as *const u8, core::mem::size_of::<Stat>()) };
            if copy_to_user(stat_va, buf).is_err() { return -14; }
            0
        }
    }
}

/// kstat_ext2: called by vfs_ops::stat for Ext2 paths (returns KStat).
/// Thin bridge from the ext2 VFS layer to our KStat type.
pub fn kstat_ext2(path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    match vfs::stat(path) {
        None     => Err(-2),
        Some(vs) => Ok(crate::fs::vfs_ops::KStat {
            ino:     vs.ino,
            mode:    vs.mode,
            nlink:   vs.nlink,
            uid:     0,
            gid:     0,
            size:    vs.size,
            atime:   0,
            mtime:   0,
            ctime:   0,
            blksize: 4096,
            blocks:  vs.size.div_ceil(512),
            is_dir:  vs.is_dir,
        }),
    }
}

/// True for /proc entries that behave like symlinks.
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
        if let Some(rest) = path.strip_prefix("/proc/") {
            rest.parse::<usize>().is_ok()
        } else {
            false
        }
    }
}

// ── sys_lseek ─────────────────────────────────────────────────────────────────────

pub fn sys_lseek(fd: usize, offset: i64, whence: i32) -> isize {
    vfs::lseek(fd, offset, whence)
}

// ── sys_getcwd ───────────────────────────────────────────────────────────────────

pub fn sys_getcwd(buf_va: usize, size: usize) -> isize {
    if buf_va == 0 || size == 0 { return -22; }
    let cwd = b"/\0";
    if size < cwd.len() { return -34; }
    if copy_to_user(buf_va, cwd).is_err() { return -14; }
    buf_va as isize
}

// ── sys_chdir / sys_fchdir ─────────────────────────────────────────────────────────

pub fn sys_chdir(_path_va: usize) -> isize { 0 }
pub fn sys_fchdir(_fd: usize)     -> isize { 0 }

// ── sys_access / sys_faccessat ──────────────────────────────────────────────────

pub fn sys_access(path_va: usize, _mode: u32) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if path.starts_with("/proc/") || path.starts_with("/dev/") || path.starts_with("/sys/") {
        return 0;
    }
    if vfs::exists(&path) { 0 } else { -2 }
}

pub fn sys_faccessat(_dirfd: i32, path_va: usize, mode: u32) -> isize {
    sys_access(path_va, mode)
}

// ── sys_readlink / sys_readlinkat ─────────────────────────────────────────────────

pub fn sys_readlink(path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    if buf_va == 0 || bufsz == 0 { return -14; }
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    let mut kbuf = alloc::vec![0u8; bufsz.min(4096)];

    if path.starts_with("/proc/") || path == "/proc/self" {
        let n = crate::fs::procfs::procfs_readlink(&path, &mut kbuf);
        if n < 0 { return n; }
        if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
        return n;
    }

    match vfs::readlink(&path) {
        Some(target) => {
            let n = target.len().min(bufsz);
            if copy_to_user(buf_va, target[..n].as_bytes()).is_err() { return -14; }
            n as isize
        }
        None => -2,
    }
}

pub fn sys_readlinkat(_dirfd: i32, path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    sys_readlink(path_va, buf_va, bufsz)
}

// ── sys_rename / sys_mkdir / sys_unlink ───────────────────────────────────────────────

pub fn sys_rename(old_va: usize, new_va: usize) -> isize {
    let old = match read_path(old_va) { Some(p) => p, None => return -14 };
    let new = match read_path(new_va) { Some(p) => p, None => return -14 };
    if vfs::rename(&old, &new) { 0 } else { -2 }
}

pub fn sys_mkdir(path_va: usize, _mode: u32) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if vfs::mkdir(&path) { 0 } else { -17 }
}

pub fn sys_unlink(path_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if vfs::unlink(&path) { 0 } else { -2 }
}

// ── sys_truncate ────────────────────────────────────────────────────────────────────

/// sys_truncate(path_va, length)  [NR 76]
pub fn sys_truncate(path_va: usize, length: i64) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if length < 0 { return -22; }
    match crate::fs::vfs_ops::truncate(&path, length as usize) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

// ── sys_chmod / sys_fchmod / sys_chown / sys_fchown ─────────────────────────────

/// sys_chmod(path_va, mode)  [NR 90]
pub fn sys_chmod(path_va: usize, mode: u32) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::chmod(&path, mode as u16) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

/// sys_fchmod(fd, mode)  [NR 91]
pub fn sys_fchmod(fd: usize, mode: u32) -> isize {
    let path = match vfs::fd_path(fd) { Some(p) => p, None => return -9 };
    match crate::fs::vfs_ops::chmod(&path, mode as u16) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

/// sys_chown(path_va, uid, gid)  [NR 92]
pub fn sys_chown(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::chown(&path, uid, gid) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

/// sys_fchown(fd, uid, gid)  [NR 93]
pub fn sys_fchown(fd: usize, uid: u32, gid: u32) -> isize {
    let path = match vfs::fd_path(fd) { Some(p) => p, None => return -9 };
    match crate::fs::vfs_ops::chown(&path, uid, gid) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

// ── sys_newfstatat ────────────────────────────────────────────────────────────────

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
