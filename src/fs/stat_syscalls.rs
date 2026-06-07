//! stat / path syscalls.
//!
//! ## Fixes in this revision
//!   - sys_fstat, sys_fchmod, sys_fchown: translate user fd → backing fd via
//!     proc_fd_backing() before passing to is_pipe / vfs::fd_path /
//!     vfs::file_size.  Previously a user pipe fd like 4 was never recognised
//!     as a pipe (is_pipe checks the backing-fd range 0x8000_0000+) so fstat on
//!     a pipe returned S_IFREG instead of S_IFIFO.
//!   - sys_fstat: handle socket, eventfd, timerfd, signalfd with proper
//!     S_IFSOCK / S_IFCHR synthetic stats.
//!   - fill_stat: call vfs_ops::lstat (follow=false) when lstat=true so
//!     symlinks are reported as S_IFLNK instead of the target S_IFREG.
//!   - sys_chdir / sys_fchdir: now validate + commit to Pcb::cwd instead of
//!     silently returning 0.
//!   - sys_getcwd: copies the real per-process cwd instead of hardcoded "/".

extern crate alloc;
use crate::fs::vfs;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr, USER_SPACE_END};
use alloc::string::String;

// AT_* dirfd constants
const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: u32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

#[inline]
fn read_path(va: usize) -> Option<String> {
    if va == 0 || va >= USER_SPACE_END {
        return None;
    }
    let mut buf = [0u8; 4096];
    copy_from_user(&mut buf, va).ok()?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end])
        .ok()
        .map(|s| String::from(s))
}

/// Translate a user-visible fd to its kernel-internal backing fd.
#[inline]
fn user_fd_to_bfd(user_fd: usize) -> Option<usize> {
    let pid = crate::proc::scheduler::current_pid();
    let r = crate::fs::process_fd::proc_fd_backing(pid, user_fd);
    if r < 0 {
        None
    } else {
        Some(r as usize)
    }
}

/// Return the current process's cwd string.
fn current_cwd() -> String {
    let pid = crate::proc::scheduler::current_pid() as usize;
    crate::proc::scheduler::with_proc(pid, |p| p.cwd.clone()).unwrap_or_else(|| String::from("/"))
}

/// Resolve `path` to an absolute path, collapsing "." and "..".
///
/// - Absolute paths (starting with '/') are normalised in-place.
/// - Relative paths are prepended with the current process cwd first.
pub fn resolve_path(path: &str) -> String {
    let base = if path.starts_with('/') {
        String::from(path)
    } else {
        let cwd = current_cwd();
        if cwd.ends_with('/') {
            alloc::format!("{}{}", cwd, path)
        } else {
            alloc::format!("{}/{}", cwd, path)
        }
    };
    normalize_path(&base)
}

/// Lexically normalise an absolute path.
fn normalize_path(abs: &str) -> String {
    let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for seg in abs.split('/') {
        match seg {
            "" | "." => {},
            ".." => {
                parts.pop();
            },
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        String::from("/")
    } else {
        let mut out = String::new();
        for p in &parts {
            out.push('/');
            out.push_str(p);
        }
        out
    }
}

// Linux x86-64 `struct stat` layout.
#[repr(C)]
struct Stat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    _pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    _atimensec: i64,
    st_mtime: i64,
    _mtimensec: i64,
    st_ctime: i64,
    _ctimensec: i64,
    _reserved: [i64; 3],
}

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;

pub fn sys_stat(path_va: usize, stat_va: usize) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    if stat_va == 0 || stat_va >= USER_SPACE_END {
        return -14;
    }
    fill_stat(&path, stat_va, false)
}

pub fn sys_lstat(path_va: usize, stat_va: usize) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    if stat_va == 0 || stat_va >= USER_SPACE_END {
        return -14;
    }
    fill_stat(&path, stat_va, true)
}

/// sys_fstat(fd, stat_va)  [NR 5]
///
/// Translates the user-visible `fd` to its kernel backing fd before
/// dispatching to the appropriate subsystem.
pub fn sys_fstat(fd: usize, stat_va: usize) -> isize {
    if stat_va == 0 || stat_va >= USER_SPACE_END {
        return -14;
    }

    let bfd = match user_fd_to_bfd(fd) {
        Some(b) => b,
        None => return -9,
    };

    let write_stat = |s: Stat| -> isize {
        let buf = unsafe {
            core::slice::from_raw_parts(&s as *const _ as *const u8, core::mem::size_of::<Stat>())
        };
        if crate::uaccess::copy_to_user_value(stat_va, buf).is_err() {
            -14
        } else {
            0
        }
    };

    if crate::fs::pipe::is_pipe(bfd) {
        return write_stat(Stat {
            st_dev: 1,
            st_ino: bfd as u64 + 1,
            st_nlink: 1,
            st_mode: S_IFIFO | 0o666,
            st_uid: 0,
            st_gid: 0,
            _pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 4096,
            st_blocks: 0,
            st_atime: 0,
            _atimensec: 0,
            st_mtime: 0,
            _mtimensec: 0,
            st_ctime: 0,
            _ctimensec: 0,
            _reserved: [0; 3],
        });
    }

    if crate::net::socket::is_socket_fd(bfd) {
        return write_stat(Stat {
            st_dev: 1,
            st_ino: bfd as u64 + 1,
            st_nlink: 1,
            st_mode: S_IFSOCK | 0o777,
            st_uid: 0,
            st_gid: 0,
            _pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 4096,
            st_blocks: 0,
            st_atime: 0,
            _atimensec: 0,
            st_mtime: 0,
            _mtimensec: 0,
            st_ctime: 0,
            _ctimensec: 0,
            _reserved: [0; 3],
        });
    }

    if crate::fs::eventfd::is_eventfd(bfd)
        || crate::fs::timerfd::is_timerfd(bfd)
        || crate::fs::signalfd::is_signalfd(bfd)
    {
        return write_stat(Stat {
            st_dev: 1,
            st_ino: bfd as u64 + 1,
            st_nlink: 1,
            st_mode: S_IFCHR | 0o600,
            st_uid: 0,
            st_gid: 0,
            _pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 4096,
            st_blocks: 0,
            st_atime: 0,
            _atimensec: 0,
            st_mtime: 0,
            _mtimensec: 0,
            st_ctime: 0,
            _ctimensec: 0,
            _reserved: [0; 3],
        });
    }

    if let Some(path) = vfs::fd_path(bfd) {
        return fill_stat(&path, stat_va, false);
    }

    let sz = vfs::file_size(bfd).unwrap_or(0);
    write_stat(Stat {
        st_dev: 1,
        st_ino: bfd as u64 + 1,
        st_nlink: 1,
        st_mode: S_IFREG | 0o644,
        st_uid: 0,
        st_gid: 0,
        _pad0: 0,
        st_rdev: 0,
        st_size: sz as i64,
        st_blksize: 4096,
        st_blocks: sz.div_ceil(512) as i64,
        st_atime: 0,
        _atimensec: 0,
        st_mtime: 0,
        _mtimensec: 0,
        st_ctime: 0,
        _ctimensec: 0,
        _reserved: [0; 3],
    })
}

fn fill_stat(path: &str, stat_va: usize, lstat: bool) -> isize {
    let mut s = Stat {
        st_dev: 2,
        st_ino: 1,
        st_nlink: 1,
        st_mode: S_IFREG | 0o644,
        st_uid: 0,
        st_gid: 0,
        _pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 4096,
        st_blocks: 0,
        st_atime: 0,
        _atimensec: 0,
        st_mtime: 0,
        _mtimensec: 0,
        st_ctime: 0,
        _ctimensec: 0,
        _reserved: [0; 3],
    };

    if path.starts_with("/proc/") || path == "/proc" {
        s.st_mode = if lstat && is_proc_symlink(path) {
            S_IFLNK | 0o777
        } else if is_proc_dir(path) {
            S_IFDIR | 0o555
        } else {
            S_IFREG | 0o444
        };
        let buf = unsafe {
            core::slice::from_raw_parts(&s as *const _ as *const u8, core::mem::size_of::<Stat>())
        };
        if crate::uaccess::copy_to_user_value(stat_va, buf).is_err() {
            return -14;
        }
        return 0;
    }

    if path.starts_with("/dev/") {
        s.st_mode = S_IFCHR | 0o666;
        s.st_rdev = crate::fs::devfs::dev_rdev(path);
        let buf = unsafe {
            core::slice::from_raw_parts(&s as *const _ as *const u8, core::mem::size_of::<Stat>())
        };
        if crate::uaccess::copy_to_user_value(stat_va, buf).is_err() {
            return -14;
        }
        return 0;
    }

    let ks_result = if lstat {
        crate::fs::vfs_ops::lstat(path)
    } else {
        crate::fs::vfs_ops::stat(path)
    };

    match ks_result {
        Err(e) => e,
        Ok(ks) => {
            s.st_ino = ks.ino;
            s.st_mode = ks.mode as u32;
            s.st_nlink = ks.nlink as u64;
            s.st_uid = ks.uid;
            s.st_gid = ks.gid;
            s.st_size = ks.size as i64;
            s.st_blksize = ks.blksize as i64;
            s.st_blocks = ks.blocks as i64;
            s.st_atime = ks.atime as i64;
            s.st_mtime = ks.mtime as i64;
            s.st_ctime = ks.ctime as i64;
            let buf = unsafe {
                core::slice::from_raw_parts(
                    &s as *const _ as *const u8,
                    core::mem::size_of::<Stat>(),
                )
            };
            if crate::uaccess::copy_to_user_value(stat_va, buf).is_err() {
                return -14;
            }
            0
        },
    }
}

pub fn kstat_ext2(path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    match vfs::stat(path) {
        None => Err(-2),
        Some(vs) => Ok(crate::fs::vfs_ops::KStat {
            ino: vs.ino,
            mode: vs.mode,
            nlink: vs.nlink,
            uid: 0,
            gid: 0,
            size: vs.size,
            atime: 0,
            mtime: 0,
            ctime: 0,
            blksize: 4096,
            blocks: vs.size.div_ceil(512),
            is_dir: vs.is_dir,
        }),
    }
}

fn is_proc_symlink(path: &str) -> bool {
    path.ends_with("/exe")
        || path == "/proc/self"
        || (path.contains("/fd/") && !path.ends_with("/fd"))
}

fn is_proc_dir(path: &str) -> bool {
    path == "/proc" || path == "/proc/self" || path.ends_with("/fd") || {
        if let Some(rest) = path.strip_prefix("/proc/") {
            rest.parse::<usize>().is_ok()
        } else {
            false
        }
    }
}

pub fn sys_lseek(fd: usize, offset: i64, whence: i32) -> isize {
    vfs::lseek(fd, offset, whence)
}

/// sys_getcwd(buf_va, size) [NR 79]
///
/// Copies the current process cwd + NUL into user space.
/// Returns ERANGE (-34) if `size` is too small.
/// Returns the user buffer address on success (matches Linux).
pub fn sys_getcwd(buf_va: usize, size: usize) -> isize {
    if buf_va == 0 || size == 0 {
        return -22;
    }
    let pid = crate::proc::scheduler::current_pid() as usize;
    let cwd = crate::proc::scheduler::with_proc(pid, |p| p.cwd.clone())
        .unwrap_or_else(|| String::from("/"));
    let needed = cwd.len() + 1; // +1 for NUL
    if size < needed {
        return -34;
    } // ERANGE
    let mut kbuf = alloc::vec![0u8; needed];
    kbuf[..cwd.len()].copy_from_slice(cwd.as_bytes());
    if crate::uaccess::copy_to_user_value(buf_va, &kbuf).is_err() {
        return -14;
    }
    buf_va as isize
}

/// sys_chdir(path_va) [NR 80]
///
/// Validates the path exists and is a directory, then writes it to
/// Pcb::cwd via with_proc_mut.  Handles relative paths by prepending
/// the current cwd.
pub fn sys_chdir(path_va: usize) -> isize {
    let raw = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    let path = resolve_path(&raw);

    // Virtual filesystems: treat any prefix as always-present dirs.
    if is_virtual_dir(&path) {
        return commit_cwd(path);
    }

    match crate::fs::vfs_ops::stat(&path) {
        Err(e) => e,
        Ok(ks) => {
            if !ks.is_dir {
                return -20;
            } // ENOTDIR
            commit_cwd(path)
        },
    }
}

/// sys_fchdir(fd) [NR 81]
///
/// Resolves the fd to a VFS path, verifies it is a directory, then
/// updates Pcb::cwd.
pub fn sys_fchdir(fd: usize) -> isize {
    let bfd = match user_fd_to_bfd(fd) {
        Some(b) => b,
        None => return -9,
    };
    let path = match vfs::fd_path(bfd) {
        Some(p) => p,
        None => return -9,
    };

    if is_virtual_dir(&path) {
        return commit_cwd(path);
    }

    match crate::fs::vfs_ops::stat(&path) {
        Err(e) => e,
        Ok(ks) => {
            if !ks.is_dir {
                return -20;
            }
            commit_cwd(path)
        },
    }
}

/// Returns true for paths that are always valid directories even without
/// a VFS entry (procfs, devfs, sysfs roots and sub-paths).
#[inline]
fn is_virtual_dir(p: &str) -> bool {
    p == "/proc"
        || p == "/dev"
        || p == "/sys"
        || p.starts_with("/proc/")
        || p.starts_with("/dev/")
        || p.starts_with("/sys/")
}

/// Atomically write `new_cwd` into the current process's Pcb::cwd.
#[inline]
fn commit_cwd(new_cwd: String) -> isize {
    let pid = crate::proc::scheduler::current_pid() as usize;
    crate::proc::scheduler::with_proc_mut(pid, |p, _pl| {
        p.cwd = new_cwd;
    });
    0
}

pub fn sys_access(path_va: usize, _mode: u32) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    if path.starts_with("/proc/") || path.starts_with("/dev/") || path.starts_with("/sys/") {
        return 0;
    }
    if vfs::exists(&path) {
        0
    } else {
        -2
    }
}

pub fn sys_faccessat(_dirfd: i32, path_va: usize, mode: u32) -> isize {
    sys_access(path_va, mode)
}

pub fn sys_readlink(path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    if buf_va == 0 || bufsz == 0 {
        return -14;
    }
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    let mut kbuf = alloc::vec![0u8; bufsz.min(4096)];

    if path.starts_with("/proc/") || path == "/proc/self" {
        let n = crate::fs::procfs::procfs_readlink(&path, &mut kbuf);
        if n < 0 {
            return n;
        }
        if crate::uaccess::copy_to_user_value(buf_va, &kbuf[..n as usize]).is_err() {
            return -14;
        }
        return n;
    }

    match vfs::readlink(&path) {
        Some(target) => {
            let n = target.len().min(bufsz);
            if crate::uaccess::copy_to_user_value(buf_va, target[..n].as_bytes()).is_err() {
                return -14;
            }
            n as isize
        },
        None => -2,
    }
}

pub fn sys_readlinkat(_dirfd: i32, path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    sys_readlink(path_va, buf_va, bufsz)
}

pub fn sys_rename(old_va: usize, new_va: usize) -> isize {
    let old = match read_path(old_va) {
        Some(p) => p,
        None => return -14,
    };
    let new = match read_path(new_va) {
        Some(p) => p,
        None => return -14,
    };
    if vfs::rename(&old, &new) {
        0
    } else {
        -2
    }
}

pub fn sys_rename_str(old: &str, new: &str) -> isize {
    if vfs::rename(old, new) {
        0
    } else {
        -2
    }
}

pub fn sys_mkdir(path_va: usize, _mode: u32) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    if vfs::mkdir(&path) {
        0
    } else {
        -17
    }
}

pub fn sys_unlink(path_va: usize) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    if vfs::unlink(&path) {
        0
    } else {
        -2
    }
}

pub fn sys_truncate(path_va: usize, length: i64) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    if length < 0 {
        return -22;
    }
    match crate::fs::vfs_ops::truncate(&path, length as usize) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn sys_chmod(path_va: usize, mode: u32) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    match crate::fs::vfs_ops::chmod(&path, mode as u16) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn sys_fchmod(fd: usize, mode: u32) -> isize {
    let bfd = match user_fd_to_bfd(fd) {
        Some(b) => b,
        None => return -9,
    };
    let path = match vfs::fd_path(bfd) {
        Some(p) => p,
        None => return -9,
    };
    match crate::fs::vfs_ops::chmod(&path, mode as u16) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn sys_chown(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    match crate::fs::vfs_ops::chown(&path, uid, gid) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn sys_fchown(fd: usize, uid: u32, gid: u32) -> isize {
    let bfd = match user_fd_to_bfd(fd) {
        Some(b) => b,
        None => return -9,
    };
    let path = match vfs::fd_path(bfd) {
        Some(p) => p,
        None => return -9,
    };
    match crate::fs::vfs_ops::chown(&path, uid, gid) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn sys_newfstatat(dirfd: i32, path_va: usize, stat_va: usize, flags: u32) -> isize {
    if path_va == 0 {
        if flags & AT_EMPTY_PATH != 0 && dirfd != AT_FDCWD {
            return sys_fstat(dirfd as usize, stat_va);
        }
        return -14;
    }
    let raw = match read_path(path_va) {
        Some(p) => p,
        None => return -14,
    };
    let path = if raw.starts_with('/') || dirfd == AT_FDCWD {
        raw
    } else {
        let dir = vfs::fd_path(dirfd as usize).unwrap_or_else(|| String::from("/"));
        alloc::format!("{}/{}", dir.trim_end_matches('/'), raw)
    };
    let lstat = flags & AT_SYMLINK_NOFOLLOW != 0;
    fill_stat(&path, stat_va, lstat)
}
