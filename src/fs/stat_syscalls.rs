//! stat / path operation syscalls.

extern crate alloc;
use alloc::string::String;
use crate::fs::vfs;
use crate::proc::exec::read_cstr_safe;

// ── stat buffer layout (x86-64 Linux struct stat) ────────────────────────
// 144 bytes total; we fill the minimum fields musl needs.
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
    st_atime:   u64,
    st_atime_ns:u64,
    st_mtime:   u64,
    st_mtime_ns:u64,
    st_ctime:   u64,
    st_ctime_ns:u64,
    _unused:    [i64; 3],
}

fn fill_stat(buf_va: usize, size: u64, is_dir: bool, ino: u64) -> isize {
    if buf_va < 0x1000 { return -14; } // EFAULT
    let mode: u32 = if is_dir { 0o040755 } else { 0o100644 };
    let s = Stat {
        st_dev: 1, st_ino: ino, st_nlink: 1,
        st_mode: mode, st_uid: 0, st_gid: 0, _pad0: 0,
        st_rdev: 0, st_size: size as i64,
        st_blksize: 4096, st_blocks: ((size + 511) / 512) as i64,
        st_atime: 0, st_atime_ns: 0,
        st_mtime: 0, st_mtime_ns: 0,
        st_ctime: 0, st_ctime_ns: 0,
        _unused: [0; 3],
    };
    unsafe { core::ptr::write_volatile(buf_va as *mut Stat, s); }
    0
}

/// sys_fstat(fd, statbuf_va)  [NR 5]
pub fn sys_fstat(fd: usize, statbuf_va: usize) -> isize {
    let size = vfs::fstat(fd).unwrap_or(0) as u64;
    fill_stat(statbuf_va, size, false, fd as u64 + 1)
}

/// sys_stat(path_va, statbuf_va)  [NR 4]
pub fn sys_stat(path_va: usize, statbuf_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    vfs::stat(&path, statbuf_va)
}

/// sys_lstat(path_va, statbuf_va)  [NR 6]
/// Same as stat — we don't follow symlinks (no symlinks implemented yet).
pub fn sys_lstat(path_va: usize, statbuf_va: usize) -> isize {
    sys_stat(path_va, statbuf_va)
}

/// sys_lseek(fd, offset, whence)  [NR 8]
pub fn sys_lseek(fd: usize, offset: i64, whence: i32) -> isize {
    vfs::seek(fd, offset, whence)
}

/// sys_access(path_va, mode)  [NR 21]
pub fn sys_access(path_va: usize, mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    vfs::access(&path, mode)
}

/// sys_faccessat(dirfd, path_va, mode)  [NR 269]
/// We ignore dirfd (treat all paths as absolute or cwd-relative).
pub fn sys_faccessat(dirfd: i32, path_va: usize, mode: u32) -> isize {
    sys_access(path_va, mode)
}

/// sys_getcwd(buf_va, size)  [NR 79]
pub fn sys_getcwd(buf_va: usize, size: usize) -> isize {
    if buf_va < 0x1000 || size == 0 { return -14; }
    let cwd = crate::proc::cwd::get_cwd();
    let bytes = cwd.as_bytes();
    if bytes.len() + 1 > size { return -34; } // ERANGE
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_va as *mut u8, bytes.len());
        *((buf_va + bytes.len()) as *mut u8) = 0;
    }
    buf_va as isize
}

/// sys_chdir(path_va)  [NR 80]
pub fn sys_chdir(path_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    if !vfs::is_dir(&path) { return -20; } // ENOTDIR
    crate::proc::cwd::set_cwd(&path);
    0
}

/// sys_rename(old_va, new_va)  [NR 82]
pub fn sys_rename(old_va: usize, new_va: usize) -> isize {
    let old = match read_cstr_safe(old_va) { Some(s) => s, None => return -14 };
    let new = match read_cstr_safe(new_va) { Some(s) => s, None => return -14 };
    // Delegate to VFS (ramfs supports rename).
    match vfs::open(&old, vfs::O_RDONLY) {
        Ok(fd) => {
            let sz = vfs::fstat(fd).unwrap_or(0);
            let mut buf = alloc::vec![0u8; sz];
            vfs::pread(fd, buf.as_mut_ptr(), sz, 0);
            vfs::close(fd);
            vfs::create_file(&new, &buf);
            // Best-effort delete old (VFS unlink).
            let _ = vfs::unlink(&old);
            0
        }
        Err(_) => -2, // ENOENT
    }
}

/// sys_mkdir(path_va, mode)  [NR 83]
pub fn sys_mkdir(path_va: usize, mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    vfs::mkdir(&path, mode)
}

/// sys_unlink(path_va)  [NR 87]
pub fn sys_unlink(path_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    vfs::unlink(&path)
}
