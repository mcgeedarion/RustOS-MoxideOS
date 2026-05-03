//! Core file I/O syscalls: read, write, open, close, pread64, writev, dup2.

extern crate alloc;
use alloc::vec::Vec;
use crate::fs::vfs;
use crate::proc::exec::read_cstr_safe;

/// sys_read(fd, buf_va, count)  [NR 0]
pub fn sys_read(fd: usize, buf_va: usize, count: usize) -> isize {
    if buf_va < 0x1000 || count == 0 { return -14; }
    // stdin (fd 0) → TTY line discipline
    if fd == 0 {
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_va as *mut u8, count) };
        return crate::shell::tty::read_line(buf);
    }
    // devfs device?
    if let Some(_kind) = crate::fs::devfs::get_dev_fd(fd) {
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_va as *mut u8, count) };
        return crate::fs::devfs::read(fd, buf);
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_va as *mut u8, count) };
    vfs::read(fd, buf)
}

/// sys_write(fd, buf_va, count)  [NR 1]
pub fn sys_write(fd: usize, buf_va: usize, count: usize) -> isize {
    if buf_va < 0x1000 || count == 0 { return -14; }
    // stdout/stderr (fd 1/2) → TTY
    if fd == 1 || fd == 2 {
        let buf = unsafe { core::slice::from_raw_parts(buf_va as *const u8, count) };
        return crate::shell::tty::write(buf);
    }
    // devfs?
    if let Some(_kind) = crate::fs::devfs::get_dev_fd(fd) {
        let buf = unsafe { core::slice::from_raw_parts(buf_va as *const u8, count) };
        return crate::fs::devfs::write(fd, buf);
    }
    let buf = unsafe { core::slice::from_raw_parts(buf_va as *const u8, count) };
    vfs::write(fd, buf)
}

/// sys_open(path_va, flags, mode)  [NR 2]
pub fn sys_open(path_va: usize, flags: u32, mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    // Try devfs first.
    if path.starts_with("/dev/") {
        if let Some(fd) = crate::fs::devfs::try_open(&path, flags) {
            return fd as isize;
        }
    }
    match vfs::open(&path, flags) {
        Ok(fd)  => fd as isize,
        Err(e)  => e as isize,
    }
}

/// sys_close(fd)  [NR 3]
pub fn sys_close(fd: usize) -> isize {
    // Close devfs fds.
    if crate::fs::devfs::get_dev_fd(fd).is_some() {
        crate::fs::devfs::close(fd);
        return 0;
    }
    vfs::close(fd)
}

/// sys_pread64(fd, buf_va, count, offset)  [NR 17]
pub fn sys_pread64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if buf_va < 0x1000 || count == 0 { return -14; }
    vfs::pread(fd, buf_va as *mut u8, count, offset)
}

/// iovec struct for writev.
#[repr(C)]
struct Iovec { iov_base: usize, iov_len: usize }

/// sys_writev(fd, iov_va, iovcnt)  [NR 20]
pub fn sys_writev(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iov_va < 0x1000 || iovcnt == 0 { return -14; }
    if iovcnt > 1024 { return -22; } // EINVAL
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let iov = unsafe { &*((iov_va + i * core::mem::size_of::<Iovec>()) as *const Iovec) };
        if iov.iov_len == 0 { continue; }
        if iov.iov_base < 0x1000 { return -14; }
        let n = sys_write(fd, iov.iov_base, iov.iov_len);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
    }
    total
}

/// sys_dup2(oldfd, newfd)  [NR 33]
pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    if oldfd == newfd { return newfd as isize; }
    vfs::dup_as(oldfd, newfd)
}
