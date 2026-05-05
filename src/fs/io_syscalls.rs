//! Core file I/O syscalls: read, write, open, close, pread64, writev, dup2.

extern crate alloc;
use alloc::vec::Vec;
use crate::fs::vfs;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

/// sys_read(fd, buf_va, count)  [NR 0]
pub fn sys_read(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    let n: isize;
    if fd == 0 {
        n = crate::shell::tty::read_line(&mut kbuf);
    } else if crate::fs::devfs::get_dev_fd(fd).is_some() {
        n = crate::fs::devfs::read(fd, &mut kbuf);
    } else {
        n = vfs::read(fd, &mut kbuf);
    }
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

/// sys_write(fd, buf_va, count)  [NR 1]
pub fn sys_write(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }
    if fd == 1 || fd == 2 {
        return crate::shell::tty::write(&kbuf);
    }
    if crate::fs::devfs::get_dev_fd(fd).is_some() {
        return crate::fs::devfs::write(fd, &kbuf);
    }
    vfs::write(fd, &kbuf)
}

/// sys_open(path_va, flags, mode)  [NR 2]
pub fn sys_open(path_va: usize, flags: u32, _mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
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
    if crate::fs::devfs::get_dev_fd(fd).is_some() {
        crate::fs::devfs::close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    crate::fs::fcntl::close_fd_meta(fd);
    vfs::close(fd)
}

/// sys_pread64(fd, buf_va, count, offset)  [NR 17]
pub fn sys_pread64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let saved = vfs::seek(fd, 0, vfs::SEEK_CUR) as i64;
    vfs::seek(fd, offset, vfs::SEEK_SET);
    let mut kbuf = alloc::vec![0u8; count];
    let n = vfs::read(fd, &mut kbuf);
    vfs::seek(fd, saved, vfs::SEEK_SET);
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

/// sys_writev(fd, iov_va, iovcnt)  [NR 20]
pub fn sys_writev(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; }
    if !validate_user_ptr(iov_va, iovcnt * 16) { return -14; }
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let mut iov_buf = [0u8; 16];
        if copy_from_user(&mut iov_buf, iov_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(iov_buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(iov_buf[8..16].try_into().unwrap());
        if len == 0 { continue; }
        let n = sys_write(fd, base, len);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
    }
    total
}

/// sys_dup2(oldfd, newfd)  [NR 33]
/// Delegates to fcntl::sys_dup2 so that the cloexec flag is propagated
/// correctly — the old direct vfs::dup_as call bypassed that entirely.
pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    crate::fs::fcntl::sys_dup2(oldfd, newfd)
}
