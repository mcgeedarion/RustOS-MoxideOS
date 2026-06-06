//! Generic file-descriptor ioctl helpers.
use super::consts::{FIONBIO, FIONREAD};
use crate::uaccess::copy_to_user;

pub fn vfs_fionread(fd: usize, arg: usize) -> isize {
    let n: u32 = crate::fs::vfs::vfs_fionread(fd).unwrap_or(0) as u32;
    copy_to_user(arg, &n.to_ne_bytes());
    0
}

pub fn pipe_fionread(fd: usize, arg: usize) -> isize {
    let n: u32 = crate::ipc::pipe::pipe_bytes_available(fd) as u32;
    copy_to_user(arg, &n.to_ne_bytes());
    0
}

pub fn set_nonblock(fd: usize, arg: usize) -> isize {
    let mut buf = [0u8; 4];
    crate::uaccess::copy_from_user(arg, &mut buf);
    let v = u32::from_ne_bytes(buf);
    crate::fs::vfs::vfs_set_nonblock(fd, v != 0);
    0
}
