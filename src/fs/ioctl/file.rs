use crate::uaccess::{copy_to_user, validate_user_ptr};

pub fn fionread_tty(arg: usize) -> isize {
    let n: i32 = 0;
    copy_to_user(arg, &n.to_ne_bytes());
    0
}

pub fn pipe_fionread(bfd: usize, arg: usize) -> isize {
    let n: i32 = crate::ipc::pipe::readable_bytes(bfd) as i32;
    copy_to_user(arg, &n.to_ne_bytes());
    0
}

pub fn vfs_fionread(bfd: usize, arg: usize) -> isize {
    let n: i32 = match crate::fs::vfs_ops::vfs_readable_bytes(bfd) {
        Some(b) => b as i32, None => 0,
    };
    copy_to_user(arg, &n.to_ne_bytes());
    0
}
