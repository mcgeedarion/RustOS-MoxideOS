use crate::uaccess::{copy_to_user, validate_user_ptr};
use super::consts::{BLKGETSIZE, BLKGETSIZE64, BLKSSZGET, BLKBSZGET};

pub fn blk_ioctl(bfd: usize, cmd: u64, arg: usize) -> isize {
    let blk = match crate::fs::vfs_ops::bfd_to_block(bfd) {
        Some(b) => b, None => return -9,
    };
    match cmd {
        BLKGETSIZE   => { let secs = blk.sectors() as u32; copy_to_user(arg, &secs.to_ne_bytes()); 0 }
        BLKGETSIZE64 => { let b    = blk.sectors() * 512;  copy_to_user(arg, &b.to_ne_bytes());   0 }
        BLKSSZGET    => { let ss: u32 = 512; copy_to_user(arg, &ss.to_ne_bytes()); 0 }
        BLKBSZGET    => { let bs: u64 = 512; copy_to_user(arg, &bs.to_ne_bytes()); 0 }
        _ => -25,
    }
}
