//! Block device ioctl handlers (BLK*).
use super::consts::*;
use crate::uaccess::{copy_to_user, copy_to_user_value};

pub fn blk_ioctl(fd: usize, req: usize, arg: usize) -> isize {
    let sector_count: u64 = crate::drivers::virtio_blk::sector_count();
    match req {
        BLKGETSIZE => {
            let sectors: u32 = sector_count.min(u32::MAX as u64) as u32;
            crate::uaccess::copy_to_user_value(arg, &sectors.to_ne_bytes());
            0
        },
        BLKGETSIZE64 => {
            let bytes: u64 = sector_count * 512;
            crate::uaccess::copy_to_user_value(arg, &bytes.to_ne_bytes());
            0
        },
        BLKBSZGET => {
            let bsz: u32 = 512;
            crate::uaccess::copy_to_user_value(arg, &bsz.to_ne_bytes());
            0
        },
        BLKFLSBUF => 0,
        BLKROGET => {
            crate::uaccess::copy_to_user_value(arg, &0u32.to_ne_bytes());
            0
        },
        BLKROSET => 0,
        _ => -25,
    }
}
