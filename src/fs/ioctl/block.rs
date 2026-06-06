//! Block device ioctl handlers (BLK*).
use super::consts::*;
use crate::uaccess::copy_to_user;

pub fn blk_ioctl(fd: usize, req: usize, arg: usize) -> isize {
    let sector_count: u64 = crate::drivers::virtio_blk::sector_count();
    match req {
        BLKGETSIZE => {
            let sectors: u32 = sector_count.min(u32::MAX as u64) as u32;
            copy_to_user(arg, &sectors.to_ne_bytes());
            0
        },
        BLKGETSIZE64 => {
            let bytes: u64 = sector_count * 512;
            copy_to_user(arg, &bytes.to_ne_bytes());
            0
        },
        BLKBSZGET => {
            let bsz: u32 = 512;
            copy_to_user(arg, &bsz.to_ne_bytes());
            0
        },
        BLKFLSBUF => 0,
        BLKROGET => {
            copy_to_user(arg, &0u32.to_ne_bytes());
            0
        },
        BLKROSET => 0,
        _ => -25,
    }
}
