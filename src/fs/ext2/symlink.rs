extern crate alloc;

use alloc::{string::String, vec::Vec};

const EXT2_S_IFMT: u16 = 0xF000;
const EXT2_S_IFLNK: u16 = 0xA000;
pub const EXT2_SYMLINK_DIR_ENTRY_TYPE: u8 = 7;
pub const EXT2_FAST_SYMLINK_MAX_LEN: usize = 60;

pub fn is_symlink_mode(mode: u16) -> bool {
    (mode & EXT2_S_IFMT) == EXT2_S_IFLNK
}

pub fn is_fast_symlink(size: u32, blocks_512: u32) -> bool {
    let len = size as usize;
    len > 0 && len <= EXT2_FAST_SYMLINK_MAX_LEN