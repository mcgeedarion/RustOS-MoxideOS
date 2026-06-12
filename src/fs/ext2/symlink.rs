extern crate alloc;

use alloc::{string::String, vec::Vec};

const EXT2_S_IFMT: u16 = 0xF000;
const EXT2_S_IFLNK: u16 = 0xA000;

/// ext2 directory-entry file type for symbolic links.
pub const EXT2_SYMLINK_DIR_ENTRY_TYPE: u8 = 7;

/// ext2 stores short symlink targets directly inside `i_block`.
pub const EXT2_FAST_SYMLINK_MAX_LEN: usize = 60;

#[inline]
pub fn is_symlink_mode(mode: u16) -> bool {
    (mode & EXT2_S_IFMT) == EXT2_S_IFLNK
}

#[inline]
pub fn is_fast_symlink(size: u64, blocks_512: u32) -> bool {
    let len = size as usize;

    if len == 0 {
        return false;
    }

    if len > EXT2_FAST_SYMLINK_MAX_LEN {
        return false;
    }

    // ext2 fast symlinks store the target bytes in i_block and allocate no
    // data blocks. Some images may leave i_blocks as 0 for these.
    blocks_512 == 0
}

/// Copy bytes from an ext2 `i_block[15]` array into a raw 60-byte buffer.
pub fn fast_symlink_bytes(i_block: &[u32; 15]) -> [u8; EXT2_FAST_SYMLINK_MAX_LEN] {
    let mut out = [0u8; EXT2_FAST_SYMLINK_MAX_LEN];

    for i in 0..15 {
        let bytes = i_block[i].to_le_bytes();
        let off = i * 4;
        out[off..off + 4].copy_from_slice(&bytes);
    }

    out
}

/// Decode a fast symlink target from the inode's `i_block` words.
pub fn read_fast_symlink_target(i_block: &[u32; 15], size: u64) -> String {
    let raw = fast_symlink_bytes(i_block);
    let len = core::cmp::min(size as usize, EXT2_FAST_SYMLINK_MAX_LEN);

    String::from_utf8_lossy(&raw[..len]).into_owned()
}

/// Encode a short target into ext2's fast-symlink `i_block` layout.
pub fn encode_fast_symlink_target(target: &[u8]) -> Option<[u32; 15]> {
    if target.len() > EXT2_FAST_SYMLINK_MAX_LEN {
        return None;
    }

    let mut raw = [0u8; EXT2_FAST_SYMLINK_MAX_LEN];
    raw[..target.len()].copy_from_slice(target);

    let mut out = [0u32; 15];

    for i in 0..15 {
        let off = i * 4;
        out[i] = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
    }

    Some(out)
}

/// Decode a regular block-backed symlink target.
pub fn read_block_symlink_target(data: &[u8], size: u64) -> String {
    let len = core::cmp::min(size as usize, data.len());
    String::from_utf8_lossy(&data[..len]).into_owned()
}

/// Choose the correct symlink target decoder.
pub fn read_symlink_target(
    i_block: &[u32; 15],
    size: u64,
    blocks_512: u32,
    block_data: &[u8],
) -> String {
    if is_fast_symlink(size, blocks_512) {
        read_fast_symlink_target(i_block, size)
    } else {
        read_block_symlink_target(block_data, size)
    }
}

/// Returns the ext2 dir-entry file type byte for an inode mode.
pub fn dir_entry_type_for_mode(mode: u16, is_dir: bool) -> u8 {
    if is_symlink_mode(mode) {
        EXT2_SYMLINK_DIR_ENTRY_TYPE
    } else if is_dir {
        2
    } else {
        1
    }
}

/// Returns true when this symlink target can be stored inline.
#[inline]
pub fn can_store_fast_symlink(target: &[u8]) -> bool {
    target.len() <= EXT2_FAST_SYMLINK_MAX_LEN
}
