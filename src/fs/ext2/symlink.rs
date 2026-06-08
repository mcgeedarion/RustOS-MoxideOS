//! ext2 symbolic-link helpers.
//!
//! ext2 stores short symlink targets directly in the inode `i_block`
//! area. These are commonly called "fast symlinks". Longer targets are
//! stored in normal data blocks and are read through the inode data path.

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// File type mask for an ext2 inode mode.
const EXT2_S_IFMT: u16 = 0xF000;
///