//! Public VFS entry-points: mount(), btrfs_stat(), btrfs_read_all() …
//! Source lines 1240–end of the original btrfs.rs monolith.
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use super::superblock::{BtrfsFs, BTRFS_MOUNTS};

