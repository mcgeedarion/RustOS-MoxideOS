//! Btrfs filesystem driver — submodule index.
//!
//! Layout:
//!   superblock.rs — all on-disk structs, constants, block I/O helpers
//!   tree_impl.rs  — lower impl BtrfsFs: btree search, chunk map, read path
//!   fs_ops.rs     — upper impl BtrfsFs: readdir, create, unlink, rename …
//!   api.rs        — pub fn mount() + pub btrfs_* wrappers
//!   checksum.rs   — crc32c stub
//!   compression.rs— decompression stubs
//!   transaction.rs— CoW write path re-export
//!   allocator.rs  — bump allocator re-export

pub mod superblock;
pub mod tree_impl;
pub mod fs_ops;
pub mod api;
pub mod checksum;
pub mod compression;
pub mod transaction;
pub mod allocator;

pub use superblock::{
    BtrfsKey, BtrfsSuperblock, BtrfsChunkItem, BtrfsRootItem,
    BtrfsHeader, BtrfsItem, BtrfsKeyPtr, BtrfsFs, BtrfsInodeItem,
    BtrfsFileExtentItem, BtrfsDirItem, BTRFS_MOUNTS,
};
pub use api::{
    mount, btrfs_stat, btrfs_read_all, btrfs_write_all, btrfs_readdir,
    btrfs_create, btrfs_mkdir, btrfs_unlink, btrfs_rmdir, btrfs_rename,
    btrfs_link, btrfs_symlink, btrfs_readlink, btrfs_chmod, btrfs_chown,
    btrfs_set_times, btrfs_truncate, btrfs_statfs, sync_inode,
};