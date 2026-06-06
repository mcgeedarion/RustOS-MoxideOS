//! Btrfs filesystem driver — submodule index.
//!
//! Layout:
//!   superblock.rs — all on-disk structs, constants, block I/O helpers,
//!                   and the lower impl BtrfsFs (btree search, chunk map,
//!                   read path) — previously split out as tree_impl.rs
//!   ops.rs        — upper impl BtrfsFs: readdir, create, unlink, rename …
//!                   (previously fs_ops.rs)
//!   inode.rs      — BtrfsInodeItem
//!   extent.rs     — BtrfsFileExtentItem
//!   directory.rs  — BtrfsDirItem
//!   mount.rs      — mount-time setup
//!   api.rs        — pub fn mount() + pub btrfs_* wrappers
//!   checksum.rs   — crc32c stub
//!   compression.rs— decompression stubs
//!   transaction.rs— CoW write path re-export
//!   allocator.rs  — bump allocator re-export

pub mod allocator;
pub mod api;
pub mod checksum;
pub mod compression;
pub mod directory;
pub mod extent;
pub mod inode;
pub mod mount;
pub mod ops;
pub mod superblock;
pub mod transaction;
pub mod tree;

pub use api::{
    btrfs_chmod, btrfs_chown, btrfs_create, btrfs_link, btrfs_mkdir, btrfs_read_all, btrfs_readdir,
    btrfs_readlink, btrfs_rename, btrfs_rmdir, btrfs_set_times, btrfs_stat, btrfs_statfs,
    btrfs_symlink, btrfs_truncate, btrfs_unlink, btrfs_write_all, mount, sync_inode,
};
pub use superblock::{
    BtrfsChunkItem, BtrfsDirItem, BtrfsFileExtentItem, BtrfsFs, BtrfsHeader, BtrfsInodeItem,
    BtrfsItem, BtrfsKey, BtrfsKeyPtr, BtrfsRootItem, BtrfsSuperblock, BTRFS_MOUNTS,
};
