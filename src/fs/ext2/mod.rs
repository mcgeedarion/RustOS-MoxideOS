//! ext2 filesystem driver — submodule index.
//!
//! Layout:
//!   superblock.rs — on-disk types: Superblock, BgDesc, Inode, DirEntry,
//!                   Ext2Stat, Ext2Statfs, Ext2Fs, FS static
//!                   (previously split out as structs.rs)
//!   inode.rs      — all impl Ext2Fs methods + Ext2DirEntry
//!                   (merged from inode.rs + structs.rs + impl_a.rs +
//! impl_b.rs)   block.rs / bitmap.rs / directory.rs / symlink.rs — helpers
//!   api.rs        — pub mount() + all sys_* / vfs wrapper functions

pub mod api;
pub mod bitmap;
pub mod block;
pub mod directory;
pub mod inode;
pub mod superblock;
pub mod symlink;

pub use api::{
    create_file, mount, read_file, readdir, set_times, sys_chmod, sys_chown, sys_link, sys_lstat,
    sys_mkdir, sys_readlink, sys_rename, sys_rmdir, sys_stat, sys_statfs, sys_symlink,
    sys_truncate, sys_unlink, write_file,
};
pub use inode::Ext2DirEntry;
pub use superblock::{Ext2Stat, Ext2Statfs};
