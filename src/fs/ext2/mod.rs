//! ext2 filesystem driver — submodule index.
//!
//! Layout:
//!   superblock.rs — on-disk types: Superblock, BgDesc, Inode, DirEntry,
//!                   Ext2Stat, Ext2Statfs, Ext2Fs, FS static
//!                   (previously split out as structs.rs)
//!   inode.rs      — all impl Ext2Fs methods + Ext2DirEntry
//!                   (merged from inode.rs + structs.rs + impl_a.rs + impl_b.rs)
//!   block.rs / bitmap.rs / directory.rs / symlink.rs — helpers
//!   api.rs        — pub mount() + all sys_* / vfs wrapper functions

pub mod superblock;
pub mod inode;
pub mod block;
pub mod bitmap;
pub mod directory;
pub mod symlink;
pub mod api;

pub use superblock::{Ext2Stat, Ext2Statfs};
pub use inode::Ext2DirEntry;
pub use api::{
    mount, sys_stat, sys_lstat, sys_statfs, readdir, sys_readlink,
    sys_truncate, sys_link, sys_mkdir, sys_rmdir, sys_unlink,
    sys_rename, sys_symlink, sys_chmod, sys_chown, set_times,
    read_file, write_file, create_file,
};