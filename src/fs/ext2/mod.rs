//! ext2 filesystem driver — submodule index.
//!
//! Layout:
//!   structs.rs  — on-disk types: Superblock, BgDesc, Inode, DirEntry + pub structs
//!   impl_a.rs   — impl Ext2Fs low-level: block/inode I/O, bitmap alloc (lines 258–640)
//!   impl_b.rs   — impl Ext2Fs high-level: path resolution, dir ops (lines 641–1034)
//!   api.rs      — pub mount() + all sys_* / vfs wrapper functions

pub mod structs;
pub mod impl_a;
pub mod impl_b;
pub mod api;

pub use structs::{Ext2Stat, Ext2DirEntry, Ext2Statfs};
pub use api::{
    mount, sys_stat, sys_lstat, sys_statfs, readdir, sys_readlink,
    sys_truncate, sys_link, sys_mkdir, sys_rmdir, sys_unlink,
    sys_rename, sys_symlink, sys_chmod, sys_chown, set_times,
    read_file, write_file, create_file,
};