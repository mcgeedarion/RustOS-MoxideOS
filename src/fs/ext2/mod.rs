//! Ext2 / Ext3 read-write filesystem driver.

pub mod superblock;
pub mod inode;
pub mod block;
pub mod bitmap;
pub mod directory;
pub mod symlink;
pub mod mount;

pub use mount::mount;
pub use superblock::{Ext2Stat, Ext2DirEntry, Ext2Statfs, FS};
pub use mount::{
    sys_stat, sys_lstat, sys_statfs, readdir, sys_readlink,
    read_file, write_file, create_file, unlink, rename, link,
    symlink, mkdir, rmdir, chmod, chown, truncate, set_times, statfs,
};
