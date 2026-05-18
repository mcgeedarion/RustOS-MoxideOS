//! Ext2/3/4 filesystem driver — submodule index.
pub mod superblock;
pub mod ops;
pub mod alloc;
pub mod mount;

pub use mount::mount;
pub use superblock::{Ext2Stat, Ext2Statfs, FS};
pub use mount::{
    sys_stat, sys_lstat, sys_statfs, sys_readlink,
    read_file, write_file, create_file, unlink, rename, link,
    symlink, mkdir, rmdir, chmod, chown, truncate, set_times,
};
