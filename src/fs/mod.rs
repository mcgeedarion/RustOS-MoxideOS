//! Filesystem subsystem.

pub mod binfmt_misc;
pub mod btrfs;
pub mod cdfs;
pub mod cgroupfs;
pub mod close_range;
pub mod dcache;
pub mod devfs;
pub mod elf;
pub mod eventfd;
pub mod exfat;
pub mod ext2;
pub mod ext4;
pub mod ext4_write;
pub mod fanotify;
pub mod fat32;
pub mod fcntl;
pub mod flock;
pub mod fs_recognizer;
pub mod getdents;
pub mod initramfs;
pub mod inotify;
pub mod io_syscalls;
pub mod ioctl;
pub mod ipc_proxy_scheme;
pub mod jbd2;
pub mod mount;
pub mod nfs;
pub mod ntfs;
pub mod overlayfs;
pub mod path;
pub mod pidfd;
pub mod pipe;
pub mod poll;
pub mod poll_ext;
pub mod proc_debug;
pub mod process_fd;
pub mod procfs;
pub mod procfs_binfmt;
pub mod ramfs;
pub mod scheme_fd; // new: scheme backing-fd store + dispatch helpers
pub mod scheme_table;
pub mod shm;
pub mod signalfd;
pub mod splice;
pub mod stat_syscalls;
pub mod sysfs;
pub mod timerfd;
pub mod tmpfs;
pub mod vfs;

// Compatibility aliases while call sites migrate to `crate::fs::vfs::ops`
// and `crate::fs::vfs::uring`.
pub use vfs::ops as vfs_ops;
pub use vfs::uring as vfs_uring;
