//! Filesystem subsystem.
//!
//! Invariants:
//! - `vfs` owns path resolution and file descriptor operation dispatch.
//! - `dcache` entries are advisory caches and must never be treated as authority over on-disk state.
//! - Mount and scheme routing decisions are mediated via `mount`, `scheme_table`, and `scheme_fd`.
//! - Syscall-facing modules (`*_syscalls`, `ioctl`, `poll`, etc.) must preserve VFS locking/order constraints.

pub mod btrfs;
pub mod cgroupfs;
pub mod close_range;
pub mod dcache;
pub mod devfs;
pub mod elf;
pub mod eventfd;
pub mod ext2;
pub mod ext4;
pub mod ext4_write;
pub mod fanotify;
pub mod fat32;
pub mod fcntl;
pub mod flock;
pub mod getdents;
pub mod initramfs;
pub mod inotify;
pub mod io_syscalls;
pub mod ioctl;
pub mod ipc_proxy_scheme;
pub mod mount;
pub mod nfs;
pub mod overlayfs;
pub mod pidfd;
pub mod pipe;
pub mod poll;
pub mod poll_ext;
pub mod proc_debug;
pub mod process_fd;
pub mod procfs;
pub mod ramfs;
pub mod scheme_fd;      // new: scheme backing-fd store + dispatch helpers
pub mod scheme_table;
pub mod shm;
pub mod splice;
pub mod stat_syscalls;
pub mod sysfs;
pub mod timerfd;
pub mod tmpfs;
pub mod vfs;
pub mod vfs_ops;
pub mod vfs_uring;
