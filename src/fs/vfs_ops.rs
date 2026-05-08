
//! VFS mutation / query operations — dispatched through the mount table.
//!
//! Every function here:
//!   1. Calls `mount::resolve(path)` to get an `FsHandle`
//!   2. Dispatches to the correct backend (ext2, fat32, ramfs, overlayfs, devfs, procfs, sysfs)
//!   3. Returns the standard POSIX errno-compatible isize / Result
//!
//! ## Backends wired
//! | FsType     | Module        | Notes                              |
//! |------------|---------------|------------------------------------|  
//! | Ext2       | fs::ext2      | read-write root; full inode ops    |
//! | Fat32      | fs::fat32     | ESP + USB; VFAT LFN                |
//! | Tmpfs      | fs::ramfs     | /tmp /run /dev/shm                 |
//! | Overlayfs  | fs::overlayfs | copy-up + whiteout merge           |
//! | Devfs      | fs::devfs     | character / block device nodes     |
//! | Procfs     | fs::procfs    | /proc virtual files                |
//! | Sysfs      | fs::sysfs     | /sys virtual files                 |

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::fs::mount::{self, FsType, OverlayOpts};
use crate::fs::overlayfs::OverlayMount;

// ── Stat result (kernel-internal) ──────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct KStat {
    pub ino:     u64,
    pub mode:    u16,
    pub nlink:   u32,
    pub uid:     u32,
    pub gid:     u32,
    pub size:    u64,
    pub atime:   u64,
    pub mtime:   u64,
    pub ctime:   u64,
    pub blksize: u64,
    pub blocks:  u64,
    pub is_dir:  bool,
}

// ── Statfs result (kernel-internal) ─────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct KStatfs {
    pub f_type:    u64,
    pub f_bsize:   u64,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_bavail:  u64,
    pub f_namelen: u64,
}

