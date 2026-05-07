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

// ── Stat result (kernel-internal, mirrors struct stat fields we care about) ──

#[derive(Clone, Debug, Default)]
pub struct KStat {
    pub ino:    u64,
    pub mode:   u16,
    pub nlink:  u32,
    pub size:   u64,
    pub is_dir: bool,
}

// ── read_all / write_all — convenience wrappers used by overlayfs ────────────

/// Read the entire contents of `path` into a Vec<u8>.
pub fn read_all(path: &str) -> Result<Vec<u8>, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Ext2 => {
            // Forward to ext2 via the kernel fd table
            use crate::fs::fcntl::{fd_open, fd_read, fd_close};
            let fd = fd_open(path, 0).map_err(|e| e)?;
            let mut data = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = fd_read(fd, &mut chunk);
                if n <= 0 { break; }
                data.extend_from_slice(&chunk[..n as usize]);
            }
            fd_close(fd);
            Ok(data)
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut f = crate::fs::fat32::fat_open(&mp, &h.subpath)?;
            let mut data = alloc::vec![0u8; f.size as usize];
            let fs_map = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = fs_map.get(&mp).ok_or(-2isize)?;
            fs.read(&mut f, &mut data).map(|_| data)
        }
        FsType::Tmpfs => {
            crate::fs::ramfs::tmpfs_read_all(&h.subpath)
        }
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            let mut buf = Vec::new();
            crate::fs::overlayfs::read(&om, &h.subpath, &mut buf)?;
            Ok(buf)
        }
        FsType::Devfs  => crate::fs::devfs::read_all(&h.subpath),
        FsType::Procfs => crate::fs::procfs::read_all(&h.subpath),
        FsType::Sysfs  => crate::fs::sysfs::read_all(&h.subpath),
    }
}

/// Write `data` to `path`, truncating the file first.
pub fn write_all(path: &str, data: &[u8]) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); } // EROFS
    match h.fstype {
        FsType::Ext2 => {
            use crate::fs::fcntl::{fd_open, fd_write, fd_close};
            // O_WRONLY | O_TRUNC | O_CREAT = 0x241
            let fd = fd_open(path, 0x241).map_err(|e| e)?;
            let n  = fd_write(fd, data);
            fd_close(fd);
            if n < 0 { Err(n as isize) } else { Ok(()) }
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut f = crate::fs::fat32::fat_open(&mp, &h.subpath)
                .or_else(|_| crate::fs::fat32::fat_creat(&mp, &h.subpath))?;
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.truncate(&mut f, 0)?;
            fs.write(&mut f, data).map(|_| ())
        }
        FsType::Tmpfs => {
            crate::fs::ramfs::tmpfs_write_all(&h.subpath, data)
        }
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::write(&om, &h.subpath, data)
        }
        FsType::Devfs | FsType::Procfs | FsType::Sysfs => Err(-30), // EROFS
    }
}

// ── create ────────────────────────────────────────────────────────────────────

pub fn create(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Ext2 => {
            use crate::fs::fcntl::{fd_open, fd_close};
            // O_CREAT | O_WRONLY | O_TRUNC
            let fd = fd_open(path, 0x241).map_err(|e| e)?;
            fd_close(fd); Ok(())
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            crate::fs::fat32::fat_creat(&mp, &h.subpath).map(|_| ())
        }
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_create(&h.subpath),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::create(&om, &h.subpath).map(|_| ())
        }
        _ => Err(-1), // EPERM
    }
}

// ── mkdir ─────────────────────────────────────────────────────────────────────

pub fn mkdir(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Ext2 => {
            crate::fs::ext2::sys_mkdir(path, 0o755).map(|_| ())
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.mkdir(&h.subpath)
        }
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_mkdir(&h.subpath),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::mkdir(&om, &h.subpath)
        }
        _ => Err(-1),
    }
}

// ── unlink ────────────────────────────────────────────────────────────────────

pub fn unlink(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Ext2 => {
            crate::fs::ext2::sys_unlink(path).map(|_| ())
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.unlink(&h.subpath)
        }
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_unlink(&h.subpath),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::unlink(&om, &h.subpath)
        }
        _ => Err(-1),
    }
}

// ── readdir ───────────────────────────────────────────────────────────────────

pub fn readdir(path: &str) -> Result<Vec<String>, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Ext2 => {
            crate::fs::ext2::sys_getdents(path)
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get(&mp).ok_or(-2isize)?;
            let entry = fs.walk(&h.subpath)?;
            let entries = fs.read_dir(entry.cluster)?;
            Ok(entries.into_iter().map(|e| e.name).collect())
        }
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_readdir(&h.subpath),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::readdir(&om, &h.subpath)
        }
        FsType::Devfs  => crate::fs::devfs::readdir(&h.subpath),
        FsType::Procfs => crate::fs::procfs::readdir(&h.subpath),
        FsType::Sysfs  => crate::fs::sysfs::readdir(&h.subpath),
    }
}

// ── stat ──────────────────────────────────────────────────────────────────────

pub fn stat(path: &str) -> Result<KStat, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Ext2 => {
            crate::fs::stat_syscalls::kstat_ext2(path)
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get(&mp).ok_or(-2isize)?;
            let e = fs.walk(&h.subpath)?;
            Ok(KStat {
                ino:    e.cluster as u64,
                mode:   if e.is_dir() { 0o040755 } else { 0o100644 },
                nlink:  1,
                size:   e.size as u64,
                is_dir: e.is_dir(),
            })
        }
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_stat(&h.subpath),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            let concrete = crate::fs::overlayfs::lookup(&om, &h.subpath)?;
            stat(&concrete)
        }
        FsType::Devfs  => crate::fs::devfs::stat(&h.subpath),
        FsType::Procfs => crate::fs::procfs::stat(&h.subpath),
        FsType::Sysfs  => crate::fs::sysfs::stat(&h.subpath),
    }
}

// ── rename ────────────────────────────────────────────────────────────────────

pub fn rename(old: &str, new: &str) -> Result<(), isize> {
    let h_old = mount::resolve(old)?;
    let h_new = mount::resolve(new)?;
    if h_old.is_readonly() { return Err(-30); }
    // Cross-mount rename is not supported
    if h_old.fstype != h_new.fstype { return Err(-18); } // EXDEV
    match h_old.fstype {
        FsType::Ext2 => {
            crate::fs::ext2::sys_rename(old, new).map(|_| ())
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h_old.subpath, old);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.rename(&h_old.subpath, &h_new.subpath)
        }
        FsType::Tmpfs => {
            crate::fs::ramfs::tmpfs_rename(&h_old.subpath, &h_new.subpath)
        }
        FsType::Overlayfs => {
            let om = overlay_mount(&h_old)?;
            crate::fs::overlayfs::rename(&om, &h_old.subpath, &h_new.subpath)
        }
        _ => Err(-1),
    }
}

// ── sys_mount / sys_umount2 — syscall entry points ───────────────────────────

/// Kernel entry point for the mount(2) syscall.  Validates arguments and
/// triggers any backend-specific initialisation (e.g. fat_mount for FAT32).
pub fn sys_mount(source: &str, target: &str, fstype: &str, flags: u64, data: &str) -> isize {
    // Register in the mount table first
    let rc = mount::sys_mount(source, target, fstype, flags, data);
    if rc != 0 { return rc; }
    // For FAT32, probe the block device and cache the BPB
    if fstype == "vfat" || fstype == "fat32" || fstype == "fat" {
        // Derive a device number from the source path (simplified: use hash)
        let dev = source.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        if let Err(e) = crate::fs::fat32::fat_mount(dev, target) {
            // Roll back the mount table entry
            mount::sys_umount2(target, 0);
            return e;
        }
    }
    0
}

/// Kernel entry point for umount2(2).
pub fn sys_umount2(target: &str, flags: u32) -> isize {
    mount::sys_umount2(target, flags)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Reconstruct the mount-point string from a resolved subpath + original path.
/// Example: path="/boot/efi/EFI/boot", subpath="/EFI/boot" → "/boot/efi"
fn mount_point_for(subpath: &str, full_path: &str) -> String {
    let sub  = subpath.trim_start_matches('/');
    let full = full_path.trim_end_matches('/');
    if sub.is_empty() {
        full.to_string()
    } else {
        let end = full.len().saturating_sub(sub.len()).saturating_sub(1);
        full[..end].to_string()
    }
}

/// Build an OverlayMount from an FsHandle's embedded OverlayOpts.
fn overlay_mount(h: &crate::fs::mount::FsHandle) -> Result<OverlayMount, isize> {
    h.overlay.as_ref()
     .map(|o| OverlayMount::from_opts(o))
     .ok_or(-22) // EINVAL — overlayfs mount missing options
}
