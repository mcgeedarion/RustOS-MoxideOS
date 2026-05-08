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

// ── read_all / write_all ─────────────────────────────────────────────────────

pub fn read_all(path: &str) -> Result<Vec<u8>, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Ext2 => {
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
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_read_all(path),
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

pub fn write_all(path: &str, data: &[u8]) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Ext2 => {
            use crate::fs::fcntl::{fd_open, fd_write, fd_close};
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
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_write_all(path, data),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::write(&om, &h.subpath, data)
        }
        FsType::Devfs | FsType::Procfs | FsType::Sysfs => Err(-30),
    }
}

// ── pread / pwrite — offset-based I/O ────────────────────────────────────────

pub fn pread(path: &str, offset: usize, len: usize) -> Result<Vec<u8>, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_pread(path, offset, len),
        FsType::Ext2 => {
            let data = read_all(path)?;
            if offset >= data.len() { return Ok(Vec::new()); }
            let end = (offset + len).min(data.len());
            Ok(data[offset..end].to_vec())
        }
        FsType::Fat32 => {
            let data = read_all(path)?;
            if offset >= data.len() { return Ok(Vec::new()); }
            let end = (offset + len).min(data.len());
            Ok(data[offset..end].to_vec())
        }
        _ => Err(-38),
    }
}

pub fn pwrite(path: &str, offset: usize, data: &[u8]) -> Result<usize, isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_pwrite(path, offset, data),
        FsType::Ext2 | FsType::Fat32 => {
            let mut full = read_all(path).unwrap_or_default();
            let end = offset + data.len();
            if end > full.len() { full.resize(end, 0); }
            full[offset..end].copy_from_slice(data);
            write_all(path, &full)?;
            Ok(data.len())
        }
        _ => Err(-38),
    }
}

// ── truncate ────────────────────────────────────────────────────────────────────

pub fn truncate(path: &str, len: usize) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_truncate(path, len),
        FsType::Ext2 => {
            crate::fs::ext2::sys_truncate(path, len as u64).map(|_| ())
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut f = crate::fs::fat32::fat_open(&mp, &h.subpath)?;
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.truncate(&mut f, len as u64)
        }
        _ => Err(-38),
    }
}

// ── create ────────────────────────────────────────────────────────────────────

pub fn create(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Ext2 => {
            use crate::fs::fcntl::{fd_open, fd_close};
            let fd = fd_open(path, 0x241).map_err(|e| e)?;
            fd_close(fd); Ok(())
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            crate::fs::fat32::fat_creat(&mp, &h.subpath).map(|_| ())
        }
        FsType::Tmpfs    => crate::fs::ramfs::tmpfs_create(path),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::create(&om, &h.subpath).map(|_| ())
        }
        _ => Err(-1),
    }
}

// ── link ──────────────────────────────────────────────────────────────────────

pub fn link(existing: &str, new: &str) -> Result<(), isize> {
    let h_e = mount::resolve(existing)?;
    let h_n = mount::resolve(new)?;
    if h_e.fstype != h_n.fstype { return Err(-18); }
    if h_e.is_readonly() { return Err(-30); }
    match h_e.fstype {
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_link(existing, new),
        FsType::Ext2  => crate::fs::ext2::sys_link(existing, new).map(|_| ()),
        _             => Err(-38),
    }
}

// ── mkdir ─────────────────────────────────────────────────────────────────────

pub fn mkdir(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Ext2 => crate::fs::ext2::sys_mkdir(path, 0o755).map(|_| ()),
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.mkdir(&h.subpath)
        }
        FsType::Tmpfs    => crate::fs::ramfs::tmpfs_mkdir(path),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::mkdir(&om, &h.subpath)
        }
        _ => Err(-1),
    }
}

// ── rmdir ─────────────────────────────────────────────────────────────────────

pub fn rmdir(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_rmdir(path),
        FsType::Ext2  => crate::fs::ext2::sys_rmdir(path).map(|_| ()),
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.rmdir(&h.subpath)
        }
        _ => Err(-1),
    }
}

// ── unlink ────────────────────────────────────────────────────────────────────

pub fn unlink(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Ext2 => crate::fs::ext2::sys_unlink(path).map(|_| ()),
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.unlink(&h.subpath)
        }
        FsType::Tmpfs    => crate::fs::ramfs::tmpfs_unlink(path),
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
        FsType::Ext2 => crate::fs::ext2::sys_getdents(path),
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get(&mp).ok_or(-2isize)?;
            let entry = fs.walk(&h.subpath)?;
            let entries = fs.read_dir(entry.cluster)?;
            Ok(entries.into_iter().map(|e| e.name).collect())
        }
        FsType::Tmpfs    => crate::fs::ramfs::tmpfs_readdir(path),
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
        FsType::Ext2 => crate::fs::stat_syscalls::kstat_ext2(path),
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
                ..KStat::default()
            })
        }
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_stat(path),
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

// ── chmod / chown ──────────────────────────────────────────────────────────────

/// Change permission bits. Native on tmpfs; no-op stub on other backends.
pub fn chmod(path: &str, mode: u16) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_chmod(path, mode),
        // ext2 chmod can be wired in later; for now succeed silently.
        FsType::Ext2 | FsType::Fat32 => Ok(()),
        _ => Ok(()), // virtual FSes: no-op
    }
}

/// Change owner/group. Native on tmpfs; no-op on other backends.
pub fn chown(path: &str, uid: u32, gid: u32) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::ramfs::tmpfs_chown(path, uid, gid),
        FsType::Ext2 | FsType::Fat32 => Ok(()),
        _ => Ok(()),
    }
}

// ── rename ────────────────────────────────────────────────────────────────────

pub fn rename(old: &str, new: &str) -> Result<(), isize> {
    let h_old = mount::resolve(old)?;
    let h_new = mount::resolve(new)?;
    if h_old.is_readonly() { return Err(-30); }
    if h_old.fstype != h_new.fstype { return Err(-18); }
    match h_old.fstype {
        FsType::Ext2 => crate::fs::ext2::sys_rename(old, new).map(|_| ()),
        FsType::Fat32 => {
            let mp = mount_point_for(&h_old.subpath, old);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.rename(&h_old.subpath, &h_new.subpath)
        }
        FsType::Tmpfs    => crate::fs::ramfs::tmpfs_rename(old, new),
        FsType::Overlayfs => {
            let om = overlay_mount(&h_old)?;
            crate::fs::overlayfs::rename(&om, &h_old.subpath, &h_new.subpath)
        }
        _ => Err(-1),
    }
}

// ── sys_mount / sys_umount2 ───────────────────────────────────────────────────

pub fn sys_mount(source: &str, target: &str, fstype: &str, flags: u64, data: &str) -> isize {
    let rc = mount::sys_mount(source, target, fstype, flags, data);
    if rc != 0 { return rc; }
    if fstype == "vfat" || fstype == "fat32" || fstype == "fat" {
        let dev = source.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        if let Err(e) = crate::fs::fat32::fat_mount(dev, target) {
            mount::sys_umount2(target, 0);
            return e;
        }
    }
    if fstype == "tmpfs" {
        let limit = parse_size_option(data).unwrap_or(64 * 1024 * 1024);
        crate::fs::ramfs::tmpfs_mount(target, limit);
    }
    0
}

pub fn sys_umount2(target: &str, flags: u32) -> isize {
    mount::sys_umount2(target, flags)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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

fn overlay_mount(h: &crate::fs::mount::FsHandle) -> Result<OverlayMount, isize> {
    h.overlay.as_ref()
     .map(|o| OverlayMount::from_opts(o))
     .ok_or(-22)
}

fn parse_size_option(data: &str) -> Option<usize> {
    for part in data.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("size=") {
            let (num_str, mult) = if val.ends_with('k') || val.ends_with('K') {
                (&val[..val.len()-1], 1024usize)
            } else if val.ends_with('m') || val.ends_with('M') {
                (&val[..val.len()-1], 1024 * 1024)
            } else if val.ends_with('g') || val.ends_with('G') {
                (&val[..val.len()-1], 1024 * 1024 * 1024)
            } else if val.ends_with('%') {
                let pct: usize = val[..val.len()-1].parse().ok()?;
                return Some((512 * 1024 * 1024 / 100) * pct);
            } else {
                (val, 1)
            };
            let n: usize = num_str.parse().ok()?;
            return Some(n * mult);
        }
    }
    None
}
