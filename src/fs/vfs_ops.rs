//! VFS mutation / query operations — dispatched through the mount table.
//!
//! Every function here:
//!   1. Calls `mount::resolve(path)` to get an `FsHandle`
//!   2. Dispatches to the correct backend (ext2, fat32, tmpfs, overlayfs, devfs, procfs, sysfs)
//!   3. Returns the standard POSIX errno-compatible isize / Result
//!
//! ## Backends wired
//! | FsType     | Module        | Notes                              |
//! |------------|---------------|------------------------------------|  
//! | Ext2       | fs::ext2      | read-write root; full inode ops    |
//! | Fat32      | fs::fat32     | ESP + USB; VFAT LFN                |
//! | Tmpfs      | fs::tmpfs     | /tmp /run /dev/shm (size-limited)  |
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

// ── Stat result (kernel-internal) ────────────────────────────────────────────────

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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_read_all(path),
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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_write_all(path, data),
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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_pread(path, offset, len),
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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_pwrite(path, offset, data),
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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_truncate(path, len),
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
        FsType::Tmpfs    => crate::fs::tmpfs::tmpfs_create(path),
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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_link(existing, new),
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
        FsType::Tmpfs    => crate::fs::tmpfs::tmpfs_mkdir(path),
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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_rmdir(path),
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
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_unlink(path),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::unlink(&om, &h.subpath)
        }
        _ => Err(-1),
    }
}

// ── rename ────────────────────────────────────────────────────────────────────

pub fn rename(old: &str, new: &str) -> Result<(), isize> {
    let h_o = mount::resolve(old)?;
    let h_n = mount::resolve(new)?;
    if h_o.fstype != h_n.fstype { return Err(-18); }
    if h_o.is_readonly() { return Err(-30); }
    match h_o.fstype {
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_rename(old, new),
        FsType::Ext2  => crate::fs::ext2::sys_rename(old, new).map(|_| ()),
        _             => Err(-38),
    }
}

// ── stat / lstat ──────────────────────────────────────────────────────────────

pub fn stat(path: &str) -> Result<KStat, isize> { stat_impl(path, false) }
pub fn lstat(path: &str) -> Result<KStat, isize> { stat_impl(path, true) }

fn stat_impl(path: &str, lstat: bool) -> Result<KStat, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Ext2 => {
            let s = if lstat {
                crate::fs::ext2::sys_lstat(path).map_err(|e| e as isize)?
            } else {
                crate::fs::ext2::sys_stat(path).map_err(|e| e as isize)?
            };
            Ok(KStat {
                ino: s.ino as u64, mode: s.mode, nlink: s.nlink,
                uid: s.uid, gid: s.gid, size: s.size,
                atime: s.atime, mtime: s.mtime, ctime: s.ctime,
                blksize: s.blksize as u64, blocks: s.blocks,
                is_dir: (s.mode & 0o170000) == 0o040000,
            })
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let fs_map = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = fs_map.get(&mp).ok_or(-2isize)?;
            let e = fs.stat(&h.subpath)?;
            Ok(KStat {
                ino: e.ino, mode: e.mode, nlink: 1,
                uid: 0, gid: 0, size: e.size,
                atime: e.mtime, mtime: e.mtime, ctime: e.mtime,
                blksize: 4096, blocks: e.size.div_ceil(512),
                is_dir: e.is_dir,
            })
        }
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_stat(path),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            let s = crate::fs::overlayfs::stat(&om, &h.subpath)?;
            Ok(KStat {
                ino: s.ino, mode: s.mode, nlink: s.nlink,
                uid: s.uid, gid: s.gid, size: s.size,
                atime: s.atime, mtime: s.mtime, ctime: s.ctime,
                blksize: s.blksize, blocks: s.blocks,
                is_dir: s.is_dir,
            })
        }
        FsType::Devfs  => crate::fs::devfs::stat(&h.subpath),
        FsType::Procfs => crate::fs::procfs::stat(&h.subpath),
        FsType::Sysfs  => crate::fs::sysfs::stat(&h.subpath),
    }
}

// ── statfs ────────────────────────────────────────────────────────────────────

/// Return filesystem statistics (sys_statfs / sys_fstatfs).
pub fn statfs(path: &str) -> Result<KStatfs, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Tmpfs  => crate::fs::tmpfs::tmpfs_statfs(path),
        // Stub for other types: return zeros.
        _ => Ok(KStatfs::default()),
    }
}

// ── readdir ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name:   String,
    pub ino:    u64,
    pub is_dir: bool,
    pub mode:   u16,
    pub size:   u64,
}

pub fn readdir(path: &str) -> Result<Vec<DirEntry>, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Ext2 => {
            let entries = crate::fs::ext2::readdir(path).map_err(|e| e as isize)?;
            Ok(entries.into_iter().map(|e| DirEntry {
                name: e.name, ino: e.ino as u64,
                is_dir: e.is_dir, mode: e.mode, size: e.size,
            }).collect())
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let fs_map = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = fs_map.get(&mp).ok_or(-2isize)?;
            let entries = fs.readdir(&h.subpath)?;
            Ok(entries.into_iter().map(|e| DirEntry {
                name: e.name, ino: e.ino,
                is_dir: e.is_dir, mode: e.mode, size: e.size,
            }).collect())
        }
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_readdir(path),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            let entries = crate::fs::overlayfs::readdir(&om, &h.subpath)?;
            Ok(entries.into_iter().map(|e| DirEntry {
                name: e.name, ino: e.ino,
                is_dir: e.is_dir, mode: e.mode, size: e.size,
            }).collect())
        }
        FsType::Devfs  => crate::fs::devfs::readdir(&h.subpath),
        FsType::Procfs => crate::fs::procfs::readdir(&h.subpath),
        FsType::Sysfs  => crate::fs::sysfs::readdir(&h.subpath),
    }
}

// ── symlink / readlink ────────────────────────────────────────────────────────

pub fn symlink(target: &str, link_path: &str) -> Result<(), isize> {
    let h = mount::resolve(link_path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_symlink(target, link_path),
        FsType::Ext2  => crate::fs::ext2::sys_symlink(target, link_path).map(|_| ()),
        _             => Err(-38),
    }
}

pub fn readlink(path: &str) -> Result<String, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_readlink(path),
        FsType::Ext2  => crate::fs::ext2::sys_readlink(path).map_err(|e| e as isize),
        _             => Err(-22),
    }
}

// ── chmod / chown ─────────────────────────────────────────────────────────────

pub fn chmod(path: &str, mode: u16) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_chmod(path, mode),
        FsType::Ext2  => crate::fs::ext2::sys_chmod(path, mode).map(|_| ()),
        _             => Err(-38),
    }
}

pub fn chown(path: &str, uid: u32, gid: u32) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    match h.fstype {
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_chown(path, uid, gid),
        FsType::Ext2  => crate::fs::ext2::sys_chown(path, uid, gid).map(|_| ()),
        _             => Err(-38),
    }
}

// ── open (VFS-level, returns kernel fd) ──────────────────────────────────────

pub fn open(path: &str, flags: u32) -> Result<usize, isize> {
    crate::fs::fcntl::fd_open(path, flags as i32)
}

// ── fd_path (reverse-map fd → path) ──────────────────────────────────────────

pub fn fd_path(fd: usize) -> Option<String> {
    crate::fs::fcntl::fd_get_path(fd)
}

// ── file_size ──────────────────────────────────────────────────────────────────

pub fn file_size(fd: usize) -> usize {
    crate::fs::fcntl::fd_size(fd).unwrap_or(0)
}

// ── mount / overlay helpers ───────────────────────────────────────────────────

fn overlay_mount(h: &mount::FsHandle) -> Result<OverlayMount, isize> {
    let mounts = crate::fs::overlayfs::OVERLAY_MOUNTS.lock();
    let om = mounts.get(&h.mount_point).ok_or(-2isize)?;
    Ok(om.clone())
}

fn mount_point_for(subpath: &str, full_path: &str) -> String {
    if subpath.is_empty() || full_path == subpath {
        return full_path.to_string();
    }
    let trimmed = full_path
        .strip_suffix(subpath)
        .unwrap_or(full_path)
        .trim_end_matches('/')
        .to_string();
    if trimmed.is_empty() { "/".to_string() } else { trimmed }
}

/// Mount a tmpfs instance at the given mount-point with a size limit.
pub fn tmpfs_mount(mount_point: &str, size_limit: usize) {
    crate::fs::tmpfs::tmpfs_mount(mount_point, size_limit);
}

/// Mount an overlayfs instance.
pub fn overlay_mount_at(mp: &str, opts: OverlayOpts) -> Result<(), isize> {
    let om = OverlayMount {
        lower:  opts.lower.clone(),
        upper:  opts.upper.clone(),
        work:   opts.work.clone(),
        merged: mp.to_string(),
    };
    let mut mounts = crate::fs::overlayfs::OVERLAY_MOUNTS.lock();
    mounts.insert(mp.to_string(), om);
    Ok(())
}

// ── parse_size — human-readable size helper (used by mount(2) handler) ────────

pub fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    for (suffix, mult) in &[
        ("T",  1024*1024*1024*1024usize),
        ("G",  1024*1024*1024),
        ("M",  1024*1024),
        ("K",  1024),
        ("k",  1024),
    ] {
        if let Some(num_str) = s.strip_suffix(suffix) {
            let n: usize = num_str.trim().parse().ok()?;
            return Some(n * mult);
        }
    }
    // Percentage of total RAM.
    if let Some(num_str) = s.strip_suffix('%') {
        let pct: usize = num_str.trim().parse().ok()?;
        let total = crate::mm::pmm::total_pages() * 4096;
        return Some((total / 100) * pct);
    }
    // Case-insensitive suffixes.
    let sl = s.to_ascii_lowercase();
    for (suffix, mult) in &[
        ("tib", 1024usize*1024*1024*1024),
        ("gib", 1024*1024*1024),
        ("mib", 1024*1024),
        ("kib", 1024),
        ("tb",  1000*1000*1000*1000),
        ("gb",  1000*1000*1000),
        ("mb",  1000*1000),
        ("kb",  1000),
    ] {
        if let Some(num_str) = sl.strip_suffix(suffix) {
            let n: usize = num_str.trim().parse().ok()?;
            return Some(n * mult);
        }
    }
    s.parse::<usize>().ok()
}
