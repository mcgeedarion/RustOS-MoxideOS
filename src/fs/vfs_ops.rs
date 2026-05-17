//! VFS mutation / query operations — dispatched through the mount table.
//!
//! Every function here:
//!   1. For stat/lstat: checks dcache first; on miss calls mount::resolve +
//!      backend, then populates the cache.
//!   2. For write-side ops: calls the backend, then invalidates the dcache
//!      entry so subsequent stat calls see fresh data.
//!   3. Returns the standard POSIX errno-compatible isize / Result
//!
//! ## Backends wired
//! | FsType      | Module          | Notes                                  |
//! |-------------|-----------------|----------------------------------------|
//! | Ext2        | fs::ext2        | read-write root; full inode ops        |
//! | Ext4        | fs::ext4        | read-only root; extents + 64-bit blk   |
//! | Fat32       | fs::fat32       | ESP + USB; VFAT LFN                    |
//! | Tmpfs       | fs::tmpfs       | /tmp /run /dev/shm (size-limited)      |
//! | Overlayfs   | fs::overlayfs   | copy-up + whiteout merge               |
//! | Devfs       | fs::devfs       | character / block device nodes         |
//! | Procfs      | fs::procfs      | /proc virtual files                    |
//! | Sysfs       | fs::sysfs       | /sys virtual files                     |
//! | Cgroupfs    | fs::cgroupfs    | /sys/fs/cgroup cgroup v2 hierarchy     |
//! | Btrfs       | fs::btrfs       | CoW B-tree; read-write                 |

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::fs::mount::{self, FsType, OverlayOpts};
use crate::fs::overlayfs::OverlayMount;
use crate::fs::dcache;

// ── Stat result (kernel-internal) ───────────────────────────────────────────────

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

// ── Statfs result (kernel-internal) ───────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct KStatfs {
    pub f_type:    u64,
    pub f_bsize:   u64,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_bavail:  u64,
    pub f_namelen: u64,
}

// Well-known f_type magic numbers (matches Linux)
const FSTYPE_EXT2:    u64 = 0xEF53;
const FSTYPE_EXT4:    u64 = 0xEF53;
const FSTYPE_FAT32:   u64 = 0x4d44;
const FSTYPE_TMPFS:   u64 = 0x0102_1994;
const FSTYPE_OVERLAY: u64 = 0x794c_7630;
const FSTYPE_DEVTMPFS:u64 = 0x1373;
const FSTYPE_PROC:    u64 = 0x9fa0;
const FSTYPE_SYSFS:   u64 = 0x6265_6572;
const FSTYPE_CGROUP2: u64 = 0x6367_7270;

// ── Cgroupfs path prefix ──────────────────────────────────────────────────────

#[inline(always)]
fn is_cgroupfs_path(path: &str) -> bool {
    path.starts_with("/sys/fs/cgroup")
}

// ── read_all / write_all ─────────────────────────────────────────────────

pub fn read_all(path: &str) -> Result<Vec<u8>, isize> {
    if is_cgroupfs_path(path) {
        let fd = crate::fs::cgroupfs::cgroupfs_open(path);
        if fd < 0 { return Err(fd as isize); }
        let fd = fd as usize;
        let mut data = alloc::vec![0u8; 4096];
        let n = crate::fs::cgroupfs::cgroupfs_read(fd, &mut data);
        crate::fs::cgroupfs::cgroupfs_close(fd);
        if n < 0 { return Err(n as isize); }
        data.truncate(n as usize);
        return Ok(data);
    }
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_read_all(&h.subpath),
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
        FsType::Ext4 => {
            let ino = crate::fs::ext4::stat(path).ok_or(-2isize)?;
            crate::fs::ext4::read_file_by_ino(ino).ok_or(-2isize)
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
        FsType::Cgroupfs => unreachable!(),
    }
}

pub fn write_all(path: &str, data: &[u8]) -> Result<(), isize> {
    if is_cgroupfs_path(path) {
        let s = core::str::from_utf8(data).map_err(|_| -22isize)?;
        let knob = path.split('/').last().unwrap_or("");
        let cg_id = crate::proc::cgroup::path_to_cgid(path
            .strip_suffix(knob).unwrap_or(path)
            .trim_end_matches('/'))
            .ok_or(-2isize)?;
        let rc = crate::proc::cgroup::write_knob(cg_id, knob, s);
        return if rc == 0 { Ok(()) } else { Err(rc) };
    }
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_write_all(&h.subpath, data),
        FsType::Ext2 => {
            use crate::fs::fcntl::{fd_open, fd_write, fd_close};
            let fd = fd_open(path, 0x241).map_err(|e| e)?;
            let n  = fd_write(fd, data);
            fd_close(fd);
            if n < 0 { Err(n as isize) } else { Ok(()) }
        }
        FsType::Ext4 => Err(-30),
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
        FsType::Cgroupfs => unreachable!(),
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── pread / pwrite ─────────────────────────────────────────────────────────

pub fn pread(path: &str, offset: usize, len: usize) -> Result<Vec<u8>, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_pread(path, offset, len),
        FsType::Btrfs => {
            let data = crate::fs::btrfs::btrfs_read_all(&h.subpath)?;
            if offset >= data.len() { return Ok(Vec::new()); }
            let end = (offset + len).min(data.len());
            Ok(data[offset..end].to_vec())
        }
        _ => {
            let data = read_all(path)?;
            if offset >= data.len() { return Ok(Vec::new()); }
            let end = (offset + len).min(data.len());
            Ok(data[offset..end].to_vec())
        }
    }
}

pub fn pwrite(path: &str, offset: usize, data: &[u8]) -> Result<usize, isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => {
            let mut full = crate::fs::btrfs::btrfs_read_all(&h.subpath).unwrap_or_default();
            let end = offset + data.len();
            if end > full.len() { full.resize(end, 0); }
            full[offset..end].copy_from_slice(data);
            crate::fs::btrfs::btrfs_write_all(&h.subpath, &full)?;
            Ok(data.len())
        }
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_pwrite(path, offset, data),
        FsType::Ext2 | FsType::Fat32 | FsType::Overlayfs => {
            let mut full = read_all(path).unwrap_or_default();
            let end = offset + data.len();
            if end > full.len() { full.resize(end, 0); }
            full[offset..end].copy_from_slice(data);
            write_all(path, &full)?;
            Ok(data.len())
        }
        FsType::Ext4 => Err(-30),
        _ => Err(-38),
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── truncate ──────────────────────────────────────────────────────────────

pub fn truncate(path: &str, len: usize) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_truncate(&h.subpath, len),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_truncate(path, len),
        FsType::Ext2 => {
            crate::fs::ext2::sys_truncate(path, len as u64).map(|_| ())
        }
        FsType::Ext4 => Err(-30),
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut f = crate::fs::fat32::fat_open(&mp, &h.subpath)?;
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.truncate(&mut f, len as u64)
        }
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::truncate(&om, &h.subpath, len as u64)
        }
        _ => Err(-38),
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

pub fn truncate_fd(bfd: usize, len: usize) -> Result<(), isize> {
    let path = crate::fs::fcntl::fd_get_path(bfd).ok_or(-9isize)?;
    truncate(&path, len)
}

// ── create ────────────────────────────────────────────────────────────────

pub fn create(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_create(&h.subpath),
        FsType::Ext2 => {
            use crate::fs::fcntl::{fd_open, fd_close};
            let fd = fd_open(path, 0x241).map_err(|e| e)?;
            fd_close(fd); Ok(())
        }
        FsType::Ext4 => Err(-30),
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
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── link ────────────────────────────────────────────────────────────────

pub fn link(existing: &str, new: &str) -> Result<(), isize> {
    let h_e = mount::resolve(existing)?;
    let h_n = mount::resolve(new)?;
    if h_e.fstype != h_n.fstype { return Err(-18); }
    if h_e.is_readonly() { return Err(-30); }
    let result = match h_e.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_link(existing, new),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_link(existing, new),
        FsType::Ext2  => crate::fs::ext2::sys_link(existing, new).map(|_| ()),
        FsType::Ext4  => Err(-30),
        FsType::Overlayfs => {
            let om = overlay_mount(&h_e)?;
            crate::fs::overlayfs::link(&om, &h_e.subpath, &h_n.subpath)
        }
        _             => Err(-38),
    };
    if result.is_ok() {
        dcache::invalidate(existing);
        dcache::invalidate(new);
    }
    result
}

// ── mkdir ────────────────────────────────────────────────────────────────

pub fn mkdir(path: &str) -> Result<(), isize> {
    if is_cgroupfs_path(path) {
        let rc = crate::fs::cgroupfs::cgroupfs_mkdir(path);
        return if rc == 0 { Ok(()) } else { Err(rc) };
    }
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_mkdir(&h.subpath),
        FsType::Ext2 => crate::fs::ext2::sys_mkdir(path, 0o755).map(|_| ()),
        FsType::Ext4 => Err(-30),
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
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── rmdir ────────────────────────────────────────────────────────────────

pub fn rmdir(path: &str) -> Result<(), isize> {
    if is_cgroupfs_path(path) {
        let rc = crate::fs::cgroupfs::cgroupfs_rmdir(path);
        return if rc == 0 { Ok(()) } else { Err(rc) };
    }
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_rmdir(&h.subpath),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_rmdir(path),
        FsType::Ext2  => crate::fs::ext2::sys_rmdir(path).map(|_| ()),
        FsType::Ext4  => Err(-30),
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.rmdir(&h.subpath)
        }
        _ => Err(-1),
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── unlink ───────────────────────────────────────────────────────────────

pub fn unlink(path: &str) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_unlink(&h.subpath),
        FsType::Ext2 => crate::fs::ext2::sys_unlink(path).map(|_| ()),
        FsType::Ext4 => Err(-30),
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
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── rename ──────────────────────────────────────────────────────────────

pub fn rename(old: &str, new: &str) -> Result<(), isize> {
    let h_o = mount::resolve(old)?;
    let h_n = mount::resolve(new)?;
    if h_o.fstype != h_n.fstype { return Err(-18); }
    if h_o.is_readonly() { return Err(-30); }
    let result = match h_o.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_rename(old, new),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_rename(old, new),
        FsType::Ext2  => crate::fs::ext2::sys_rename(old, new).map(|_| ()),
        FsType::Ext4  => Err(-30),
        FsType::Overlayfs => {
            let om = overlay_mount(&h_o)?;
            crate::fs::overlayfs::rename(&om, &h_o.subpath, &h_n.subpath)
        }
        _             => Err(-38),
    };
    if result.is_ok() {
        dcache::invalidate(old);
        dcache::invalidate(new);
    }
    result
}

// ── stat / lstat ───────────────────────────────────────────────────────────

pub fn stat(path: &str) -> Result<KStat, isize> { stat_impl(path, false) }
pub fn lstat(path: &str) -> Result<KStat, isize> { stat_impl(path, true) }

fn stat_impl(path: &str, lstat: bool) -> Result<KStat, isize> {
    if is_cgroupfs_path(path) {
        return match crate::fs::cgroupfs::cgroupfs_exists(path) {
            None        => Err(-2),
            Some(is_dir) => Ok(KStat {
                mode:    if is_dir { 0o040755 } else { 0o100644 },
                nlink:   if is_dir { 2 } else { 1 },
                blksize: 4096,
                is_dir,
                ..KStat::default()
            }),
        };
    }

    if !lstat {
        if let Some(entry) = dcache::lookup(path) {
            return Ok(entry.stat);
        }
    }

    let h = mount::resolve(path)?;
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_stat(&h.subpath),
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
        FsType::Ext4 => {
            let s = if lstat {
                crate::fs::ext4::sys_lstat(path).map_err(|e| e as isize)?
            } else {
                crate::fs::ext4::sys_stat(path).map_err(|e| e as isize)?
            };
            Ok(KStat {
                ino: s.ino, mode: s.mode, nlink: s.nlink,
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
        FsType::Cgroupfs => unreachable!(),
    };

    if !lstat {
        if let Ok(ref s) = result {
            dcache::insert(path, h.fstype, s.ino, s.clone());
        }
    }
    result
}

// ── utimens ──────────────────────────────────────────────────────────────

pub fn utimens(path: &str, atime_ns: u64, mtime_ns: u64) -> Result<(), isize> {
    if is_cgroupfs_path(path) { return Ok(()); }

    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }

    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_set_times(&h.subpath, atime_ns, mtime_ns),
        FsType::Ext2 => {
            crate::fs::ext2::set_times(path, atime_ns, mtime_ns)
                .map_err(|e| e as isize)
        }
        FsType::Tmpfs => {
            crate::fs::tmpfs::tmpfs_set_times(path, atime_ns, mtime_ns)
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let mut mounts = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = mounts.get_mut(&mp).ok_or(-2isize)?;
            fs.set_mtime(&h.subpath, mtime_ns)
        }
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::copy_up_if_needed(&om, &h.subpath)?;
            let upper_path = alloc::format!("{}/{}", om.upper, h.subpath);
            crate::fs::tmpfs::tmpfs_set_times(&upper_path, atime_ns, mtime_ns)
        }
        FsType::Devfs | FsType::Procfs | FsType::Sysfs => Ok(()),
        FsType::Ext4 => Err(-30),
        FsType::Cgroupfs => Ok(()),
    };

    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── get_times ─────────────────────────────────────────────────────────────

pub fn get_times(path: &str) -> Result<(u64, u64), isize> {
    let st = stat(path)?;
    Ok((st.atime, st.mtime))
}

// ── statfs ─────────────────────────────────────────────────────────────

pub fn statfs(path: &str) -> Result<KStatfs, isize> {
    if is_cgroupfs_path(path) {
        return Ok(KStatfs {
            f_type:    FSTYPE_CGROUP2,
            f_bsize:   4096,
            f_namelen: 255,
            ..KStatfs::default()
        });
    }
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Btrfs  => Ok(crate::fs::btrfs::btrfs_statfs()),
        FsType::Tmpfs  => crate::fs::tmpfs::tmpfs_statfs(path),
        FsType::Ext2  => {
            let s = crate::fs::ext2::sys_statfs(path).map_err(|e| e as isize)?;
            Ok(KStatfs {
                f_type:    FSTYPE_EXT2,
                f_bsize:   s.f_bsize as u64,
                f_blocks:  s.f_blocks,
                f_bfree:   s.f_bfree,
                f_bavail:  s.f_bavail,
                f_namelen: s.f_namelen as u64,
            })
        }
        FsType::Ext4  => {
            let s = crate::fs::ext4::sys_statfs(path).map_err(|e| e as isize)?;
            Ok(KStatfs {
                f_type:    FSTYPE_EXT4,
                f_bsize:   s.f_bsize as u64,
                f_blocks:  s.f_blocks,
                f_bfree:   s.f_bfree,
                f_bavail:  s.f_bavail,
                f_namelen: s.f_namelen as u64,
            })
        }
        FsType::Fat32 => {
            let mp = mount_point_for(&h.subpath, path);
            let fs_map = crate::fs::fat32::FAT_MOUNTS.lock();
            let fs = fs_map.get(&mp).ok_or(-2isize)?;
            let s = fs.statfs()?;
            Ok(KStatfs {
                f_type:    FSTYPE_FAT32,
                f_bsize:   s.cluster_size as u64,
                f_blocks:  s.total_clusters,
                f_bfree:   s.free_clusters,
                f_bavail:  s.free_clusters,
                f_namelen: 255,
            })
        }
        FsType::Overlayfs => Ok(KStatfs {
            f_type:    FSTYPE_OVERLAY,
            f_bsize:   4096,
            f_namelen: 255,
            ..KStatfs::default()
        }),
        FsType::Devfs => Ok(KStatfs {
            f_type:    FSTYPE_DEVTMPFS,
            f_bsize:   4096,
            f_namelen: 255,
            ..KStatfs::default()
        }),
        FsType::Procfs => Ok(KStatfs {
            f_type:    FSTYPE_PROC,
            f_bsize:   4096,
            f_namelen: 255,
            ..KStatfs::default()
        }),
        FsType::Sysfs => Ok(KStatfs {
            f_type:    FSTYPE_SYSFS,
            f_bsize:   4096,
            f_namelen: 255,
            ..KStatfs::default()
        }),
        FsType::Cgroupfs => Ok(KStatfs {
            f_type:    FSTYPE_CGROUP2,
            f_bsize:   4096,
            f_namelen: 255,
            ..KStatfs::default()
        }),
    }
}

// ── readdir ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name:   String,
    pub ino:    u64,
    pub is_dir: bool,
    pub mode:   u16,
    pub size:   u64,
}

pub fn readdir(path: &str) -> Result<Vec<DirEntry>, isize> {
    if is_cgroupfs_path(path) {
        return match crate::fs::cgroupfs::cgroupfs_list_dir_by_path(path) {
            None => Err(-20),
            Some(entries) => Ok(entries.into_iter().map(|e| DirEntry {
                name:   e.name,
                ino:    0,
                is_dir: e.is_dir,
                mode:   if e.is_dir { 0o040755 } else { 0o100644 },
                size:   0,
            }).collect()),
        };
    }
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_readdir(&h.subpath),
        FsType::Ext2 => {
            let entries = crate::fs::ext2::readdir(path).map_err(|e| e as isize)?;
            Ok(entries.into_iter().map(|e| DirEntry {
                name: e.name, ino: e.ino as u64,
                is_dir: e.is_dir, mode: e.mode, size: e.size,
            }).collect())
        }
        FsType::Ext4 => {
            let entries = crate::fs::ext4::readdir(path).map_err(|e| e as isize)?;
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
        FsType::Cgroupfs => unreachable!(),
    }
}

// ── symlink / readlink ─────────────────────────────────────────────────────

pub fn symlink(target: &str, link_path: &str) -> Result<(), isize> {
    let h = mount::resolve(link_path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_symlink(target, link_path),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_symlink(target, link_path),
        FsType::Ext2  => crate::fs::ext2::sys_symlink(target, link_path).map(|_| ()),
        FsType::Ext4  => Err(-30),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::symlink(&om, target, &h.subpath)
        }
        FsType::Fat32 => Err(-1),
        _             => Err(-38),
    };
    if result.is_ok() { dcache::invalidate(link_path); }
    result
}

pub fn readlink(path: &str) -> Result<String, isize> {
    let h = mount::resolve(path)?;
    match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_readlink(&h.subpath),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_readlink(path),
        FsType::Ext2  => crate::fs::ext2::sys_readlink(path).map_err(|e| e as isize),
        FsType::Ext4  => crate::fs::ext4::sys_readlink(path).map_err(|e| e as isize),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::readlink(&om, &h.subpath)
        }
        FsType::Fat32 => Err(-22),
        _             => Err(-22),
    }
}

// ── chmod / chown ──────────────────────────────────────────────────────────

pub fn chmod(path: &str, mode: u16) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_chmod(&h.subpath, mode),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_chmod(path, mode),
        FsType::Ext2  => crate::fs::ext2::sys_chmod(path, mode).map(|_| ()),
        FsType::Ext4  => Err(-30),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::copy_up_if_needed(&om, &h.subpath)?;
            crate::fs::overlayfs::chmod(&om, &h.subpath, mode)
        }
        FsType::Fat32 => Err(-1),
        _             => Err(-38),
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

pub fn chown(path: &str, uid: u32, gid: u32) -> Result<(), isize> {
    let h = mount::resolve(path)?;
    if h.is_readonly() { return Err(-30); }
    let result = match h.fstype {
        FsType::Btrfs => crate::fs::btrfs::btrfs_chown(&h.subpath, uid, gid),
        FsType::Tmpfs => crate::fs::tmpfs::tmpfs_chown(path, uid, gid),
        FsType::Ext2  => crate::fs::ext2::sys_chown(path, uid, gid).map(|_| ()),
        FsType::Ext4  => Err(-30),
        FsType::Overlayfs => {
            let om = overlay_mount(&h)?;
            crate::fs::overlayfs::copy_up_if_needed(&om, &h.subpath)?;
            crate::fs::overlayfs::chown(&om, &h.subpath, uid, gid)
        }
        FsType::Fat32 => Err(-1),
        _             => Err(-38),
    };
    if result.is_ok() { dcache::invalidate(path); }
    result
}

// ── open (VFS-level) ────────────────────────────────────────────────────────

pub fn open(path: &str, flags: u32) -> Result<usize, isize> {
    crate::fs::vfs::open_raw(path, flags)
}

pub fn fd_path(fd: usize) -> Option<String> {
    crate::fs::fcntl::fd_get_path(fd)
}

pub fn file_size(fd: usize) -> usize {
    crate::fs::fcntl::fd_size(fd).unwrap_or(0)
}

// ── mount / overlay helpers ───────────────────────────────────────────────────────

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

pub fn tmpfs_mount(mount_point: &str, size_limit: usize) {
    crate::fs::tmpfs::tmpfs_mount(mount_point, size_limit);
}

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
    if let Some(num_str) = s.strip_suffix('%') {
        let pct: usize = num_str.trim().parse().ok()?;
        let total = crate::mm::pmm::total_pages() * 4096;
        return Some((total / 100) * pct);
    }
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
