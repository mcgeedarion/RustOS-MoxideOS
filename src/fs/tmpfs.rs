//! tmpfs — RAM-backed filesystem with per-mount size accounting.
//!
//! ## Differences from ramfs
//! | Feature              | ramfs                | tmpfs                         |
//! |----------------------|----------------------|-------------------------------|
//! | Size limit           | None (OOM kills)     | Enforced; default 50% of RAM  |
//! | statfs support       | Stub zeros           | Accurate f_blocks/f_bfree     |
//! | Per-mount isolation  | Shared global table  | Per-mount BTreeMap            |
//! | swap backing         | No                   | Stub (no swap yet)            |
//!
//! ## Mount lifecycle
//! ```text
//! init_mounts()  →  vfs_ops::tmpfs_mount("/tmp", 0)   // 0 = default (50% RAM)
//!                →  tmpfs::tmpfs_mount("/tmp", 0)
//!                →  TmpfsMount::new(size_limit)
//! ```
//!
//! ## Public API (mirrors ramfs::tmpfs_* surface consumed by vfs_ops)
//! - tmpfs_mount(mount_point, size_limit)
//! - tmpfs_read_all / tmpfs_write_all
//! - tmpfs_pread / tmpfs_pwrite
//! - tmpfs_truncate
//! - tmpfs_create / tmpfs_mkdir / tmpfs_rmdir / tmpfs_unlink
//! - tmpfs_link / tmpfs_rename
//! - tmpfs_symlink / tmpfs_readlink
//! - tmpfs_stat / tmpfs_readdir
//! - tmpfs_chmod / tmpfs_chown
//! - tmpfs_statfs

extern crate alloc;
use crate::fs::vfs_ops::{DirEntry, KStat, KStatfs};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;

pub const TMPFS_MAGIC: u64 = 0x0102_1994;

enum TmpfsKind {
    Regular { data: Vec<u8> },
    Dir { children: BTreeMap<String, u64> }, // name → ino
    Symlink { target: String },
}

struct TmpfsNode {
    ino: u64,
    mode: u16,
    uid: u32,
    gid: u32,
    atime: u64,
    mtime: u64,
    ctime: u64,
    nlink: u32,
    kind: TmpfsKind,
}

impl TmpfsNode {
    fn data_len(&self) -> usize {
        match &self.kind {
            TmpfsKind::Regular { data } => data.len(),
            TmpfsKind::Symlink { target } => target.len(),
            TmpfsKind::Dir { .. } => 0,
        }
    }
    fn is_dir(&self) -> bool {
        matches!(self.kind, TmpfsKind::Dir { .. })
    }
    fn is_symlink(&self) -> bool {
        matches!(self.kind, TmpfsKind::Symlink { .. })
    }
}

struct TmpfsMount {
    size_limit: usize, // bytes; 0 = unlimited
    used_bytes: usize,
    next_ino: u64,
    inodes: BTreeMap<u64, TmpfsNode>, // ino → node
    paths: BTreeMap<String, u64>,     // abs-path → ino
}

impl TmpfsMount {
    fn new(size_limit: usize) -> Self {
        let limit = if size_limit == 0 {
            // Default: 50 % of physical RAM.
            crate::mm::pmm::total_pages() * 4096 / 2
        } else {
            size_limit
        };
        let mut m = Self {
            size_limit: limit,
            used_bytes: 0,
            next_ino: 2, // 1 is reserved for the root inode
            inodes: BTreeMap::new(),
            paths: BTreeMap::new(),
        };
        // Root directory inode (ino=1).
        let root = TmpfsNode {
            ino: 1,
            mode: 0o40755,
            uid: 0,
            gid: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            nlink: 2,
            kind: TmpfsKind::Dir {
                children: BTreeMap::new(),
            },
        };
        m.inodes.insert(1, root);
        m.paths.insert("/".to_string(), 1);
        m
    }

    fn alloc_ino(&mut self) -> u64 {
        let i = self.next_ino;
        self.next_ino += 1;
        i
    }

    /// Check whether `extra` bytes can be allocated without breaching the
    /// limit.
    fn can_alloc(&self, extra: usize) -> bool {
        self.size_limit == 0 || (self.used_bytes + extra <= self.size_limit)
    }

    /// Look up ino for an absolute path; returns ENOENT on miss.
    fn lookup(&self, path: &str) -> Result<u64, isize> {
        self.paths.get(path).copied().ok_or(-2)
    }

    /// Split a path into (parent_path, file_name).
    fn split(path: &str) -> (&str, &str) {
        match path.rfind('/') {
            Some(0) | None => ("/", path.trim_start_matches('/')),
            Some(i) => (&path[..i], &path[i + 1..]),
        }
    }
}

static MOUNTS: Mutex<BTreeMap<String, TmpfsMount>> = Mutex::new(BTreeMap::new());

/// Register a new tmpfs instance at `mount_point`.
/// `size_limit` = 0 means 50 % of physical RAM.
pub fn tmpfs_mount(mount_point: &str, size_limit: usize) {
    let mut map = MOUNTS.lock();
    map.entry(mount_point.to_string())
        .or_insert_with(|| TmpfsMount::new(size_limit));
    crate::serial_println!(
        "tmpfs: mounted {} (limit={} bytes)",
        mount_point,
        if size_limit == 0 {
            crate::mm::pmm::total_pages() * 4096 / 2
        } else {
            size_limit
        }
    );
}

/// Find the longest-prefix mount that owns `path`.
/// Returns (mount_point, subpath_within_mount).
fn resolve_mount<'a>(
    map: &'a BTreeMap<String, TmpfsMount>,
    path: &str,
) -> Option<(&'a str, String)> {
    let mut best: Option<(&str, String)> = None;
    let mut best_len = 0usize;
    for mp in map.keys() {
        let mp_s = mp.as_str();
        let matches = if mp_s == "/" {
            path.starts_with('/')
        } else {
            path.starts_with(mp_s)
                && (path.len() == mp_s.len() || path.as_bytes().get(mp_s.len()) == Some(&b'/'))
        };
        if matches && mp_s.len() >= best_len {
            best_len = mp_s.len();
            let rel = if mp_s == "/" {
                path.to_string()
            } else if path.len() == mp_s.len() {
                "/".to_string()
            } else {
                path[mp_s.len()..].to_string()
            };
            let sub = if rel.starts_with('/') {
                rel
            } else {
                format!("/",)
            };
            best = Some((mp_s, sub));
        }
    }
    best
}

/// Same as resolve_mount but for &mut access.
fn resolve_mp(path: &str) -> Option<String> {
    let map = MOUNTS.lock();
    let mut best_len = 0usize;
    let mut best_mp: Option<String> = None;
    for mp in map.keys() {
        let mp_s = mp.as_str();
        let matches = if mp_s == "/" {
            path.starts_with('/')
        } else {
            path.starts_with(mp_s)
                && (path.len() == mp_s.len() || path.as_bytes().get(mp_s.len()) == Some(&b'/'))
        };
        if matches && mp_s.len() >= best_len {
            best_len = mp_s.len();
            best_mp = Some(mp.clone());
        }
    }
    best_mp
}

/// Compute the path relative to a mount-point (always starts with '/').
fn subpath(mount_point: &str, full_path: &str) -> String {
    if mount_point == "/" {
        full_path.to_string()
    } else if full_path.len() == mount_point.len() {
        "/".to_string()
    } else {
        full_path[mount_point.len()..].to_string()
    }
}

pub fn tmpfs_read_all(path: &str) -> Result<Vec<u8>, isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let map = MOUNTS.lock();
    let fs = map.get(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    match &node.kind {
        TmpfsKind::Regular { data } => Ok(data.clone()),
        _ => Err(-21), // EISDIR
    }
}

pub fn tmpfs_write_all(path: &str, data: &[u8]) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;

    let ino = match fs.lookup(&sub) {
        Ok(i) => i,
        Err(_) => {
            // Auto-create file (matches ramfs behaviour).
            drop_and_create(fs, &sub, data)?;
            return Ok(());
        },
    };
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    match &mut node.kind {
        TmpfsKind::Regular { data: old } => {
            let delta = data.len().saturating_sub(old.len());
            if delta > 0 && !fs.can_alloc(delta) {
                return Err(-28);
            } // ENOSPC
            fs.used_bytes = fs.used_bytes.saturating_sub(old.len());
            *old = data.to_vec();
            fs.used_bytes += data.len();
            Ok(())
        },
        _ => Err(-21),
    }
}

/// Helper: create a new regular file with given content, also linking it
/// into the parent directory and the path index.
fn drop_and_create(fs: &mut TmpfsMount, sub: &str, data: &[u8]) -> Result<u64, isize> {
    if !fs.can_alloc(data.len()) {
        return Err(-28);
    }
    let (par_path, name) = TmpfsMount::split(sub);
    if name.is_empty() {
        return Err(-22);
    } // EINVAL
    let par_ino = fs.paths.get(par_path).copied().ok_or(-2isize)?;
    let ino = fs.alloc_ino();
    let node = TmpfsNode {
        ino,
        mode: 0o100644,
        uid: 0,
        gid: 0,
        atime: 0,
        mtime: 0,
        ctime: 0,
        nlink: 1,
        kind: TmpfsKind::Regular {
            data: data.to_vec(),
        },
    };
    fs.inodes.insert(ino, node);
    fs.paths.insert(sub.to_string(), ino);
    fs.used_bytes += data.len();
    // Add to parent directory.
    if let Some(par) = fs.inodes.get_mut(&par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.insert(name.to_string(), ino);
        }
    }
    Ok(ino)
}

pub fn tmpfs_pread(path: &str, offset: usize, len: usize) -> Result<Vec<u8>, isize> {
    let data = tmpfs_read_all(path)?;
    if offset >= data.len() {
        return Ok(Vec::new());
    }
    let end = (offset + len).min(data.len());
    Ok(data[offset..end].to_vec())
}

pub fn tmpfs_pwrite(path: &str, offset: usize, new: &[u8]) -> Result<usize, isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    match &mut node.kind {
        TmpfsKind::Regular { data } => {
            let end = offset + new.len();
            if end > data.len() {
                let extra = end - data.len();
                if !fs.can_alloc(extra) {
                    return Err(-28);
                }
                data.resize(end, 0);
                fs.used_bytes += extra;
            }
            data[offset..end].copy_from_slice(new);
            Ok(new.len())
        },
        _ => Err(-21),
    }
}

pub fn tmpfs_truncate(path: &str, len: usize) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    match &mut node.kind {
        TmpfsKind::Regular { data } => {
            if len > data.len() {
                let extra = len - data.len();
                if !fs.can_alloc(extra) {
                    return Err(-28);
                }
                fs.used_bytes += extra;
            } else {
                fs.used_bytes = fs.used_bytes.saturating_sub(data.len() - len);
            }
            data.resize(len, 0);
            Ok(())
        },
        _ => Err(-21),
    }
}

pub fn tmpfs_create(path: &str) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    if fs.lookup(&sub).is_ok() {
        return Ok(());
    } // already exists
    drop_and_create(fs, &sub, &[]).map(|_| ())
}

pub fn tmpfs_mkdir(path: &str) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    if fs.lookup(&sub).is_ok() {
        return Err(-17);
    } // EEXIST
    let (par_path, name) = TmpfsMount::split(&sub);
    if name.is_empty() {
        return Err(-22);
    }
    let par_ino = fs.paths.get(par_path).copied().ok_or(-2isize)?;
    let ino = fs.alloc_ino();
    let node = TmpfsNode {
        ino,
        mode: 0o40755,
        uid: 0,
        gid: 0,
        atime: 0,
        mtime: 0,
        ctime: 0,
        nlink: 2,
        kind: TmpfsKind::Dir {
            children: BTreeMap::new(),
        },
    };
    fs.inodes.insert(ino, node);
    fs.paths.insert(sub.to_string(), ino);
    if let Some(par) = fs.inodes.get_mut(&par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.insert(name.to_string(), ino);
        }
    }
    Ok(())
}

pub fn tmpfs_rmdir(path: &str) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    if !node.is_dir() {
        return Err(-20);
    } // ENOTDIR
    if let TmpfsKind::Dir { children } = &node.kind {
        if !children.is_empty() {
            return Err(-39);
        } // ENOTEMPTY
    }
    let (par_path, name) = TmpfsMount::split(&sub);
    let par_ino = fs.paths.get(par_path).copied().ok_or(-2isize)?;
    fs.inodes.remove(&ino);
    fs.paths.remove(&sub.to_string());
    if let Some(par) = fs.inodes.get_mut(&par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.remove(name);
        }
    }
    Ok(())
}

pub fn tmpfs_unlink(path: &str) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    if node.is_dir() {
        return Err(-21);
    } // EISDIR
    let freed = node.data_len();
    let nlink = node.nlink;
    drop(node);
    let (par_path, name) = TmpfsMount::split(&sub);
    let par_ino = fs.paths.get(par_path).copied().ok_or(-2isize)?;
    fs.paths.remove(&sub.to_string());
    // Decrement nlink; remove inode only when nlink reaches 0.
    if let Some(node) = fs.inodes.get_mut(&ino) {
        node.nlink = nlink.saturating_sub(1);
        if node.nlink == 0 {
            fs.inodes.remove(&ino);
            fs.used_bytes = fs.used_bytes.saturating_sub(freed);
        }
    }
    if let Some(par) = fs.inodes.get_mut(&par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.remove(name);
        }
    }
    Ok(())
}

pub fn tmpfs_link(existing: &str, new: &str) -> Result<(), isize> {
    let mp = resolve_mp(existing).ok_or(-2isize)?;
    let sub_e = subpath(&mp, existing);
    let sub_n = subpath(&mp, new);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub_e)?;
    if fs.lookup(&sub_n).is_ok() {
        return Err(-17);
    } // EEXIST
    let (par_path, name) = TmpfsMount::split(&sub_n);
    let par_ino = fs.paths.get(par_path).copied().ok_or(-2isize)?;
    fs.paths.insert(sub_n.to_string(), ino);
    if let Some(node) = fs.inodes.get_mut(&ino) {
        node.nlink += 1;
    }
    if let Some(par) = fs.inodes.get_mut(&par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.insert(name.to_string(), ino);
        }
    }
    Ok(())
}

pub fn tmpfs_rename(old: &str, new: &str) -> Result<(), isize> {
    let mp = resolve_mp(old).ok_or(-2isize)?;
    let sub_o = subpath(&mp, old);
    let sub_n = subpath(&mp, new);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub_o)?;
    // Remove old directory entry.
    let (old_par_path, old_name) = TmpfsMount::split(&sub_o);
    let old_par_ino = fs.paths.get(old_par_path).copied().ok_or(-2isize)?;
    fs.paths.remove(&sub_o.to_string());
    if let Some(par) = fs.inodes.get_mut(&old_par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.remove(old_name);
        }
    }
    // If new already exists (and is a regular file), unlink it first.
    if let Ok(victim) = fs.lookup(&sub_n) {
        let freed = fs.inodes.get(&victim).map(|n| n.data_len()).unwrap_or(0);
        fs.inodes.remove(&victim);
        fs.paths.remove(&sub_n.to_string());
        fs.used_bytes = fs.used_bytes.saturating_sub(freed);
        let (np, nn) = TmpfsMount::split(&sub_n);
        let np_ino = fs.paths.get(np).copied().unwrap_or(0);
        if let Some(par) = fs.inodes.get_mut(&np_ino) {
            if let TmpfsKind::Dir { children } = &mut par.kind {
                children.remove(nn);
            }
        }
    }
    // Insert new path.
    let (new_par_path, new_name) = TmpfsMount::split(&sub_n);
    let new_par_ino = fs.paths.get(new_par_path).copied().ok_or(-2isize)?;
    fs.paths.insert(sub_n.to_string(), ino);
    if let Some(par) = fs.inodes.get_mut(&new_par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.insert(new_name.to_string(), ino);
        }
    }
    Ok(())
}

pub fn tmpfs_symlink(target: &str, link_path: &str) -> Result<(), isize> {
    let mp = resolve_mp(link_path).ok_or(-2isize)?;
    let sub = subpath(&mp, link_path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    if fs.lookup(&sub).is_ok() {
        return Err(-17);
    }
    let (par_path, name) = TmpfsMount::split(&sub);
    let par_ino = fs.paths.get(par_path).copied().ok_or(-2isize)?;
    if !fs.can_alloc(target.len()) {
        return Err(-28);
    }
    let ino = fs.alloc_ino();
    let node = TmpfsNode {
        ino,
        mode: 0o120777,
        uid: 0,
        gid: 0,
        atime: 0,
        mtime: 0,
        ctime: 0,
        nlink: 1,
        kind: TmpfsKind::Symlink {
            target: target.to_string(),
        },
    };
    fs.used_bytes += target.len();
    fs.inodes.insert(ino, node);
    fs.paths.insert(sub.to_string(), ino);
    if let Some(par) = fs.inodes.get_mut(&par_ino) {
        if let TmpfsKind::Dir { children } = &mut par.kind {
            children.insert(name.to_string(), ino);
        }
    }
    Ok(())
}

pub fn tmpfs_readlink(path: &str) -> Result<String, isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let map = MOUNTS.lock();
    let fs = map.get(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    match &node.kind {
        TmpfsKind::Symlink { target } => Ok(target.clone()),
        _ => Err(-22), // EINVAL
    }
}

pub fn tmpfs_stat(path: &str) -> Result<KStat, isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let map = MOUNTS.lock();
    let fs = map.get(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    let size = node.data_len() as u64;
    Ok(KStat {
        ino,
        mode: node.mode,
        nlink: node.nlink,
        uid: node.uid,
        gid: node.gid,
        size,
        atime: node.atime,
        mtime: node.mtime,
        ctime: node.ctime,
        blksize: 4096,
        blocks: size.div_ceil(512),
        is_dir: node.is_dir(),
    })
}

pub fn tmpfs_readdir(path: &str) -> Result<Vec<DirEntry>, isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let map = MOUNTS.lock();
    let fs = map.get(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    match &node.kind {
        TmpfsKind::Dir { children } => {
            let mut out = Vec::new();
            for (name, child_ino) in children {
                if let Some(cn) = fs.inodes.get(child_ino) {
                    out.push(DirEntry {
                        name: name.clone(),
                        ino: cn.ino,
                        is_dir: cn.is_dir(),
                        mode: cn.mode,
                        size: cn.data_len() as u64,
                    });
                }
            }
            Ok(out)
        },
        _ => Err(-20), // ENOTDIR
    }
}

pub fn tmpfs_chmod(path: &str, mode: u16) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    if let Some(node) = fs.inodes.get_mut(&ino) {
        // Preserve file-type bits, replace permission bits.
        node.mode = (node.mode & 0o170000) | (mode & 0o7777);
    }
    Ok(())
}

pub fn tmpfs_chown(path: &str, uid: u32, gid: u32) -> Result<(), isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let sub = subpath(&mp, path);
    let mut map = MOUNTS.lock();
    let fs = map.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.lookup(&sub)?;
    if let Some(node) = fs.inodes.get_mut(&ino) {
        node.uid = uid;
        node.gid = gid;
    }
    Ok(())
}

/// Return filesystem statistics for a path on a tmpfs mount.
/// Called by sys_statfs / sys_fstatfs via vfs_ops::statfs().
pub fn tmpfs_statfs(path: &str) -> Result<KStatfs, isize> {
    let mp = resolve_mp(path).ok_or(-2isize)?;
    let map = MOUNTS.lock();
    let fs = map.get(&mp).ok_or(-2isize)?;
    let limit = fs.size_limit;
    let used = fs.used_bytes;
    let (blocks, bfree, bavail) = if limit == 0 {
        (0, 0, 0)
    } else {
        let total = (limit + 4095) / 4096;
        let used_b = (used + 4095) / 4096;
        let free = total.saturating_sub(used_b);
        (total as u64, free as u64, free as u64)
    };
    Ok(KStatfs {
        f_type: TMPFS_MAGIC,
        f_bsize: 4096,
        f_blocks: blocks,
        f_bfree: bfree,
        f_bavail: bavail,
        f_namelen: 255,
    })
}

struct TmpSchemeFd {
    path: String,
    offset: usize,
    readable: bool,
    writable: bool,
}

static TMP_SCHEME_FDS: Mutex<BTreeMap<u64, TmpSchemeFd>> = Mutex::new(BTreeMap::new());
static TMP_SCHEME_NEXT_FID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Scheme adapter for `tmp:<path>` URLs.
pub struct TmpFs;

impl TmpFs {
    pub const fn new() -> Self {
        Self
    }
}

fn tmp_scheme_path(path: &str) -> String {
    let p = path.trim_start_matches('/');
    if p.is_empty() {
        String::from("/tmp")
    } else if p == "tmp" || p.starts_with("tmp/") {
        format!("/{}", p)
    } else {
        format!("/tmp/{}", p)
    }
}

fn tmp_scheme_error(errno: isize) -> scheme_api::SchemeError {
    match errno {
        -2 => scheme_api::SchemeError::NotFound,
        -13 => scheme_api::SchemeError::PermissionDenied,
        -22 => scheme_api::SchemeError::InvalidArg,
        -11 => scheme_api::SchemeError::WouldBlock,
        _ => scheme_api::SchemeError::Io,
    }
}

fn tmp_scheme_access(flags: scheme_api::OpenFlags) -> (bool, bool) {
    let write = flags.intersects(
        scheme_api::OpenFlags::WRITE
            | scheme_api::OpenFlags::CREATE
            | scheme_api::OpenFlags::TRUNCATE
            | scheme_api::OpenFlags::APPEND,
    );
    let read = flags.contains(scheme_api::OpenFlags::READ) || !write;
    (read, write)
}

impl crate::fs::scheme_table::Scheme for TmpFs {
    fn open(
        &self,
        path: &str,
        flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        let full_path = tmp_scheme_path(path);
        let (readable, writable) = tmp_scheme_access(flags);

        match tmpfs_stat(&full_path) {
            Ok(st) => {
                if st.is_dir && !flags.contains(scheme_api::OpenFlags::DIRECTORY) {
                    return Err(scheme_api::SchemeError::InvalidArg);
                }
            },
            Err(-2) if flags.contains(scheme_api::OpenFlags::CREATE) => {
                tmpfs_create(&full_path).map_err(tmp_scheme_error)?;
            },
            Err(e) => return Err(tmp_scheme_error(e)),
        }

        if flags.contains(scheme_api::OpenFlags::TRUNCATE) {
            tmpfs_truncate(&full_path, 0).map_err(tmp_scheme_error)?;
        }

        let offset = if flags.contains(scheme_api::OpenFlags::APPEND) {
            tmpfs_stat(&full_path)
                .map(|st| st.size as usize)
                .unwrap_or(0)
        } else {
            0
        };
        let fid = TMP_SCHEME_NEXT_FID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        TMP_SCHEME_FDS.lock().insert(
            fid,
            TmpSchemeFd {
                path: full_path,
                offset,
                readable,
                writable,
            },
        );
        Ok(scheme_api::SchemeFileId(fid))
    }

    fn read(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &mut [u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let (path, offset, readable) = {
            let fds = TMP_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(scheme_api::SchemeError::NotFound)?;
            (fd.path.clone(), fd.offset, fd.readable)
        };
        if !readable {
            return Err(scheme_api::SchemeError::PermissionDenied);
        }
        let data = tmpfs_pread(&path, offset, buf.len()).map_err(tmp_scheme_error)?;
        let n = data.len();
        buf[..n].copy_from_slice(&data);
        if n > 0 {
            if let Some(fd) = TMP_SCHEME_FDS.lock().get_mut(&fid.0) {
                fd.offset = fd.offset.saturating_add(n);
            }
        }
        Ok(n)
    }

    fn write(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &[u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let (path, offset, writable) = {
            let fds = TMP_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(scheme_api::SchemeError::NotFound)?;
            (fd.path.clone(), fd.offset, fd.writable)
        };
        if !writable {
            return Err(scheme_api::SchemeError::PermissionDenied);
        }
        let n = tmpfs_pwrite(&path, offset, buf).map_err(tmp_scheme_error)?;
        if n > 0 {
            if let Some(fd) = TMP_SCHEME_FDS.lock().get_mut(&fid.0) {
                fd.offset = fd.offset.saturating_add(n);
            }
        }
        Ok(n)
    }

    fn seek(
        &self,
        fid: scheme_api::SchemeFileId,
        offset: i64,
        whence: u8,
    ) -> Result<u64, scheme_api::SchemeError> {
        let mut fds = TMP_SCHEME_FDS.lock();
        let fd = fds
            .get_mut(&fid.0)
            .ok_or(scheme_api::SchemeError::NotFound)?;
        let size = tmpfs_stat(&fd.path).map_err(tmp_scheme_error)?.size as i64;
        let base = match whence {
            0 => 0,
            1 => fd.offset as i64,
            2 => size,
            _ => return Err(scheme_api::SchemeError::InvalidArg),
        };
        let next = base
            .checked_add(offset)
            .ok_or(scheme_api::SchemeError::InvalidArg)?;
        if next < 0 {
            return Err(scheme_api::SchemeError::InvalidArg);
        }
        fd.offset = next as usize;
        Ok(fd.offset as u64)
    }

    fn close(&self, fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        TMP_SCHEME_FDS.lock().remove(&fid.0);
        Ok(())
    }
}
