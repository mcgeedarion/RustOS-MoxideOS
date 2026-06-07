//! tmpfs / ramfs — fully in-memory filesystem.
//!
//! Suitable for mounting at /tmp, /run, /dev/shm, etc.
//!
//! ## Design
//!
//! Each tmpfs instance is a `TmpFs` struct containing:
//!   - a `BTreeMap<u64, INode>` — all inodes keyed by inode number
//!   - a `BTreeMap<String, u64>` — path → inode mapping
//!   - a size limit and used-byte counter
//!
//! Multiple instances can co-exist (e.g. /tmp and /dev/shm are separate).
//! The global `TMPFS_INSTANCES` map owns all of them keyed by mount-point.
//!
//! ## Supported operations
//!
//!   create, read_all, write_all, pread, pwrite, truncate, stat, readdir,
//!   mkdir, rmdir, unlink, rename, link, symlink, readlink, chmod, chown,
//!   statfs, O_TMPFILE anonymous inodes (tmpfs_create_anon).

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

use spin::Mutex;

pub(crate) enum INodeData {
    File(Vec<u8>),
    Dir(BTreeMap<String, u64>),
    Symlink(String),
}

pub(crate) struct INode {
    pub ino: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub data: INodeData,
}

impl INode {
    pub fn new_file(ino: u64) -> Self {
        INode {
            ino,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            nlink: 1,
            atime: 0,
            mtime: 0,
            ctime: 0,
            data: INodeData::File(Vec::new()),
        }
    }
    pub fn new_dir(ino: u64) -> Self {
        INode {
            ino,
            mode: 0o040755,
            uid: 0,
            gid: 0,
            nlink: 2,
            atime: 0,
            mtime: 0,
            ctime: 0,
            data: INodeData::Dir(BTreeMap::new()),
        }
    }
    pub fn new_symlink(ino: u64, target: &str) -> Self {
        INode {
            ino,
            mode: 0o120777,
            uid: 0,
            gid: 0,
            nlink: 1,
            atime: 0,
            mtime: 0,
            ctime: 0,
            data: INodeData::Symlink(target.to_string()),
        }
    }
    pub fn file_size(&self) -> usize {
        match &self.data {
            INodeData::File(v) => v.len(),
            INodeData::Symlink(s) => s.len(),
            INodeData::Dir(_) => 0,
        }
    }
    pub fn is_dir(&self) -> bool {
        matches!(&self.data, INodeData::Dir(_))
    }
}

pub struct TmpFsStatfs {
    pub f_type: u64, // always TMPFS_MAGIC
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_namelen: u64,
}

/// Linux TMPFS_MAGIC
pub const TMPFS_MAGIC: u64 = 0x0102_1994;

pub(crate) struct TmpFs {
    pub inodes: BTreeMap<u64, INode>,
    pub paths: BTreeMap<String, u64>,
    pub next_ino: u64,
    pub limit: usize,
    pub used: usize,
}

impl TmpFs {
    fn new(limit: usize) -> Self {
        let mut fs = TmpFs {
            inodes: BTreeMap::new(),
            paths: BTreeMap::new(),
            next_ino: 2,
            limit,
            used: 0,
        };
        // root directory = inode 1
        let root = INode::new_dir(1);
        fs.inodes.insert(1, root);
        fs.paths.insert("/".to_string(), 1);
        fs
    }

    pub fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    pub fn statfs(&self) -> TmpFsStatfs {
        let bsize: u64 = 4096;
        let total_blocks = (self.limit as u64).div_ceil(bsize);
        let used_blocks = (self.used as u64).div_ceil(bsize);
        TmpFsStatfs {
            f_type: TMPFS_MAGIC,
            f_bsize: bsize,
            f_blocks: total_blocks,
            f_bfree: total_blocks.saturating_sub(used_blocks),
            f_bavail: total_blocks.saturating_sub(used_blocks),
            f_namelen: 255,
        }
    }

    /// Resolve a path relative to the mount root to an inode number.
    /// `path` should be the full absolute path (e.g. "/tmp/foo");
    /// the mount root is stripped to get the in-fs relative path.
    fn resolve(&self, mount_point: &str, full_path: &str) -> Option<u64> {
        let rel = strip_mount_prefix(mount_point, full_path);
        self.paths
            .get(rel)
            .copied()
            .or_else(|| self.paths.get(&alloc::format!("{}/", rel)).copied())
    }
}

pub(crate) static TMPFS_INSTANCES: Mutex<BTreeMap<String, TmpFs>> = Mutex::new(BTreeMap::new());

/// Mount a new tmpfs instance at `mount_point` with the given byte limit.
/// If a mount already exists at this point it is replaced.
pub fn tmpfs_mount(mount_point: &str, limit: usize) {
    let mut tbl = TMPFS_INSTANCES.lock();
    let mp = normalise_mp(mount_point);
    tbl.insert(mp, TmpFs::new(limit));
}

/// Ensure at least one tmpfs exists (lazy default at root for tests).
fn ensure_defaults() {
    let mut tbl = TMPFS_INSTANCES.lock();
    if tbl.is_empty() {
        tbl.insert("/".to_string(), TmpFs::new(64 * 1024 * 1024));
    }
}

fn normalise_mp(mp: &str) -> String {
    if mp.is_empty() {
        return "/".to_string();
    }
    let s = mp.trim_end_matches('/');
    if s.is_empty() {
        "/".to_string()
    } else {
        s.to_string()
    }
}

/// Strip the mount-point prefix from a full path, returning the
/// in-filesystem relative path (always starts with '/').
fn strip_mount_prefix<'a>(mount_point: &str, full_path: &'a str) -> &'a str {
    let mp = mount_point.trim_end_matches('/');
    if mp.is_empty() {
        return full_path;
    }
    if full_path == mp {
        return "/";
    }
    if let Some(rel) = full_path.strip_prefix(mp) {
        if rel.starts_with('/') {
            return rel;
        }
    }
    full_path
}

/// Find the best (longest-prefix) TmpFs mount for a given full path.
/// Returns (mount_point_key, in-fs_relative_path) or None.
fn best_mount<'a>(tbl: &'a BTreeMap<String, TmpFs>, full_path: &str) -> Option<(&'a str, String)> {
    let mut best_len = 0usize;
    let mut best_mp: Option<&str> = None;
    for mp in tbl.keys() {
        let ms = mp.trim_end_matches('/');
        if (full_path == ms || full_path.starts_with(&alloc::format!("{}/", ms)) || ms.is_empty())
            && ms.len() >= best_len
        {
            best_len = ms.len();
            best_mp = Some(mp.as_str());
        }
    }
    let mp = best_mp?;
    let rel = strip_mount_prefix(mp, full_path).to_string();
    Some((mp, rel))
}

/// Parent path of a relative-within-fs path (e.g. "/foo/bar" → "/foo").
fn parent_path(rel: &str) -> &str {
    let trimmed = rel.trim_end_matches('/');
    if let Some(pos) = trimmed.rfind('/') {
        if pos == 0 {
            "/"
        } else {
            &trimmed[..pos]
        }
    } else {
        "/"
    }
}

/// Basename component of a relative-within-fs path.
fn basename(rel: &str) -> &str {
    let trimmed = rel.trim_end_matches('/');
    if let Some(pos) = trimmed.rfind('/') {
        &trimmed[pos + 1..]
    } else {
        trimmed
    }
}

pub fn tmpfs_create(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    if fs.paths.contains_key(&rel) {
        return Err(-17);
    } // EEXIST

    let parent = parent_path(&rel).to_string();
    let name = basename(&rel).to_string();
    if !fs.paths.contains_key(&parent) {
        return Err(-2);
    } // ENOENT

    let ino = fs.alloc_ino();
    let node = INode::new_file(ino);
    fs.inodes.insert(ino, node);
    fs.paths.insert(rel, ino);

    // Add directory entry.
    let parent_ino = *fs.paths.get(&parent).unwrap();
    if let Some(p) = fs.inodes.get_mut(&parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.insert(name, ino);
        }
    }
    Ok(())
}

pub fn tmpfs_read_all(full_path: &str) -> Result<Vec<u8>, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let fs = tbl.get(mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    match &node.data {
        INodeData::File(v) => Ok(v.clone()),
        _ => Err(-22),
    }
}

pub fn tmpfs_write_all(full_path: &str, data: &[u8]) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    // Create if missing.
    if !fs.paths.contains_key(&rel) {
        let parent = parent_path(&rel).to_string();
        let name = basename(&rel).to_string();
        if !fs.paths.contains_key(&parent) {
            return Err(-2);
        }
        let ino = fs.alloc_ino();
        let node = INode::new_file(ino);
        fs.inodes.insert(ino, node);
        fs.paths.insert(rel.clone(), ino);
        let parent_ino = *fs.paths.get(&parent).unwrap();
        if let Some(p) = fs.inodes.get_mut(&parent_ino) {
            if let INodeData::Dir(ref mut entries) = p.data {
                entries.insert(name, ino);
            }
        }
    }

    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    let old_size = match &node.data {
        INodeData::File(v) => v.len(),
        _ => return Err(-22),
    };
    let new_size = data.len();
    if new_size > old_size {
        let delta = new_size - old_size;
        if fs.used + delta > fs.limit {
            return Err(-28);
        } // ENOSPC
        fs.used += delta;
    } else {
        fs.used = fs.used.saturating_sub(old_size - new_size);
    }
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    match &mut node.data {
        INodeData::File(v) => {
            *v = data.to_vec();
            Ok(())
        },
        _ => Err(-22),
    }
}

pub fn tmpfs_pread(full_path: &str, offset: usize, len: usize) -> Result<Vec<u8>, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let fs = tbl.get(mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    match &node.data {
        INodeData::File(v) => {
            if offset >= v.len() {
                return Ok(Vec::new());
            }
            let end = (offset + len).min(v.len());
            Ok(v[offset..end].to_vec())
        },
        _ => Err(-22),
    }
}

pub fn tmpfs_pwrite(full_path: &str, offset: usize, data: &[u8]) -> Result<usize, isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    let old_size = match &node.data {
        INodeData::File(v) => v.len(),
        _ => return Err(-22),
    };
    let new_end = offset + data.len();
    if new_end > old_size {
        let delta = new_end - old_size;
        if fs.used + delta > fs.limit {
            return Err(-28);
        }
        fs.used += delta;
    }
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    match &mut node.data {
        INodeData::File(v) => {
            let end = offset + data.len();
            if end > v.len() {
                v.resize(end, 0);
            }
            v[offset..end].copy_from_slice(data);
            Ok(data.len())
        },
        _ => Err(-22),
    }
}

pub fn tmpfs_truncate(full_path: &str, len: usize) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    let old_size = match &node.data {
        INodeData::File(v) => v.len(),
        _ => return Err(-22),
    };
    if len > old_size {
        let delta = len - old_size;
        if fs.used + delta > fs.limit {
            return Err(-28);
        }
        fs.used += delta;
    } else {
        fs.used = fs.used.saturating_sub(old_size - len);
    }
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    match &mut node.data {
        INodeData::File(v) => {
            v.resize(len, 0);
            Ok(())
        },
        _ => Err(-22),
    }
}

pub fn tmpfs_stat(full_path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let fs = tbl.get(mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    let size = node.file_size() as u64;
    Ok(crate::fs::vfs_ops::KStat {
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

pub fn tmpfs_mkdir(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    if fs.paths.contains_key(&rel) {
        return Err(-17);
    }

    let parent = parent_path(&rel).to_string();
    let name = basename(&rel).to_string();
    if !fs.paths.contains_key(&parent) {
        return Err(-2);
    }

    let ino = fs.alloc_ino();
    let node = INode::new_dir(ino);
    fs.inodes.insert(ino, node);
    fs.paths.insert(rel, ino);

    let parent_ino = *fs.paths.get(&parent).unwrap();
    if let Some(p) = fs.inodes.get_mut(&parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.insert(name, ino);
        }
    }
    Ok(())
}

pub fn tmpfs_rmdir(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let is_empty = match &fs.inodes.get(&ino).ok_or(-2isize)?.data {
        INodeData::Dir(entries) => entries.is_empty(),
        _ => return Err(-20), // ENOTDIR
    };
    if !is_empty {
        return Err(-39);
    } // ENOTEMPTY

    // Remove from parent.
    let parent = parent_path(&rel).to_string();
    let name = basename(&rel).to_string();
    let parent_ino = fs.paths.get(&parent).copied().unwrap_or(1);
    if let Some(p) = fs.inodes.get_mut(&parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.remove(&name);
        }
    }
    fs.inodes.remove(&ino);
    fs.paths.remove(&rel);
    Ok(())
}

pub fn tmpfs_unlink(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    if node.is_dir() {
        return Err(-21);
    } // EISDIR
    let freed = node.file_size();
    fs.used = fs.used.saturating_sub(freed);

    let parent = parent_path(&rel).to_string();
    let name = basename(&rel).to_string();
    let parent_ino = fs.paths.get(&parent).copied().unwrap_or(1);
    if let Some(p) = fs.inodes.get_mut(&parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.remove(&name);
        }
    }
    fs.paths.remove(&rel);
    // Only drop the inode when nlink reaches 0.
    let nlink = {
        let n = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
        n.nlink = n.nlink.saturating_sub(1);
        n.nlink
    };
    if nlink == 0 {
        fs.inodes.remove(&ino);
    }
    Ok(())
}

pub fn tmpfs_rename(old_path: &str, new_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    // Both paths must be on the same tmpfs instance.
    let (mp_o, rel_o) = best_mount(&tbl, old_path).ok_or(-2isize)?;
    let (mp_n, rel_n) = best_mount(&tbl, new_path).ok_or(-2isize)?;
    if mp_o != mp_n {
        return Err(-18);
    } // EXDEV
    let mp = mp_o.to_string();
    let rel_o = rel_o.clone();
    let rel_n = rel_n.clone();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    let &ino = fs.paths.get(&rel_o).ok_or(-2isize)?;

    // Remove old directory entry.
    let old_parent = parent_path(&rel_o).to_string();
    let old_name = basename(&rel_o).to_string();
    let old_parent_ino = fs.paths.get(&old_parent).copied().unwrap_or(1);
    if let Some(p) = fs.inodes.get_mut(&old_parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.remove(&old_name);
        }
    }
    fs.paths.remove(&rel_o);

    // If new_path exists, remove it first.
    if let Some(&old_new_ino) = fs.paths.get(&rel_n) {
        fs.inodes.remove(&old_new_ino);
        fs.paths.remove(&rel_n);
    }

    // Insert new directory entry.
    let new_parent = parent_path(&rel_n).to_string();
    let new_name = basename(&rel_n).to_string();
    let new_parent_ino = fs.paths.get(&new_parent).copied().unwrap_or(1);
    if let Some(p) = fs.inodes.get_mut(&new_parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.insert(new_name, ino);
        }
    }
    fs.paths.insert(rel_n, ino);
    Ok(())
}

pub fn tmpfs_link(existing: &str, new_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp_e, rel_e) = best_mount(&tbl, existing).ok_or(-2isize)?;
    let (mp_n, rel_n) = best_mount(&tbl, new_path).ok_or(-2isize)?;
    if mp_e != mp_n {
        return Err(-18);
    }
    let mp = mp_e.to_string();
    let rel_e = rel_e.clone();
    let rel_n = rel_n.clone();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    let &ino = fs.paths.get(&rel_e).ok_or(-2isize)?;
    if fs.paths.contains_key(&rel_n) {
        return Err(-17);
    }
    if fs.inodes.get(&ino).map(|n| n.is_dir()).unwrap_or(false) {
        return Err(-1);
    }

    let parent = parent_path(&rel_n).to_string();
    let name = basename(&rel_n).to_string();
    let parent_ino = fs.paths.get(&parent).copied().ok_or(-2isize)?;
    if let Some(p) = fs.inodes.get_mut(&parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.insert(name, ino);
        }
    }
    fs.paths.insert(rel_n, ino);
    if let Some(node) = fs.inodes.get_mut(&ino) {
        node.nlink += 1;
    }
    Ok(())
}

pub fn tmpfs_symlink(target: &str, link_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, link_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;

    if fs.paths.contains_key(&rel) {
        return Err(-17);
    }
    let parent = parent_path(&rel).to_string();
    let name = basename(&rel).to_string();
    if !fs.paths.contains_key(&parent) {
        return Err(-2);
    }

    let ino = fs.alloc_ino();
    let node = INode::new_symlink(ino, target);
    fs.inodes.insert(ino, node);
    fs.paths.insert(rel, ino);

    let parent_ino = *fs.paths.get(&parent).unwrap();
    if let Some(p) = fs.inodes.get_mut(&parent_ino) {
        if let INodeData::Dir(ref mut entries) = p.data {
            entries.insert(name, ino);
        }
    }
    Ok(())
}

pub fn tmpfs_readlink(full_path: &str) -> Result<String, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let fs = tbl.get(mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    match &node.data {
        INodeData::Symlink(s) => Ok(s.clone()),
        _ => Err(-22),
    }
}

pub fn tmpfs_readdir(full_path: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let fs = tbl.get(mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get(&ino).ok_or(-2isize)?;
    match &node.data {
        INodeData::Dir(entries) => {
            let mut out = Vec::new();
            for (name, &child_ino) in entries.iter() {
                if let Some(child) = fs.inodes.get(&child_ino) {
                    let size = child.file_size() as u64;
                    out.push(crate::fs::vfs_ops::DirEntry {
                        name: name.clone(),
                        ino: child_ino,
                        is_dir: child.is_dir(),
                        mode: child.mode,
                        size,
                    });
                }
            }
            Ok(out)
        },
        _ => Err(-20), // ENOTDIR
    }
}

pub fn tmpfs_chmod(full_path: &str, mode: u16) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    // Preserve file-type bits, replace permission bits.
    node.mode = (node.mode & 0o170000) | (mode & 0o7777);
    Ok(())
}

pub fn tmpfs_chown(full_path: &str, uid: u32, gid: u32) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let (mp, rel) = best_mount(&tbl, full_path).ok_or(-2isize)?;
    let mp = mp.to_string();
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;
    let &ino = fs.paths.get(&rel).ok_or(-2isize)?;
    let node = fs.inodes.get_mut(&ino).ok_or(-2isize)?;
    if uid != u32::MAX {
        node.uid = uid;
    }
    if gid != u32::MAX {
        node.gid = gid;
    }
    Ok(())
}

// Returns a KStatfs for the tmpfs instance whose mount-point is the longest
// prefix of `full_path`.  Called by stat_syscalls::sys_statfs / sys_fstatfs.

pub fn tmpfs_statfs_for(full_path: &str) -> crate::fs::vfs_ops::KStatfs {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let mut best_len = 0usize;
    let mut best_mp: Option<&str> = None;
    for mp in tbl.keys() {
        let ms = mp.trim_end_matches('/');
        if (full_path == ms || full_path.starts_with(&alloc::format!("{}/", ms)) || ms.is_empty())
            && ms.len() >= best_len
        {
            best_len = ms.len();
            best_mp = Some(mp.as_str());
        }
    }
    if let Some(mp) = best_mp {
        let sf = tbl.get(mp).unwrap().statfs();
        return crate::fs::vfs_ops::KStatfs {
            f_type: sf.f_type,
            f_bsize: sf.f_bsize,
            f_blocks: sf.f_blocks,
            f_bfree: sf.f_bfree,
            f_bavail: sf.f_bavail,
            f_namelen: sf.f_namelen,
        };
    }
    crate::fs::vfs_ops::KStatfs::default()
}

// An anon inode lives in the inode table of the owning tmpfs instance but is
// never inserted into any directory.  Its FD backing path is the synthetic
// string "<mountpoint>/@anon:<ino>".  Both '@' and ':' are illegal in POSIX
// filenames, so this can never collide with a real path.

const ANON_PREFIX: &str = "/@anon:";

/// True iff `path` is a synthetic anon path produced by `tmpfs_create_anon`.
pub fn is_anon_path(path: &str) -> bool {
    path.contains(ANON_PREFIX)
}

/// Parse "<mountroot>/@anon:<ino>" into (mountroot, ino).
fn parse_anon_path(full_path: &str) -> Option<(&str, u64)> {
    let at = full_path.rfind(ANON_PREFIX)?;
    let ino_str = &full_path[at + ANON_PREFIX.len()..];
    let ino: u64 = ino_str.parse().ok()?;
    Some((&full_path[..at], ino))
}

fn anon_fs_mut<'a>(tbl: &'a mut BTreeMap<String, TmpFs>, mp_prefix: &str) -> Option<&'a mut TmpFs> {
    let key = mp_prefix.trim_end_matches('/').to_string();
    if tbl.contains_key(&key) {
        return tbl.get_mut(&key);
    }
    let key2 = alloc::format!("{}/", key);
    if tbl.contains_key(&key2) {
        return tbl.get_mut(&key2);
    }
    None
}

fn anon_fs_ref<'a>(tbl: &'a BTreeMap<String, TmpFs>, mp_prefix: &str) -> Option<&'a TmpFs> {
    let key = mp_prefix.trim_end_matches('/').to_string();
    tbl.get(&key)
        .or_else(|| tbl.get(&alloc::format!("{}/", key)))
}

/// Create an anonymous (unlinked) file inside the tmpfs that owns `dir_path`.
/// Returns the synthetic backing path on success, or a negative errno.
pub fn tmpfs_create_anon(dir_path: &str) -> Result<String, isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    let mut best_len = 0usize;
    let mut best_mp: Option<String> = None;
    for mp in tbl.keys() {
        let ms = mp.trim_end_matches('/');
        if (dir_path == ms || dir_path.starts_with(&alloc::format!("{}/", ms)) || ms.is_empty())
            && ms.len() >= best_len
        {
            best_len = ms.len();
            best_mp = Some(mp.clone());
        }
    }
    let mp = best_mp.ok_or(-2isize)?;
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;
    let ino = fs.alloc_ino();
    let node = INode::new_file(ino);
    fs.inodes.insert(ino, node);
    let mountroot = mp.trim_end_matches('/');
    Ok(alloc::format!("{}{}{}", mountroot, ANON_PREFIX, ino))
}

/// pread on an anonymous inode.
pub fn tmpfs_anon_pread(full_path: &str, offset: usize, len: usize) -> Result<Vec<u8>, isize> {
    ensure_defaults();
    let (mp_prefix, ino) = parse_anon_path(full_path).ok_or(-9isize)?;
    let mut tbl = TMPFS_INSTANCES.lock();
    let fs = anon_fs_mut(&mut tbl, mp_prefix).ok_or(-9isize)?;
    let node = fs.inodes.get(&ino).ok_or(-9isize)?;
    match &node.data {
        INodeData::File(v) => {
            if offset >= v.len() {
                return Ok(Vec::new());
            }
            let end = (offset + len).min(v.len());
            Ok(v[offset..end].to_vec())
        },
        _ => Err(-22),
    }
}

/// pwrite on an anonymous inode.
pub fn tmpfs_anon_pwrite(full_path: &str, offset: usize, data: &[u8]) -> Result<usize, isize> {
    ensure_defaults();
    let (mp_prefix, ino) = parse_anon_path(full_path).ok_or(-9isize)?;
    let mut tbl = TMPFS_INSTANCES.lock();
    let fs = anon_fs_mut(&mut tbl, mp_prefix).ok_or(-9isize)?;
    let node = fs.inodes.get(&ino).ok_or(-9isize)?;
    let old_size = if let INodeData::File(v) = &node.data {
        v.len()
    } else {
        return Err(-22);
    };
    let new_end = offset + data.len();
    if new_end > old_size {
        let delta = new_end - old_size;
        if fs.used + delta > fs.limit {
            return Err(-28);
        }
        fs.used += delta;
    }
    let node = fs.inodes.get_mut(&ino).ok_or(-9isize)?;
    match &mut node.data {
        INodeData::File(v) => {
            let end = offset + data.len();
            if end > v.len() {
                v.resize(end, 0);
            }
            v[offset..end].copy_from_slice(data);
            Ok(data.len())
        },
        _ => Err(-22),
    }
}

/// ftruncate on an anonymous inode.
pub fn tmpfs_anon_truncate(full_path: &str, len: usize) -> Result<(), isize> {
    ensure_defaults();
    let (mp_prefix, ino) = parse_anon_path(full_path).ok_or(-9isize)?;
    let mut tbl = TMPFS_INSTANCES.lock();
    let fs = anon_fs_mut(&mut tbl, mp_prefix).ok_or(-9isize)?;
    let node = fs.inodes.get(&ino).ok_or(-9isize)?;
    let old_size = if let INodeData::File(v) = &node.data {
        v.len()
    } else {
        return Err(-22);
    };
    if len > old_size {
        let delta = len - old_size;
        if fs.used + delta > fs.limit {
            return Err(-28);
        }
        fs.used += delta;
    } else {
        fs.used = fs.used.saturating_sub(old_size - len);
    }
    let node = fs.inodes.get_mut(&ino).ok_or(-9isize)?;
    match &mut node.data {
        INodeData::File(v) => {
            v.resize(len, 0);
            Ok(())
        },
        _ => Err(-22),
    }
}

/// fstat on an anonymous inode.
pub fn tmpfs_anon_stat(full_path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    ensure_defaults();
    let (mp_prefix, ino) = parse_anon_path(full_path).ok_or(-9isize)?;
    let tbl = TMPFS_INSTANCES.lock();
    let fs = anon_fs_ref(&tbl, mp_prefix).ok_or(-9isize)?;
    let node = fs.inodes.get(&ino).ok_or(-9isize)?;
    let size = node.file_size() as u64;
    Ok(crate::fs::vfs_ops::KStat {
        ino,
        mode: node.mode,
        nlink: 1,
        uid: node.uid,
        gid: node.gid,
        size,
        atime: node.atime,
        mtime: node.mtime,
        ctime: node.ctime,
        blksize: 4096,
        blocks: size.div_ceil(512),
        is_dir: false,
    })
}

struct RamSchemeFd {
    path: String,
    offset: usize,
    readable: bool,
    writable: bool,
}

static RAM_SCHEME_FDS: Mutex<BTreeMap<u64, RamSchemeFd>> = Mutex::new(BTreeMap::new());
static RAM_SCHEME_NEXT_FID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Scheme adapter for `ram:<path>` URLs.
pub struct RamFs;

impl RamFs {
    pub const fn new() -> Self {
        Self
    }
}

fn ram_scheme_path(path: &str) -> String {
    if path.is_empty() {
        String::from("/")
    } else if path.starts_with('/') {
        String::from(path)
    } else {
        format!("/{}", path)
    }
}

fn ram_scheme_error(errno: isize) -> scheme_api::SchemeError {
    match errno {
        -2 => scheme_api::SchemeError::NotFound,
        -13 => scheme_api::SchemeError::PermissionDenied,
        -22 => scheme_api::SchemeError::InvalidArg,
        -11 => scheme_api::SchemeError::WouldBlock,
        _ => scheme_api::SchemeError::Io,
    }
}

fn ram_scheme_access(flags: scheme_api::OpenFlags) -> (bool, bool) {
    let write = flags.intersects(
        scheme_api::OpenFlags::WRITE
            | scheme_api::OpenFlags::CREATE
            | scheme_api::OpenFlags::TRUNCATE
            | scheme_api::OpenFlags::APPEND,
    );
    let read = flags.contains(scheme_api::OpenFlags::READ) || !write;
    (read, write)
}

impl crate::fs::scheme_table::Scheme for RamFs {
    fn open(
        &self,
        path: &str,
        flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        let full_path = ram_scheme_path(path);
        let (readable, writable) = ram_scheme_access(flags);

        match tmpfs_stat(&full_path) {
            Ok(st) => {
                if st.is_dir && !flags.contains(scheme_api::OpenFlags::DIRECTORY) {
                    return Err(scheme_api::SchemeError::InvalidArg);
                }
            },
            Err(-2) if flags.contains(scheme_api::OpenFlags::CREATE) => {
                tmpfs_create(&full_path).map_err(ram_scheme_error)?;
            },
            Err(e) => return Err(ram_scheme_error(e)),
        }

        if flags.contains(scheme_api::OpenFlags::TRUNCATE) {
            tmpfs_truncate(&full_path, 0).map_err(ram_scheme_error)?;
        }

        let offset = if flags.contains(scheme_api::OpenFlags::APPEND) {
            tmpfs_stat(&full_path)
                .map(|st| st.size as usize)
                .unwrap_or(0)
        } else {
            0
        };
        let fid = RAM_SCHEME_NEXT_FID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        RAM_SCHEME_FDS.lock().insert(
            fid,
            RamSchemeFd {
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
            let fds = RAM_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(scheme_api::SchemeError::NotFound)?;
            (fd.path.clone(), fd.offset, fd.readable)
        };
        if !readable {
            return Err(scheme_api::SchemeError::PermissionDenied);
        }
        let data = tmpfs_pread(&path, offset, buf.len()).map_err(ram_scheme_error)?;
        let n = data.len();
        buf[..n].copy_from_slice(&data);
        if n > 0 {
            if let Some(fd) = RAM_SCHEME_FDS.lock().get_mut(&fid.0) {
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
            let fds = RAM_SCHEME_FDS.lock();
            let fd = fds.get(&fid.0).ok_or(scheme_api::SchemeError::NotFound)?;
            (fd.path.clone(), fd.offset, fd.writable)
        };
        if !writable {
            return Err(scheme_api::SchemeError::PermissionDenied);
        }
        let n = tmpfs_pwrite(&path, offset, buf).map_err(ram_scheme_error)?;
        if n > 0 {
            if let Some(fd) = RAM_SCHEME_FDS.lock().get_mut(&fid.0) {
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
        let mut fds = RAM_SCHEME_FDS.lock();
        let fd = fds
            .get_mut(&fid.0)
            .ok_or(scheme_api::SchemeError::NotFound)?;
        let size = tmpfs_stat(&fd.path).map_err(ram_scheme_error)?.size as i64;
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
        RAM_SCHEME_FDS.lock().remove(&fid.0);
        Ok(())
    }
}
