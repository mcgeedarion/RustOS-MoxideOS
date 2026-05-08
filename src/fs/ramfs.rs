//! tmpfs / ramfs — fully in-memory filesystem.
//!
//! Suitable for mounting at /tmp, /run, /dev/shm, etc.
//! Files are backed by heap-allocated byte vectors; no block device is used.
//!
//! ## VFS integration
//! ramfs is wired into the path-dispatch in vfs_ops.rs by mount-point prefix
//! matching (see `MountTable` in mount.rs).  When the caller's path falls under
//! a ramfs mount point, all I/O is forwarded here.
//!
//! ## Supported operations
//!   open, creat, read, write, pread, pwrite, seek, truncate, ftruncate
//!   mkdir, rmdir, unlink, rename, link, symlink, readlink
//!   stat (full: uid/gid/timestamps), statfs, readdir (getdents64)
//!   chmod, chown
//!
//! ## Multi-mount correctness
//!   Every mutating shim uses `find_instance_and_rel` to route to the
//!   specific TmpFs instance for the given full path, so /tmp, /run, and
//!   /dev/shm are genuinely independent namespaces.

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const TMPFS_MAGIC:   u64 = 0x0102_1994;
const DEFAULT_LIMIT: usize = 64 * 1024 * 1024; // 64 MiB per mount
const INO_ROOT:      u64  = 1;

// POSIX mode bits
const S_IFREG: u16 = 0o0100_000;
const S_IFDIR: u16 = 0o0040_000;
const S_IFLNK: u16 = 0o0120_000;
const S_IFMT:  u16 = 0o0170_000;

// ── Inode ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum INodeData {
    File(Vec<u8>),
    Dir(BTreeMap<String, u64>),   // name → ino
    Symlink(String),
}

#[derive(Clone)]
struct INode {
    ino:   u64,
    mode:  u16,
    uid:   u32,
    gid:   u32,
    nlink: u32,
    atime: u64,
    mtime: u64,
    ctime: u64,
    data:  INodeData,
}

impl INode {
    fn new_file(ino: u64) -> Self {
        INode { ino, mode: S_IFREG | 0o644, uid: 0, gid: 0, nlink: 1,
                atime: 0, mtime: 0, ctime: 0, data: INodeData::File(Vec::new()) }
    }
    fn new_dir(ino: u64) -> Self {
        let mut d = BTreeMap::new();
        d.insert(".".to_string(), ino);
        INode { ino, mode: S_IFDIR | 0o755, uid: 0, gid: 0, nlink: 2,
                atime: 0, mtime: 0, ctime: 0, data: INodeData::Dir(d) }
    }
    fn new_symlink(ino: u64, target: String) -> Self {
        INode { ino, mode: S_IFLNK | 0o777, uid: 0, gid: 0, nlink: 1,
                atime: 0, mtime: 0, ctime: 0, data: INodeData::Symlink(target) }
    }
    fn size(&self) -> usize {
        match &self.data {
            INodeData::File(v)    => v.len(),
            INodeData::Symlink(s) => s.len(),
            INodeData::Dir(_)     => 0,
        }
    }
    fn is_dir(&self)  -> bool { self.mode & S_IFMT == S_IFDIR }
    fn is_file(&self) -> bool { self.mode & S_IFMT == S_IFREG }
}

// ── Per-mount filesystem state ────────────────────────────────────────────────

struct TmpFs {
    inodes:   BTreeMap<u64, INode>,
    next_ino: u64,
    used:     usize,
    limit:    usize,
}

impl TmpFs {
    fn new(limit: usize) -> Self {
        let mut fs = TmpFs {
            inodes:   BTreeMap::new(),
            next_ino: INO_ROOT + 1,
            used:     0,
            limit,
        };
        let root = INode::new_dir(INO_ROOT);
        fs.inodes.insert(INO_ROOT, root);
        fs
    }

    fn alloc_ino(&mut self) -> u64 {
        let i = self.next_ino;
        self.next_ino += 1;
        i
    }

    // ── Path resolution ───────────────────────────────────────────────────────

    fn lookup(&self, path: &str) -> Option<u64> {
        let path = path.trim_start_matches('/');
        let mut cur = INO_ROOT;
        if path.is_empty() { return Some(cur); }
        for part in path.split('/') {
            if part.is_empty() || part == "." { continue; }
            if part == ".." {
                let mut found = INO_ROOT;
                'outer: for inode in self.inodes.values() {
                    if let INodeData::Dir(d) = &inode.data {
                        for (_, &child_ino) in d.iter() {
                            if child_ino == cur && inode.ino != cur {
                                found = inode.ino;
                                break 'outer;
                            }
                        }
                    }
                }
                cur = found;
                continue;
            }
            let dir_node = self.inodes.get(&cur)?;
            if let INodeData::Dir(d) = &dir_node.data {
                cur = *d.get(part)?;
            } else {
                return None;
            }
        }
        Some(cur)
    }

    fn split_parent(&self, path: &str) -> Option<(u64, String)> {
        let path = path.trim_end_matches('/');
        match path.rfind('/') {
            None | Some(0) => {
                let name = path.trim_start_matches('/');
                Some((INO_ROOT, name.to_string()))
            }
            Some(i) => {
                let parent_path = &path[..i];
                let name        = &path[i + 1..];
                let parent_ino  = self.lookup(parent_path)?;
                let parent      = self.inodes.get(&parent_ino)?;
                if !parent.is_dir() { return None; }
                Some((parent_ino, name.to_string()))
            }
        }
    }

    // ── File I/O ──────────────────────────────────────────────────────────────

    fn read_all(&self, path: &str) -> Result<Vec<u8>, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get(&ino).ok_or(-2isize)?;
        match &node.data {
            INodeData::File(v)    => Ok(v.clone()),
            INodeData::Dir(_)     => Err(-21),
            INodeData::Symlink(_) => Err(-22),
        }
    }

    /// Read `len` bytes from `path` starting at `offset`.
    fn pread(&self, path: &str, offset: usize, len: usize) -> Result<Vec<u8>, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get(&ino).ok_or(-2isize)?;
        match &node.data {
            INodeData::File(v) => {
                if offset >= v.len() { return Ok(Vec::new()); }
                let end = (offset + len).min(v.len());
                Ok(v[offset..end].to_vec())
            }
            INodeData::Dir(_)     => Err(-21), // EISDIR
            INodeData::Symlink(_) => Err(-22), // EINVAL
        }
    }

    /// Write `data` to `path` at `offset`, extending the file if necessary.
    fn pwrite(&mut self, path: &str, offset: usize, data: &[u8]) -> Result<usize, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get_mut(&ino).ok_or(-2isize)?;
        match &mut node.data {
            INodeData::File(v) => {
                let end = offset + data.len();
                let old_len = v.len();
                // Capacity check against mount limit.
                let new_used = self.used as isize
                    - old_len as isize
                    + end.max(old_len) as isize;
                if new_used > self.limit as isize { return Err(-28); } // ENOSPC
                if end > v.len() { v.resize(end, 0); }
                v[offset..end].copy_from_slice(data);
                self.used = (self.used as isize
                    - old_len as isize
                    + v.len() as isize) as usize;
                Ok(data.len())
            }
            INodeData::Dir(_)     => Err(-21),
            INodeData::Symlink(_) => Err(-22),
        }
    }

    fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get_mut(&ino).ok_or(-2isize)?;
        match &mut node.data {
            INodeData::File(v) => {
                let old_len = v.len() as isize;
                let new_used = self.used as isize - old_len + data.len() as isize;
                if new_used as usize > self.limit { return Err(-28); }
                self.used = new_used as usize;
                *v = data.to_vec();
                Ok(())
            }
            INodeData::Dir(_)     => Err(-21),
            INodeData::Symlink(_) => Err(-22),
        }
    }

    /// Resize a file to exactly `len` bytes (truncate or zero-extend).
    fn truncate(&mut self, path: &str, len: usize) -> Result<(), isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get_mut(&ino).ok_or(-2isize)?;
        if node.is_dir() { return Err(-21); } // EISDIR
        match &mut node.data {
            INodeData::File(v) => {
                let old_len = v.len();
                // Check new size against limit (only when growing).
                if len > old_len {
                    let new_used = self.used + (len - old_len);
                    if new_used > self.limit { return Err(-28); } // ENOSPC
                }
                let delta = len as isize - old_len as isize;
                v.resize(len, 0);
                self.used = (self.used as isize + delta) as usize;
                Ok(())
            }
            _ => Err(-22),
        }
    }

    // ── Directory operations ──────────────────────────────────────────────────

    fn create(&mut self, path: &str) -> Result<(), isize> {
        if self.lookup(path).is_some() { return Err(-17); } // EEXIST
        let (parent_ino, name) = self.split_parent(path).ok_or(-2isize)?;
        let ino = self.alloc_ino();
        let node = INode::new_file(ino);
        self.inodes.insert(ino, node);
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.insert(name, ino);
        }
        Ok(())
    }

    fn mkdir(&mut self, path: &str) -> Result<(), isize> {
        if self.lookup(path).is_some() { return Err(-17); }
        let (parent_ino, name) = self.split_parent(path).ok_or(-2isize)?;
        let ino = self.alloc_ino();
        let mut node = INode::new_dir(ino);
        if let INodeData::Dir(d) = &mut node.data {
            d.insert("..".to_string(), parent_ino);
        }
        self.inodes.insert(ino, node);
        // Bump parent nlink for the new ".."
        if let Some(p) = self.inodes.get_mut(&parent_ino) { p.nlink += 1; }
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.insert(name, ino);
        }
        Ok(())
    }

    /// Remove an empty directory.
    fn rmdir(&mut self, path: &str) -> Result<(), isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        {
            let node = self.inodes.get(&ino).ok_or(-2isize)?;
            if !node.is_dir() { return Err(-20); } // ENOTDIR
            // Must be empty (only "." and ".." allowed)
            if let INodeData::Dir(d) = &node.data {
                let non_dot = d.keys().filter(|k| k.as_str() != "." && k.as_str() != "..").count();
                if non_dot > 0 { return Err(-39); } // ENOTEMPTY
            }
        }
        self.inodes.remove(&ino);
        let (parent_ino, name) = self.split_parent(path).ok_or(-2isize)?;
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.remove(&name);
        }
        // Decrement parent nlink (the ".."/subdirectory link is gone)
        if let Some(p) = self.inodes.get_mut(&parent_ino) {
            p.nlink = p.nlink.saturating_sub(1);
        }
        Ok(())
    }

    fn unlink(&mut self, path: &str) -> Result<(), isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        {
            let node = self.inodes.get_mut(&ino).ok_or(-2isize)?;
            if node.is_dir() { return Err(-21); } // EISDIR
            node.nlink = node.nlink.saturating_sub(1);
            // Only free data when all hard links are gone.
            if node.nlink == 0 {
                if let INodeData::File(v) = &node.data {
                    self.used = self.used.saturating_sub(v.len());
                }
            }
        }
        // Remove directory entry; keep inode if nlink > 0 (other hard links).
        let (parent_ino, name) = self.split_parent(path).ok_or(-2isize)?;
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.remove(&name);
        }
        // Drop the inode only when nlink reaches zero.
        if self.inodes.get(&ino).map_or(false, |n| n.nlink == 0) {
            self.inodes.remove(&ino);
        }
        Ok(())
    }

    /// Create a hard link: `new_path` → same inode as `existing_path`.
    fn link(&mut self, existing_path: &str, new_path: &str) -> Result<(), isize> {
        if self.lookup(new_path).is_some() { return Err(-17); } // EEXIST
        let ino = self.lookup(existing_path).ok_or(-2isize)?;
        {
            let node = self.inodes.get(&ino).ok_or(-2isize)?;
            if node.is_dir() { return Err(-1); } // EPERM: cannot hard-link dirs
        }
        let (parent_ino, name) = self.split_parent(new_path).ok_or(-2isize)?;
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.insert(name, ino);
        }
        if let Some(node) = self.inodes.get_mut(&ino) {
            node.nlink += 1;
        }
        Ok(())
    }

    fn rename(&mut self, old: &str, new: &str) -> Result<(), isize> {
        let ino = self.lookup(old).ok_or(-2isize)?;
        let (old_parent_ino, old_name) = self.split_parent(old).ok_or(-2isize)?;
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&old_parent_ino).map(|n| &mut n.data) {
            d.remove(&old_name);
        }
        let (new_parent_ino, new_name) = self.split_parent(new).ok_or(-2isize)?;
        if self.inodes.get(&new_parent_ino).is_none() { return Err(-2); }
        // If destination already exists, unlink it first.
        if let Some(old_dst_ino) = self.lookup(new) {
            if let Some(n) = self.inodes.get_mut(&old_dst_ino) {
                n.nlink = n.nlink.saturating_sub(1);
                if n.nlink == 0 {
                    if let INodeData::File(v) = &n.data { self.used = self.used.saturating_sub(v.len()); }
                }
            }
            if self.inodes.get(&old_dst_ino).map_or(false, |n| n.nlink == 0) {
                self.inodes.remove(&old_dst_ino);
            }
            if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&new_parent_ino).map(|n| &mut n.data) {
                d.remove(&new_name);
            }
        }
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&new_parent_ino).map(|n| &mut n.data) {
            d.insert(new_name, ino);
        }
        Ok(())
    }

    fn readdir(&self, path: &str) -> Result<Vec<String>, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get(&ino).ok_or(-2isize)?;
        match &node.data {
            INodeData::Dir(d) => Ok(d.keys().cloned().collect()),
            _ => Err(-20),
        }
    }

    fn stat(&self, path: &str) -> Result<TmpfsStat, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get(&ino).ok_or(-2isize)?;
        let sz = node.size() as u64;
        Ok(TmpfsStat {
            ino:     node.ino,
            mode:    node.mode,
            nlink:   node.nlink,
            uid:     node.uid,
            gid:     node.gid,
            size:    sz,
            atime:   node.atime,
            mtime:   node.mtime,
            ctime:   node.ctime,
            blksize: 4096,
            blocks:  sz.div_ceil(512),
            is_dir:  node.is_dir(),
        })
    }

    fn symlink(&mut self, target: &str, link_path: &str) -> Result<(), isize> {
        if self.lookup(link_path).is_some() { return Err(-17); }
        let (parent_ino, name) = self.split_parent(link_path).ok_or(-2isize)?;
        let ino = self.alloc_ino();
        let node = INode::new_symlink(ino, target.to_string());
        self.inodes.insert(ino, node);
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.insert(name, ino);
        }
        Ok(())
    }

    fn readlink(&self, path: &str) -> Result<String, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get(&ino).ok_or(-2isize)?;
        match &node.data {
            INodeData::Symlink(t) => Ok(t.clone()),
            _ => Err(-22),
        }
    }

    fn chmod(&mut self, path: &str, mode: u16) -> Result<(), isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get_mut(&ino).ok_or(-2isize)?;
        // Preserve the file-type bits; replace permission bits only.
        node.mode = (node.mode & S_IFMT) | (mode & !S_IFMT);
        Ok(())
    }

    fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get_mut(&ino).ok_or(-2isize)?;
        // 0xFFFF_FFFF means "don't change" (matching Linux chown(2) semantics)
        if uid != 0xFFFF_FFFF { node.uid = uid; }
        if gid != 0xFFFF_FFFF { node.gid = gid; }
        Ok(())
    }

    fn statfs(&self) -> TmpfsStatfs {
        TmpfsStatfs {
            f_type:    TMPFS_MAGIC,
            f_bsize:   4096,
            f_blocks:  (self.limit / 4096) as u64,
            f_bfree:   (self.limit.saturating_sub(self.used) / 4096) as u64,
            f_bavail:  (self.limit.saturating_sub(self.used) / 4096) as u64,
            f_namelen: 255,
        }
    }
}

// ── Stat / statfs result types ────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct TmpfsStat {
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

#[derive(Clone, Debug)]
pub struct TmpfsStatfs {
    pub f_type:    u64,
    pub f_bsize:   u64,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_bavail:  u64,
    pub f_namelen: u64,
}

// ── Global per-mountpoint instance table ──────────────────────────────────────

pub static TMPFS_INSTANCES: Mutex<BTreeMap<String, TmpFs>> =
    Mutex::new(BTreeMap::new());

/// Create a new tmpfs instance at `mountpoint` (idempotent).
pub fn tmpfs_mount(mountpoint: &str, limit: usize) {
    let mut tbl = TMPFS_INSTANCES.lock();
    tbl.entry(mountpoint.to_string())
       .or_insert_with(|| TmpFs::new(limit));
}

// ── Mountpoint lookup helper ──────────────────────────────────────────────────
//
// Finds the TmpFs instance whose mount-point is the longest prefix of
// `full_path` and returns (&mut TmpFs, mount-relative path).
// All mutating shims use this so that /tmp, /run, /dev/shm are independent.

fn find_instance_and_rel<'a>(
    tbl: &'a mut BTreeMap<String, TmpFs>,
    full_path: &str,
) -> Option<(&'a mut TmpFs, String)> {
    let mut best_len = 0usize;
    let mut best_mp: Option<String> = None;
    for mp in tbl.keys() {
        let mp_str = mp.trim_end_matches('/');
        if full_path == mp_str ||
           full_path.starts_with(&alloc::format!("{}/", mp_str))
        {
            if mp_str.len() > best_len {
                best_len = mp_str.len();
                best_mp = Some(mp.clone());
            }
        }
    }
    let mp = best_mp?;
    let mp_str = mp.trim_end_matches('/');
    let rel = if full_path.len() == mp_str.len() {
        "/".to_string()
    } else {
        full_path[mp_str.len()..].to_string()
    };
    let fs = tbl.get_mut(&mp)?;
    Some((fs, rel))
}

/// Ensure the three canonical tmpfs instances exist (idempotent).
#[inline]
fn ensure_defaults() {
    let mut tbl = TMPFS_INSTANCES.lock();
    for mp in &["/tmp", "/run", "/dev/shm"] {
        tbl.entry(mp.to_string()).or_insert_with(|| TmpFs::new(DEFAULT_LIMIT));
    }
}

// ── Public VFS shims ──────────────────────────────────────────────────────────
//
// All shims accept the FULL absolute path (not the mount-relative subpath)
// so that `find_instance_and_rel` can pick the correct TmpFs instance.
// The vfs_ops dispatcher already has the full path; it now passes `path`
// directly rather than `h.subpath`.  For backwards compatibility the
// read-only shims that only scan (tmpfs_read_all, tmpfs_stat, etc.) also
// accept full paths via the same mechanism.

/// Read entire file. `full_path` is the absolute path (e.g. "/tmp/foo").
pub fn tmpfs_read_all(full_path: &str) -> Result<Vec<u8>, isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    // Try to find via longest-prefix first.
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        if fs.lookup(&rel).is_some() { return fs.read_all(&rel); }
    }
    // Fallback: scan all instances (handles h.subpath callers).
    for fs in tbl.values() {
        if fs.lookup(full_path).is_some() { return fs.read_all(full_path); }
    }
    Err(-2)
}

/// Read `len` bytes at `offset` from `full_path`.
pub fn tmpfs_pread(full_path: &str, offset: usize, len: usize) -> Result<Vec<u8>, isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.pread(&rel, offset, len);
    }
    Err(-2)
}

/// Write `data` to `full_path` at `offset` (extends file if needed).
pub fn tmpfs_pwrite(full_path: &str, offset: usize, data: &[u8]) -> Result<usize, isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.pwrite(&rel, offset, data);
    }
    Err(-2)
}

/// Overwrite the entire file with `data` (creates if absent).
pub fn tmpfs_write_all(full_path: &str, data: &[u8]) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        if fs.lookup(&rel).is_some() {
            return fs.write_all(&rel, data);
        } else {
            fs.create(&rel)?;
            return fs.write_all(&rel, data);
        }
    }
    Err(-2)
}

/// Create a new empty file at `full_path`.
pub fn tmpfs_create(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.create(&rel);
    }
    Err(-2)
}

/// Create directory at `full_path`.
pub fn tmpfs_mkdir(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.mkdir(&rel);
    }
    Err(-2)
}

/// Remove empty directory at `full_path`.
pub fn tmpfs_rmdir(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.rmdir(&rel);
    }
    Err(-2)
}

/// Unlink (delete) a file at `full_path`.
pub fn tmpfs_unlink(full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        if fs.lookup(&rel).is_some() { return fs.unlink(&rel); }
    }
    // Fallback scan.
    for fs in tbl.values_mut() {
        if fs.lookup(full_path).is_some() { return fs.unlink(full_path); }
    }
    Err(-2)
}

/// Hard-link `existing_full_path` as `new_full_path` (must be same mountpoint).
pub fn tmpfs_link(existing_full_path: &str, new_full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    // Both paths must resolve to the same TmpFs instance.
    // We find the instance for the existing path and check the new path is also within it.
    let mut best_len = 0usize;
    let mut best_mp: Option<String> = None;
    for mp in tbl.keys() {
        let ms = mp.trim_end_matches('/');
        if (existing_full_path == ms || existing_full_path.starts_with(&alloc::format!("{}/", ms)))
            && ms.len() > best_len
        {
            best_len = ms.len();
            best_mp = Some(mp.clone());
        }
    }
    let mp = best_mp.ok_or(-2isize)?;
    let ms = mp.trim_end_matches('/');
    // new_full_path must also be under the same mountpoint.
    if !(new_full_path == ms || new_full_path.starts_with(&alloc::format!("{}/", ms))) {
        return Err(-18); // EXDEV
    }
    let rel_old = if existing_full_path.len() == ms.len() { "/".to_string() } else { existing_full_path[ms.len()..].to_string() };
    let rel_new = if new_full_path.len() == ms.len() { "/".to_string() } else { new_full_path[ms.len()..].to_string() };
    let fs = tbl.get_mut(&mp).ok_or(-2isize)?;
    fs.link(&rel_old, &rel_new)
}

/// Rename `old_full_path` to `new_full_path`.
pub fn tmpfs_rename(old_full_path: &str, new_full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel_old)) = find_instance_and_rel(&mut tbl, old_full_path) {
        let ms = {
            let mut blen = 0usize;
            let mut bmp: Option<String> = None;
            for mp in tbl.keys() {
                let ms = mp.trim_end_matches('/');
                if (old_full_path == ms || old_full_path.starts_with(&alloc::format!("{}/", ms)))
                    && ms.len() > blen { blen = ms.len(); bmp = Some(mp.clone()); }
            }
            bmp
        };
        if let Some(mp) = ms {
            let mount_str = mp.trim_end_matches('/');
            let rel_new = if new_full_path.len() == mount_str.len() { "/".to_string() } else { new_full_path[mount_str.len()..].to_string() };
            let fs2 = tbl.get_mut(&mp).ok_or(-2isize)?;
            return fs2.rename(&rel_old, &rel_new);
        }
    }
    // Fallback (subpath callers)
    for fs in tbl.values_mut() {
        if fs.lookup(old_full_path).is_some() {
            return fs.rename(old_full_path, new_full_path);
        }
    }
    Err(-2)
}

/// Resize a file to exactly `len` bytes.
pub fn tmpfs_truncate(full_path: &str, len: usize) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.truncate(&rel, len);
    }
    Err(-2)
}

/// List directory entries for `full_path`.
pub fn tmpfs_readdir(full_path: &str) -> Result<Vec<String>, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    // Read-only scan; can't use find_instance_and_rel (needs &mut).
    let mut best_len = 0usize;
    let mut best_mp: Option<&str> = None;
    for mp in tbl.keys() {
        let ms = mp.trim_end_matches('/');
        if (full_path == ms || full_path.starts_with(&alloc::format!("{}/", ms)))
            && ms.len() > best_len
        {
            best_len = ms.len();
            best_mp = Some(mp.as_str());
        }
    }
    if let Some(mp) = best_mp {
        let ms = mp.trim_end_matches('/');
        let rel = if full_path.len() == ms.len() { "/" } else { &full_path[ms.len()..] };
        return tbl.get(mp).unwrap().readdir(rel);
    }
    for fs in tbl.values() {
        if fs.lookup(full_path).is_some() { return fs.readdir(full_path); }
    }
    Err(-2)
}

/// Return kernel stat for `full_path`.
pub fn tmpfs_stat(full_path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let mut best_len = 0usize;
    let mut best_mp: Option<&str> = None;
    for mp in tbl.keys() {
        let ms = mp.trim_end_matches('/');
        if (full_path == ms || full_path.starts_with(&alloc::format!("{}/", ms)))
            && ms.len() > best_len
        {
            best_len = ms.len();
            best_mp = Some(mp.as_str());
        }
    }
    if let Some(mp) = best_mp {
        let ms = mp.trim_end_matches('/');
        let rel = if full_path.len() == ms.len() { "/" } else { &full_path[ms.len()..] };
        let s = tbl.get(mp).unwrap().stat(rel)?;
        return Ok(crate::fs::vfs_ops::KStat {
            ino:     s.ino,
            mode:    s.mode,
            nlink:   s.nlink,
            uid:     s.uid,
            gid:     s.gid,
            size:    s.size,
            atime:   s.atime,
            mtime:   s.mtime,
            ctime:   s.ctime,
            blksize: s.blksize,
            blocks:  s.blocks,
            is_dir:  s.is_dir,
        });
    }
    for fs in tbl.values() {
        if fs.lookup(full_path).is_some() {
            let s = fs.stat(full_path)?;
            return Ok(crate::fs::vfs_ops::KStat {
                ino: s.ino, mode: s.mode, nlink: s.nlink,
                uid: s.uid, gid: s.gid, size: s.size,
                atime: s.atime, mtime: s.mtime, ctime: s.ctime,
                blksize: s.blksize, blocks: s.blocks, is_dir: s.is_dir,
            });
        }
    }
    Err(-2)
}

/// Return statfs for a mount-point path.
pub fn tmpfs_statfs(mountpoint: &str) -> Option<TmpfsStatfs> {
    let tbl = TMPFS_INSTANCES.lock();
    tbl.get(mountpoint).map(|fs| fs.statfs())
}

/// Create symlink `link_path` → `target`.
pub fn tmpfs_symlink(target: &str, link_full_path: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, link_full_path) {
        return fs.symlink(target, &rel);
    }
    Err(-2)
}

/// Read the target of a symlink at `full_path`.
pub fn tmpfs_readlink(full_path: &str) -> Result<String, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    let mut best_len = 0usize;
    let mut best_mp: Option<&str> = None;
    for mp in tbl.keys() {
        let ms = mp.trim_end_matches('/');
        if (full_path == ms || full_path.starts_with(&alloc::format!("{}/", ms)))
            && ms.len() > best_len
        {
            best_len = ms.len();
            best_mp = Some(mp.as_str());
        }
    }
    if let Some(mp) = best_mp {
        let ms = mp.trim_end_matches('/');
        let rel = if full_path.len() == ms.len() { "/" } else { &full_path[ms.len()..] };
        return tbl.get(mp).unwrap().readlink(rel);
    }
    for fs in tbl.values() {
        if fs.lookup(full_path).is_some() { return fs.readlink(full_path); }
    }
    Err(-2)
}

/// Change permission bits on `full_path`.
pub fn tmpfs_chmod(full_path: &str, mode: u16) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.chmod(&rel, mode);
    }
    Err(-2)
}

/// Change owner/group of `full_path`. 0xFFFF_FFFF = don't change.
pub fn tmpfs_chown(full_path: &str, uid: u32, gid: u32) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some((fs, rel)) = find_instance_and_rel(&mut tbl, full_path) {
        return fs.chown(&rel, uid, gid);
    }
    Err(-2)
}
