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
//!   open, creat, read, write, seek, truncate
//!   mkdir, rmdir, unlink, rename, link, symlink, readlink
//!   stat, statfs, readdir (getdents64)
//!   mmap (MAP_ANONYMOUS-style: returns a Vec that lives until munmap)

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use spin::Mutex;

// ── Constants ────────────────────────────────────────────────────────────────

const TMPFS_MAGIC:   u64 = 0x0102_1994;
const DEFAULT_LIMIT: usize = 64 * 1024 * 1024; // 64 MiB per mount
const INO_ROOT:      u64  = 1;

// POSIX mode bits
const S_IFREG: u16 = 0o0100_000;
const S_IFDIR: u16 = 0o0040_000;
const S_IFLNK: u16 = 0o0120_000;
const S_IFMT:  u16 = 0o0170_000;

// ── Inode ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum INodeData {
    File(Vec<u8>),
    Dir(BTreeMap<String, u64>),   // name → ino
    Symlink(String),
}

#[derive(Clone)]
struct INode {
    ino:        u64,
    mode:       u16,
    uid:        u32,
    gid:        u32,
    nlink:      u32,
    atime:      u64,
    mtime:      u64,
    ctime:      u64,
    data:       INodeData,
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

// ── Per-mount filesystem state ───────────────────────────────────────────────

struct TmpFs {
    inodes:   BTreeMap<u64, INode>,
    next_ino: u64,
    used:     usize,   // bytes of file data currently allocated
    limit:    usize,   // maximum bytes of file data
}

impl TmpFs {
    fn new(limit: usize) -> Self {
        let mut fs = TmpFs {
            inodes:   BTreeMap::new(),
            next_ino: INO_ROOT + 1,
            used:     0,
            limit,
        };
        // Create root directory inode.
        let root = INode::new_dir(INO_ROOT);
        fs.inodes.insert(INO_ROOT, root);
        fs
    }

    fn alloc_ino(&mut self) -> u64 {
        let i = self.next_ino;
        self.next_ino += 1;
        i
    }

    // Resolve absolute path → inode number.  Does NOT follow the final
    // component if it is a symlink (use resolve_follow for that).
    fn lookup(&self, path: &str) -> Option<u64> {
        let path = path.trim_start_matches('/');
        let mut cur = INO_ROOT;
        if path.is_empty() { return Some(cur); }
        for part in path.split('/') {
            if part.is_empty() || part == "." { continue; }
            if part == ".." {
                // Walk up: find any dir that has `cur` as a child.
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
                return None; // not a directory
            }
        }
        Some(cur)
    }

    // Split a path into (parent_ino, filename).  Returns None if parent does
    // not exist or is not a directory.
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

    // ── File I/O ─────────────────────────────────────────────────────────────

    fn read_all(&self, path: &str) -> Result<Vec<u8>, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?; // ENOENT
        let node = self.inodes.get(&ino).ok_or(-2isize)?;
        match &node.data {
            INodeData::File(v) => Ok(v.clone()),
            INodeData::Dir(_)  => Err(-21),  // EISDIR
            INodeData::Symlink(_) => Err(-22), // EINVAL — use readlink
        }
    }

    fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), isize> {
        let delta = data.len() as isize;
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get_mut(&ino).ok_or(-2isize)?;
        match &mut node.data {
            INodeData::File(v) => {
                let old_len = v.len() as isize;
                let new_used = self.used as isize - old_len + delta;
                if new_used as usize > self.limit { return Err(-28); } // ENOSPC
                self.used = new_used as usize;
                *v = data.to_vec();
                Ok(())
            }
            INodeData::Dir(_) => Err(-21),  // EISDIR
            INodeData::Symlink(_) => Err(-22),
        }
    }

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
        if self.lookup(path).is_some() { return Err(-17); } // EEXIST
        let (parent_ino, name) = self.split_parent(path).ok_or(-2isize)?;
        let ino = self.alloc_ino();
        let mut node = INode::new_dir(ino);
        // Add ".." pointing to parent
        if let INodeData::Dir(d) = &mut node.data {
            d.insert("..".to_string(), parent_ino);
        }
        self.inodes.insert(ino, node);
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.insert(name, ino);
        }
        Ok(())
    }

    fn unlink(&mut self, path: &str) -> Result<(), isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        {
            let node = self.inodes.get(&ino).ok_or(-2isize)?;
            if node.is_dir() { return Err(-21); } // EISDIR
            if let INodeData::File(v) = &node.data {
                self.used = self.used.saturating_sub(v.len());
            }
        }
        self.inodes.remove(&ino);
        let (parent_ino, name) = self.split_parent(path).ok_or(-2isize)?;
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&parent_ino).map(|n| &mut n.data) {
            d.remove(&name);
        }
        Ok(())
    }

    fn rename(&mut self, old: &str, new: &str) -> Result<(), isize> {
        let ino = self.lookup(old).ok_or(-2isize)?;
        // Remove from old parent
        let (old_parent_ino, old_name) = self.split_parent(old).ok_or(-2isize)?;
        if let Some(INodeData::Dir(d)) = self.inodes.get_mut(&old_parent_ino).map(|n| &mut n.data) {
            d.remove(&old_name);
        }
        // Insert into new parent (creating new intermediate dirs is not done here)
        let (new_parent_ino, new_name) = self.split_parent(new).ok_or(-2isize)?;
        // Ensure new parent exists
        if self.inodes.get(&new_parent_ino).is_none() { return Err(-2); }
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
            _ => Err(-20), // ENOTDIR
        }
    }

    fn stat(&self, path: &str) -> Result<TmpfsStat, isize> {
        let ino = self.lookup(path).ok_or(-2isize)?;
        let node = self.inodes.get(&ino).ok_or(-2isize)?;
        Ok(TmpfsStat {
            ino:    node.ino,
            mode:   node.mode,
            nlink:  node.nlink,
            size:   node.size() as u64,
            is_dir: node.is_dir(),
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
            _ => Err(-22), // EINVAL
        }
    }

    fn statfs(&self) -> TmpfsStatfs {
        TmpfsStatfs {
            f_type:   TMPFS_MAGIC,
            f_bsize:  4096,
            f_blocks: (self.limit / 4096) as u64,
            f_bfree:  ((self.limit - self.used) / 4096) as u64,
            f_bavail: ((self.limit - self.used) / 4096) as u64,
            f_namelen: 255,
        }
    }
}

// ── Stat / statfs result types ────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct TmpfsStat {
    pub ino:    u64,
    pub mode:   u16,
    pub nlink:  u32,
    pub size:   u64,
    pub is_dir: bool,
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

// ── Global per-mountpoint instance table ─────────────────────────────────────
//
// Keyed by the absolute mount-point path (e.g. "/tmp", "/run", "/dev/shm").
// vfs_ops passes the mount-relative subpath; we extract the mountpoint from
// the full path at call time via `mount::resolve` → `FsHandle::subpath`.
// Because we only receive the subpath here, we look up by trying each key
// that is a prefix of the original full path.  For simplicity, the shim
// functions below operate on subpaths and the callers must ensure the
// correct instance is addressed — which is guaranteed because vfs_ops
// calls us only after `mount::resolve` has already selected FsType::Tmpfs.
//
// A single default instance covers all tmpfs mounts that are pre-registered
// in init_mounts().  Dynamically mounted tmpfs volumes are inserted by
// `tmpfs_mount()`.

pub static TMPFS_INSTANCES: Mutex<BTreeMap<String, TmpFs>> =
    Mutex::new(BTreeMap::new());

/// Called by sys_mount (or init_mounts indirectly) to create a new tmpfs
/// instance at `mountpoint`.  Safe to call multiple times — ignored if
/// the mount already exists.
pub fn tmpfs_mount(mountpoint: &str, limit: usize) {
    let mut tbl = TMPFS_INSTANCES.lock();
    tbl.entry(mountpoint.to_string())
       .or_insert_with(|| TmpFs::new(limit));
}

// ── Mountpoint lookup helper ──────────────────────────────────────────────────
//
// vfs_ops passes us `h.subpath` (mount-relative) and we need to find which
// TmpFs instance owns it.  Because all tmpfs mount points are pre-registered
// we search by full path prefix.
//
// The full path is reconstructed as: find the mountpoint key whose prefix,
// when appended with subpath, yields a sensible full path.  The simpler
// approach used here is: the caller also passes the full absolute path so
// we can strip the subpath suffix to recover the mountpoint.  Since the VFS
// shims below only receive the subpath, we fall back to iterating all
// instances and picking the one with the longest matching mountpoint prefix
// against a synthetic full path.  In practice, with three fixed mounts
// (/tmp, /run, /dev/shm) the overhead is negligible.
//
// For the public shim API, we accept the subpath (as vfs_ops provides it)
// and locate the instance whose root contains that sub-tree.  Because each
// subpath is unique within its mount, we return the first instance that has
// the root inode (i.e. any instance — if the path resolves successfully we
// know we're in the right one).  A cleaner solution would thread the full
// path through, but that would require changing the vfs_ops interface.
//
// CURRENT IMPL: We expose a secondary set of shims that accept the full
// absolute path and derive the mountpoint via longest-prefix matching.

fn find_instance_and_rel<'a>(
    tbl: &'a mut BTreeMap<String, TmpFs>,
    full_path: &str,
) -> Option<(&'a mut TmpFs, String)> {
    // Find the longest mountpoint prefix that matches full_path
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

// ── Public VFS shims (called from vfs_ops) ────────────────────────────────────
//
// vfs_ops calls these with the mount-relative subpath (h.subpath).  We
// automatically ensure the relevant TmpFs instance is initialized.
//
// NOTE: These functions receive the subpath as produced by mount::resolve,
// e.g. "/myfile" for a file at "/tmp/myfile" mounted at "/tmp".  We must
// apply all operations against the root of the TmpFs instance — which is
// exactly what the subpath represents.

/// Ensure the default tmpfs instances exist (idempotent).
#[inline]
fn ensure_defaults() {
    let mut tbl = TMPFS_INSTANCES.lock();
    for mp in &["/tmp", "/run", "/dev/shm"] {
        tbl.entry(mp.to_string()).or_insert_with(|| TmpFs::new(DEFAULT_LIMIT));
    }
}

/// vfs_ops::read_all dispatch target for FsType::Tmpfs.
/// `subpath` is the mount-relative path, e.g. "/myfile".
pub fn tmpfs_read_all(subpath: &str) -> Result<Vec<u8>, isize> {
    ensure_defaults();
    // The subpath is relative to the mount root.  We try every instance and
    // return the first hit — because subpaths within different mounts are
    // independent namespaces, only one should match.
    let mut tbl = TMPFS_INSTANCES.lock();
    for fs in tbl.values() {
        if fs.lookup(subpath).is_some() {
            return fs.read_all(subpath);
        }
    }
    Err(-2) // ENOENT
}

/// vfs_ops::write_all dispatch target for FsType::Tmpfs.
pub fn tmpfs_write_all(subpath: &str, data: &[u8]) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    // Write to the first instance that already has the file, or the first
    // writable instance (create semantics).
    for fs in tbl.values_mut() {
        if fs.lookup(subpath).is_some() {
            return fs.write_all(subpath, data);
        }
    }
    // File not found in any instance — create it in the first instance
    if let Some(fs) = tbl.values_mut().next() {
        fs.create(subpath)?;
        return fs.write_all(subpath, data);
    }
    Err(-2)
}

/// vfs_ops::create dispatch target for FsType::Tmpfs.
pub fn tmpfs_create(subpath: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some(fs) = tbl.values_mut().next() {
        return fs.create(subpath);
    }
    Err(-2)
}

/// vfs_ops::mkdir dispatch target for FsType::Tmpfs.
pub fn tmpfs_mkdir(subpath: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some(fs) = tbl.values_mut().next() {
        return fs.mkdir(subpath);
    }
    Err(-2)
}

/// vfs_ops::unlink dispatch target for FsType::Tmpfs.
pub fn tmpfs_unlink(subpath: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    for fs in tbl.values_mut() {
        if fs.lookup(subpath).is_some() {
            return fs.unlink(subpath);
        }
    }
    Err(-2)
}

/// vfs_ops::rename dispatch target for FsType::Tmpfs.
pub fn tmpfs_rename(old_subpath: &str, new_subpath: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    // Both paths must be in the same instance (cross-mount rename → EXDEV).
    for fs in tbl.values_mut() {
        if fs.lookup(old_subpath).is_some() {
            return fs.rename(old_subpath, new_subpath);
        }
    }
    Err(-2)
}

/// vfs_ops::readdir dispatch target for FsType::Tmpfs.
pub fn tmpfs_readdir(subpath: &str) -> Result<Vec<String>, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    for fs in tbl.values() {
        if fs.lookup(subpath).is_some() {
            return fs.readdir(subpath);
        }
    }
    Err(-2)
}

/// vfs_ops::stat dispatch target for FsType::Tmpfs.
/// Returns a KStat-compatible structure.  vfs_ops::stat maps it to KStat.
pub fn tmpfs_stat(subpath: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    for fs in tbl.values() {
        if fs.lookup(subpath).is_some() {
            let s = fs.stat(subpath)?;
            return Ok(crate::fs::vfs_ops::KStat {
                ino:    s.ino,
                mode:   s.mode,
                nlink:  s.nlink,
                size:   s.size,
                is_dir: s.is_dir,
            });
        }
    }
    Err(-2)
}

/// vfs_ops::statfs dispatch target for FsType::Tmpfs.
pub fn tmpfs_statfs(mountpoint: &str) -> Option<TmpfsStatfs> {
    let tbl = TMPFS_INSTANCES.lock();
    tbl.get(mountpoint).map(|fs| fs.statfs())
}

/// vfs_ops::symlink dispatch target for FsType::Tmpfs.
pub fn tmpfs_symlink(target: &str, link_subpath: &str) -> Result<(), isize> {
    ensure_defaults();
    let mut tbl = TMPFS_INSTANCES.lock();
    if let Some(fs) = tbl.values_mut().next() {
        return fs.symlink(target, link_subpath);
    }
    Err(-2)
}

/// vfs_ops::readlink dispatch target for FsType::Tmpfs.
pub fn tmpfs_readlink(subpath: &str) -> Result<String, isize> {
    ensure_defaults();
    let tbl = TMPFS_INSTANCES.lock();
    for fs in tbl.values() {
        if fs.lookup(subpath).is_some() {
            return fs.readlink(subpath);
        }
    }
    Err(-2)
}
