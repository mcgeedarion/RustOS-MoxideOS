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
                // For simplicity, scan; a real impl would keep a parent link.
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
            let dir_ino = self.inodes.get(&cur)?;
            if let INodeData::Dir(d) = &dir_ino.data {
                cur = *d.get(part)?;
         