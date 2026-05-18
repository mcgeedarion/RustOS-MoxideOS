extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::tree::{BtrfsFs, BtrfsKey};
use super::superblock::{BtrfsSuperblock, BtrfsChunkItem, BtrfsRootItem,
    BTRFS_MOUNTS, BTRFS_SUPERBLOCK_OFFSET, BTRFS_SUPERBLOCK_SIZE,
    BTRFS_SYSTEM_CHUNK_ARRAY_SIZE, BTRFS_FS_TREE_OBJECTID,
    BTRFS_ROOT_ITEM_KEY, BTRFS_CHUNK_ITEM_KEY,
    block_read, block_write};

pub fn mount() -> bool {
    let sb_lba     = BTRFS_SUPERBLOCK_OFFSET / 512;
    let sb_sectors = (BTRFS_SUPERBLOCK_SIZE as u64 + 511) / 512;
    let sb_raw     = block_read(sb_lba, sb_sectors as u32);
    if sb_raw.len() < BTRFS_SUPERBLOCK_SIZE { return false; }
    let sb = BtrfsSuperblock::from_bytes(&sb_raw[..BTRFS_SUPERBLOCK_SIZE]);
    if !sb.is_valid() { return false; }
    let chunk_map = parse_sys_chunk_array(&sb);
    let root_tree_root = sb.root;
    let mut fs = BtrfsFs {
        superblock: sb,
        chunk_map,
        root_tree_root,
        fs_tree_root: 0,
        path_cache: BTreeMap::new(),
        alloc_cursor: 0,
    };
    fs.fs_tree_root = match resolve_fs_tree_root(&fs) {
        Some(r) => r,
        None => return false,
    };
    fs.alloc_cursor = fs.superblock.total_bytes;
    BTRFS_MOUNTS.lock().insert(String::from("/"), fs);
    true
}

fn parse_sys_chunk_array(sb: &BtrfsSuperblock) -> Vec<(u64, u64, BtrfsChunkItem)> {
    let mut out = Vec::new();
    let total = sb.sys_chunk_array_size as usize;
    let arr   = &sb.sys_chunk_array[..total.min(BTRFS_SYSTEM_CHUNK_ARRAY_SIZE)];
    let mut pos = 0usize;
    while pos + 17 <= arr.len() {
        let key = BtrfsKey::from_bytes(&arr[pos..pos + 17]);
        pos += 17;
        if key.ty != BTRFS_CHUNK_ITEM_KEY { break; }
        if pos + 80 > arr.len() { break; }
        let chunk = BtrfsChunkItem::from_bytes(&arr[pos..pos + 80]);
        pos += 80;
        let start = key.offset;
        let end   = start + chunk.length;
        out.push((start, end, chunk));
    }
    out
}

fn resolve_fs_tree_root(fs: &BtrfsFs) -> Option<u64> {
    let results = fs.btree_search(fs.root_tree_root, |k| {
        if k.objectid != BTRFS_FS_TREE_OBJECTID { return k.objectid.cmp(&BTRFS_FS_TREE_OBJECTID); }
        if k.ty != BTRFS_ROOT_ITEM_KEY { return k.ty.cmp(&BTRFS_ROOT_ITEM_KEY); }
        core::cmp::Ordering::Equal
    });
    let best = results.into_iter().max_by_key(|(k, _)| k.offset)?;
    if best.1.len() < 184 { return None; }
    let ri = BtrfsRootItem::from_bytes(&best.1);
    Some(ri.bytenr)
}

fn btrfs_name_hash(name: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME:  u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    for &b in name { h ^= b as u64; h = h.wrapping_mul(FNV_PRIME); }
    h
}

fn align_up(v: u64, align: u64) -> u64 { (v + align - 1) & !(align - 1) }

fn split_path(path: &str) -> Result<(&str, &str), isize> {
    let path = path.trim_end_matches('/');
    if path.is_empty() { return Err(-22); }
    match path.rfind('/') {
        Some(0) => Ok(("/", &path[1..])),
        Some(i) => Ok((&path[..i], &path[i + 1..])),
        None    => Err(-22),
    }
}

pub fn btrfs_stat(subpath: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.stat(subpath)
}
pub fn btrfs_read_all(subpath: &str) -> Result<Vec<u8>, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.read_all(subpath)
}
pub fn btrfs_write_all(subpath: &str, data: &[u8]) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.write_all(subpath, data)
}
pub fn btrfs_readdir(subpath: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.readdir(subpath)
}
pub fn btrfs_create(subpath: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.create(subpath)
}
pub fn btrfs_mkdir(subpath: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.mkdir(subpath)
}
pub fn btrfs_unlink(subpath: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.unlink(subpath)
}
pub fn btrfs_rmdir(subpath: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.rmdir(subpath)
}
pub fn btrfs_rename(old: &str, new: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.rename(old, new)
}
pub fn btrfs_link(existing: &str, new: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.link(existing, new)
}
pub fn btrfs_symlink(target: &str, link_path: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.symlink(target, link_path)
}
pub fn btrfs_readlink(subpath: &str) -> Result<String, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.readlink(subpath)
}
pub fn btrfs_chmod(subpath: &str, mode: u16) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.chmod(subpath, mode)
}
pub fn btrfs_chown(subpath: &str, uid: u32, gid: u32) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.chown(subpath, uid, gid)
}
pub fn btrfs_set_times(subpath: &str, atime_ns: u64, mtime_ns: u64) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.set_times(subpath, atime_ns, mtime_ns)
}
pub fn btrfs_truncate(subpath: &str, len: usize) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.truncate(subpath, len)
}
pub fn btrfs_statfs() -> crate::fs::vfs_ops::KStatfs {
    let mounts = BTRFS_MOUNTS.lock();
    if let Some(fs) = mounts.values().next() {
        fs.statfs()
    } else {
        crate::fs::vfs_ops::KStatfs::default()
    }
}
pub fn sync_inode(_path: &str) { /* write-through; nothing to flush */ }
