//! Public VFS entry-points: mount(), btrfs_stat(), btrfs_read_all() …
//! Source lines 1240–end of the original btrfs.rs monolith.
extern crate alloc;
use super::superblock::{BtrfsFs, BtrfsSuperblock, BTRFS_MOUNTS};
use alloc::string::String;
use alloc::vec::Vec;

pub fn mount(subpath: &str) -> Option<()> {
    // Read superblock at offset 0x10000 (sector 128)
    let raw = crate::drivers::block::read_sectors_vec(128, 8);
    let sb = BtrfsSuperblock::from_bytes(&raw)?;

    // Parse sys_chunk_array to bootstrap the chunk map
    let chunk_map = parse_sys_chunk_array(&sb)?;

    // Construct a temporary BtrfsFs to search the chunk tree
    let mut fs = BtrfsFs {
        superblock: sb.clone(),
        chunk_map: chunk_map.clone(),
        root_tree_root: sb.root,
        fs_tree_root: 0,
        path_cache: alloc::collections::BTreeMap::new(),
        alloc_cursor: sb.total_bytes,
    };

    // Find the FS tree root via the root tree
    fs.fs_tree_root = resolve_fs_tree_root(&fs).unwrap_or(0);
    if fs.fs_tree_root == 0 {
        return None;
    }

    BTRFS_MOUNTS.lock().insert(subpath.to_string(), fs);
    Some(())
}

fn parse_sys_chunk_array(
    sb: &BtrfsSuperblock,
) -> Option<alloc::vec::Vec<(u64, u64, super::superblock::BtrfsChunkItem)>> {
    use super::superblock::{BtrfsChunkItem, BtrfsKey};
    let arr = &sb.sys_chunk_array[..sb.sys_chunk_array_size as usize];
    let mut map = alloc::vec::Vec::new();
    let mut off = 0usize;
    while off + 17 <= arr.len() {
        let key = BtrfsKey::from_bytes(&arr[off..off + 17]);
        off += 17;
        if key.ty != 228 {
            break;
        } // BTRFS_CHUNK_ITEM_KEY
        let Some(chunk) = BtrfsChunkItem::from_bytes(&arr[off..]) else {
            break;
        };
        let stripe_size = 80 + chunk.num_stripes as usize * 64;
        let logical_end = key.offset + chunk.length;
        map.push((key.offset, logical_end, chunk));
        off += stripe_size;
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

fn resolve_fs_tree_root(fs: &BtrfsFs) -> Option<u64> {
    use super::superblock::{BtrfsKey, BtrfsRootItem, BTRFS_FS_TREE_OBJECTID, BTRFS_ROOT_ITEM_KEY};
    const BTRFS_FS_TREE_OBJECTID: u64 = 5;
    const BTRFS_ROOT_ITEM_KEY: u8 = 132;
    let key = BtrfsKey::new(BTRFS_FS_TREE_OBJECTID, BTRFS_ROOT_ITEM_KEY, 0);
    let data = fs.lookup_item(fs.root_tree_root, key)?;
    let ri = BtrfsRootItem::from_bytes(&data)?;
    Some(ri.bytenr)
}

fn with_fs<T, F: FnOnce(&BtrfsFs) -> T>(subpath: &str, f: F) -> Result<T, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.get(subpath).ok_or(-19isize)?;
    Ok(f(fs))
}

fn with_fs_mut<T, F: FnOnce(&mut BtrfsFs) -> T>(subpath: &str, f: F) -> Result<T, isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.get_mut(subpath).ok_or(-19isize)?;
    Ok(f(fs))
}

fn mount_for(path: &str) -> &'static str {
    "/"
} // single-mount stub

pub fn btrfs_stat(path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    with_fs(mount_for(path), |fs| fs.stat(path))?
}

pub fn btrfs_read_all(path: &str) -> Result<Vec<u8>, isize> {
    with_fs(mount_for(path), |fs| fs.read_all(path))?
}

pub fn btrfs_write_all(path: &str, data: &[u8]) -> Result<(), isize> {
    let data = data.to_vec();
    with_fs_mut(mount_for(path), move |fs| fs.write_all(path, &data))?
}

pub fn btrfs_readdir(path: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
    with_fs(mount_for(path), |fs| fs.readdir(path))?
}

pub fn btrfs_create(path: &str) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| fs.create(path))?
}

pub fn btrfs_mkdir(path: &str) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| fs.mkdir(path))?
}

pub fn btrfs_unlink(path: &str) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| fs.unlink(path))?
}

pub fn btrfs_rmdir(path: &str) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| fs.rmdir(path))?
}

pub fn btrfs_rename(old: &str, new: &str) -> Result<(), isize> {
    let new = new.to_string();
    with_fs_mut(mount_for(old), move |fs| fs.rename(old, &new))?
}

pub fn btrfs_link(existing: &str, new: &str) -> Result<(), isize> {
    let new = new.to_string();
    with_fs_mut(mount_for(existing), move |fs| fs.link(existing, &new))?
}

pub fn btrfs_symlink(target: &str, path: &str) -> Result<(), isize> {
    let target = target.to_string();
    with_fs_mut(mount_for(path), move |fs| fs.symlink(&target, path))?
}

pub fn btrfs_readlink(path: &str) -> Result<String, isize> {
    with_fs(mount_for(path), |fs| fs.readlink(path))?
}

pub fn btrfs_chmod(path: &str, mode: u32) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| fs.chmod(path, mode))?
}

pub fn btrfs_chown(path: &str, uid: u32, gid: u32) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| fs.chown(path, uid, gid))?
}

pub fn btrfs_set_times(path: &str, atime_sec: u64, mtime_sec: u64) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| {
        fs.set_times(path, atime_sec, mtime_sec)
    })?
}

pub fn btrfs_truncate(path: &str, new_len: u64) -> Result<(), isize> {
    with_fs_mut(mount_for(path), |fs| fs.truncate(path, new_len))?
}

pub fn btrfs_statfs(path: &str) -> Result<crate::fs::vfs_ops::KStatfs, isize> {
    with_fs(mount_for(path), |fs| Ok(fs.statfs()))?
}

pub fn sync_inode(path: &str) -> Result<(), isize> {
    // No-op: all writes are synchronous in this driver
    Ok(())
}
