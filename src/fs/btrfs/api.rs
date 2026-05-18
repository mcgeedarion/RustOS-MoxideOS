extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::superblock::*;
use super::tree::*;

pub fn mount() -> bool {
    let sb_raw = {
        let lba   = BTRFS_SUPERBLOCK_OFFSET / 512;
        let count = (BTRFS_SUPERBLOCK_SIZE as u64 + 511) / 512;
        block_read(lba, count as u32)
    };
    if sb_raw.len() < BTRFS_SUPERBLOCK_SIZE { return false; }
    let sb: BtrfsSuperblock = unsafe {
        core::ptr::read_unaligned(sb_raw.as_ptr() as *const BtrfsSuperblock)
    };
    if unsafe { core::ptr::read_unaligned(&sb.magic) } != BTRFS_MAGIC { return false; }

    let mut fs = BtrfsFs::new(sb);

    // Parse sys_chunk_array to bootstrap the chunk map
    let sys_size = unsafe { core::ptr::read_unaligned(&fs.superblock.sys_chunk_array_size) } as usize;
    let sys_arr  = unsafe {
        core::slice::from_raw_parts(fs.superblock.sys_chunk_array.as_ptr(), sys_size.min(BTRFS_SYSTEM_CHUNK_ARRAY_SIZE))
    };
    let mut off = 0usize;
    while off + 17 <= sys_arr.len() {
        let key = BtrfsKey::from_bytes(&sys_arr[off..off+17]);
        off += 17;
        if key.ty == BTRFS_CHUNK_ITEM_KEY {
            let ci_size = core::mem::size_of::<BtrfsChunkItem>();
            if off + ci_size > sys_arr.len() { break; }
            let ci: BtrfsChunkItem = unsafe {
                core::ptr::read_unaligned(sys_arr.as_ptr().add(off) as *const BtrfsChunkItem)
            };
            let logical_start = key.offset;
            let length = unsafe { core::ptr::read_unaligned(&ci.length) };
            fs.chunk_map.push((logical_start, logical_start + length, ci));
            let num_stripes = unsafe { core::ptr::read_unaligned(&ci.num_stripes) } as usize;
            off += ci_size + num_stripes * 32;
        }
    }

    // Resolve fs-tree root via the root tree
    let chunk_root = unsafe { core::ptr::read_unaligned(&fs.superblock.chunk_root) };
    let root_root  = unsafe { core::ptr::read_unaligned(&fs.superblock.root) };
    fs.root_tree_root = root_root;

    let fs_tree_key = BtrfsKey::new(BTRFS_FS_TREE_OBJECTID, BTRFS_ROOT_ITEM_KEY, 0);
    if let Some(ri_data) = fs.btree_search(root_root, &fs_tree_key) {
        if ri_data.len() >= core::mem::size_of::<BtrfsRootItem>() {
            let ri: BtrfsRootItem = unsafe {
                core::ptr::read_unaligned(ri_data.as_ptr() as *const BtrfsRootItem)
            };
            fs.fs_tree_root = unsafe { core::ptr::read_unaligned(&ri.bytenr) };
        }
    }

    if fs.fs_tree_root == 0 { return false; }

    BTRFS_MOUNTS.lock().insert(String::from("/"), fs);
    true
}

fn with_fs<T, F: FnOnce(&BtrfsFs) -> T>(subpath: &str, f: F) -> Result<T, isize> {
    let m = BTRFS_MOUNTS.lock();
    let fs = m.get("/").ok_or(-5isize)?;
    Ok(f(fs))
}

fn with_fs_mut<T, F: FnOnce(&mut BtrfsFs) -> T>(f: F) -> Result<T, isize> {
    let mut m = BTRFS_MOUNTS.lock();
    let fs = m.get_mut("/").ok_or(-5isize)?;
    Ok(f(fs))
}

pub fn btrfs_stat(subpath: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    with_fs(subpath, |fs| {
        let ino   = fs.resolve_path(subpath).ok_or(-2isize)?;
        let inode = fs.read_inode(ino).ok_or(-5isize)?;
        let mode  = unsafe { core::ptr::read_unaligned(&inode.mode) };
        let size  = unsafe { core::ptr::read_unaligned(&inode.size) };
        let uid   = unsafe { core::ptr::read_unaligned(&inode.uid) };
        let gid   = unsafe { core::ptr::read_unaligned(&inode.gid) };
        let mtime = unsafe { core::ptr::read_unaligned(&inode.mtime_sec) };
        let atime = unsafe { core::ptr::read_unaligned(&inode.atime_sec) };
        let ctime = unsafe { core::ptr::read_unaligned(&inode.ctime_sec) };
        Ok(crate::fs::vfs_ops::KStat {
            ino, mode: mode as u32, nlink: 1, uid, gid, size,
            atime, mtime, ctime, blksize: 4096,
            blocks: (size + 511) / 512,
        })
    })?
}

pub fn btrfs_read_all(subpath: &str) -> Result<Vec<u8>, isize> {
    with_fs(subpath, |fs| fs.read_all(subpath))?
}

pub fn btrfs_write_all(subpath: &str, data: &[u8]) -> Result<(), isize> {
    with_fs_mut(|fs| fs.write_all(subpath, data))?
}

pub fn btrfs_readdir(subpath: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
    with_fs(subpath, |fs| fs.readdir(subpath))?
}

pub fn btrfs_create(subpath: &str, mode: u32) -> Result<u64, isize> {
    with_fs_mut(|fs| fs.create(subpath, mode))?
}

pub fn btrfs_mkdir(subpath: &str, mode: u32) -> Result<(), isize> {
    with_fs_mut(|fs| fs.mkdir(subpath, mode))?
}

pub fn btrfs_unlink(subpath: &str) -> Result<(), isize> {
    with_fs_mut(|fs| fs.unlink(subpath))?
}

pub fn btrfs_rmdir(subpath: &str) -> Result<(), isize> {
    with_fs_mut(|fs| fs.unlink(subpath))?
}

pub fn btrfs_rename(src: &str, dst: &str) -> Result<(), isize> {
    with_fs_mut(|fs| fs.rename(src, dst))?
}

pub fn btrfs_link(_src: &str, _dst: &str) -> Result<(), isize> { Err(-1) }

pub fn btrfs_symlink(target: &str, link_path: &str) -> Result<(), isize> {
    with_fs_mut(|fs| fs.symlink(target, link_path))?
}

pub fn btrfs_readlink(subpath: &str) -> Result<String, isize> {
    with_fs(subpath, |fs| fs.readlink(subpath))?
}

pub fn btrfs_chmod(subpath: &str, mode: u32) -> Result<(), isize> {
    with_fs_mut(|fs| fs.chmod(subpath, mode))?
}

pub fn btrfs_chown(subpath: &str, uid: u32, gid: u32) -> Result<(), isize> {
    with_fs_mut(|fs| fs.chown(subpath, uid, gid))?
}

pub fn btrfs_set_times(subpath: &str, atime: u64, mtime: u64) -> Result<(), isize> {
    with_fs_mut(|fs| fs.set_times(subpath, atime, mtime))?
}

pub fn btrfs_truncate(subpath: &str, size: u64) -> Result<(), isize> {
    with_fs_mut(|fs| fs.truncate(subpath, size))?
}

pub fn btrfs_statfs(_subpath: &str) -> Result<crate::fs::vfs_ops::Statfs, isize> {
    with_fs(_subpath, |fs| {
        let total = unsafe { core::ptr::read_unaligned(&fs.superblock.total_bytes) };
        let used  = unsafe { core::ptr::read_unaligned(&fs.superblock.bytes_used) };
        Ok(crate::fs::vfs_ops::Statfs {
            f_type:   0x9123683E,
            f_bsize:  4096,
            f_blocks: total / 4096,
            f_bfree:  (total - used) / 4096,
            f_bavail: (total - used) / 4096,
            f_namelen: 255,
        })
    })?
}

pub fn sync_inode(_subpath: &str) -> Result<(), isize> { Ok(()) }