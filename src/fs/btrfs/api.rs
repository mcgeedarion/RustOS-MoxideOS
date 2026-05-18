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
use super::mount::{parse_sys_chunk_array, parse_superblock};

pub fn mount(subvol: &str) -> bool {
    let raw = {
        let lba   = 0x10000u64 / 512;
        let count = (4096 / 512) as u32;
        crate::drivers::block::read_sectors_raw(lba, count)
    };
    let Some(sb) = parse_superblock(&raw) else { return false; };
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
    fs.build_chunk_map();
    fs.resolve_fs_tree_root();
    BTRFS_MOUNTS.lock().insert(subvol.to_string(), fs);
    true
}

macro_rules! with_fs {
    ($subvol:expr, $var:ident, $body:expr) => {{
        let mut mounts = BTRFS_MOUNTS.lock();
        let $var = mounts.get_mut($subvol).ok_or(-5isize)?;
        $body
    }};
}

pub fn btrfs_stat(subpath: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    with_fs!("/", fs, fs.stat(subpath))
}

pub fn btrfs_read_all(subpath: &str) -> Result<Vec<u8>, isize> {
    with_fs!("/", fs, fs.read_all(subpath))
}

pub fn btrfs_write_all(subpath: &str, data: &[u8]) -> Result<(), isize> {
    with_fs!("/", fs, fs.write_all(subpath, data))
}

pub fn btrfs_readdir(subpath: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.get("/").ok_or(-5isize)?;
    fs.readdir(subpath)
}

pub fn btrfs_create(subpath: &str, mode: u32) -> Result<(), isize> {
    with_fs!("/", fs, fs.create(subpath, mode))
}

pub fn btrfs_mkdir(subpath: &str, mode: u32) -> Result<(), isize> {
    with_fs!("/", fs, fs.mkdir_op(subpath, mode))
}

pub fn btrfs_unlink(subpath: &str) -> Result<(), isize> {
    with_fs!("/", fs, fs.unlink_op(subpath))
}

pub fn btrfs_rmdir(subpath: &str) -> Result<(), isize> {
    with_fs!("/", fs, fs.rmdir_op(subpath))
}

pub fn btrfs_rename(old: &str, new: &str) -> Result<(), isize> {
    with_fs!("/", fs, fs.rename_op(old, new))
}

pub fn btrfs_link(target: &str, link_path: &str) -> Result<(), isize> {
    with_fs!("/", fs, fs.link_op(target, link_path))
}

pub fn btrfs_symlink(target: &str, link_path: &str) -> Result<(), isize> {
    with_fs!("/", fs, fs.symlink_op(target, link_path))
}

pub fn btrfs_readlink(subpath: &str) -> Result<String, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.get("/").ok_or(-5isize)?;
    fs.read_symlink(subpath).ok_or(-22)
}

pub fn btrfs_chmod(subpath: &str, mode: u32) -> Result<(), isize> {
    with_fs!("/", fs, fs.chmod_op(subpath, mode))
}

pub fn btrfs_chown(subpath: &str, uid: u32, gid: u32) -> Result<(), isize> {
    with_fs!("/", fs, fs.chown_op(subpath, uid, gid))
}

pub fn btrfs_set_times(subpath: &str, atime: u64, mtime: u64) -> Result<(), isize> {
    with_fs!("/", fs, fs.set_times_op(subpath, atime, mtime))
}

pub fn btrfs_truncate(subpath: &str, size: u64) -> Result<(), isize> {
    with_fs!("/", fs, fs.truncate_op(subpath, size))
}

pub fn btrfs_statfs(_subpath: &str) -> Result<crate::fs::vfs_ops::KStatfs, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.get("/").ok_or(-5isize)?;
    Ok(fs.statfs_op())
}

pub fn sync_inode(_subpath: &str) -> Result<(), isize> {
    // Full writeback is triggered on unmount; no-op for now.
    Ok(())
}
