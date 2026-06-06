//! Public VFS entry-points for ext2.
//! Source lines 1035–end of the original ext2.rs monolith.
extern crate alloc;
use alloc::{vec::Vec, string::String};
use super::superblock::{Ext2Stat, Ext2Statfs, Ext2Fs, Superblock, BgDesc, FS};
use super::inode::Ext2DirEntry;

pub fn mount() -> bool {
    // Read superblock from sector 2 (offset 1024 bytes)
    let raw = crate::drivers::block::read_sectors_vec(2, 2);
    let sb  = match Superblock::from_bytes(&raw) {
        Some(s) => s,
        None    => return false,
    };
    let block_size  = sb.block_size();
    let lba_offset  = 0u64;
    // Read block group descriptor table
    let bgdt_block  = sb.first_data_block + 1;
    let n_groups    = ((sb.blocks_count + sb.blocks_per_group - 1)
                      / sb.blocks_per_group) as usize;
    let gd_per_block = block_size / 32;
    let bgdt_blocks  = (n_groups + gd_per_block - 1) / gd_per_block;
    let lba_bgdt     = lba_offset + (bgdt_block as u64 * block_size as u64 / 512);
    let raw_bgdt = crate::drivers::block::read_sectors_vec(
        lba_bgdt, (bgdt_blocks * block_size / 512) as u32,
    );
    let mut group_descs = Vec::new();
    for i in 0..n_groups {
        let off = i * 32;
        if off + 32 > raw_bgdt.len() { break; }
        group_descs.push(BgDesc::from_bytes(&raw_bgdt[off..off + 32]));
    }
    *FS.lock() = Some(Ext2Fs { sb, group_descs, block_size, lba_offset });
    true
}

fn with_fs<T, F: FnOnce(&Ext2Fs) -> T>(f: F) -> Result<T, isize> {
    let guard = FS.lock();
    match &*guard {
        Some(fs) => Ok(f(fs)),
        None     => Err(-19),
    }
}

fn with_fs_mut<T, F: FnOnce(&mut Ext2Fs) -> T>(f: F) -> Result<T, isize> {
    let mut guard = FS.lock();
    match &mut *guard {
        Some(fs) => Ok(f(fs)),
        None     => Err(-19),
    }
}

pub fn sys_stat(path: &str) -> Result<Ext2Stat, i32> {
    with_fs(|fs| fs.do_stat(path, true))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_lstat(path: &str) -> Result<Ext2Stat, i32> {
    with_fs(|fs| fs.do_stat(path, false))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_statfs(_path: &str) -> Result<Ext2Statfs, i32> {
    with_fs(|fs| Ok(fs.statfs()))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn readdir(path: &str) -> Result<Vec<Ext2DirEntry>, i32> {
    with_fs(|fs| fs.do_readdir(path))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_readlink(path: &str) -> Result<String, i32> {
    with_fs(|fs| fs.do_readlink(path))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_truncate(path: &str, len: u64) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_truncate(path, len))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_link(existing: &str, new: &str) -> Result<(), i32> {
    let new = new.to_string();
    with_fs_mut(move |fs| fs.do_link(existing, &new))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_mkdir(path: &str, mode: u16) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_mkdir(path, mode))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_rmdir(path: &str) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_rmdir(path))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_unlink(path: &str) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_unlink(path))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_rename(old: &str, new: &str) -> Result<(), i32> {
    let new = new.to_string();
    with_fs_mut(move |fs| fs.do_rename(old, &new))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_symlink(target: &str, path: &str) -> Result<(), i32> {
    let target = target.to_string();
    with_fs_mut(move |fs| fs.do_symlink(&target, path))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_chmod(path: &str, mode: u16) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_chmod(path, mode))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn sys_chown(path: &str, uid: u32, gid: u32) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_chown(path, uid, gid))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn set_times(path: &str, atime_ns: u64, mtime_ns: u64) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_set_times(path, atime_ns, mtime_ns))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}

pub fn read_file(path: &str) -> Result<Vec<u8>, i32> {
    with_fs(|fs| {
        let ino   = fs.resolve_path(path).ok_or(-2isize)?;
        let inode = fs.read_inode(ino).ok_or(-2isize)?;
        Ok(fs.read_inode_data(&inode))
    })
    .unwrap_or(Err(-2))
    .map_err(|e| e as i32)
}

pub fn write_file(path: &str, data: &[u8]) -> Result<(), i32> {
    let data = data.to_vec();
    with_fs_mut(move |fs| {
        let ino   = fs.resolve_path(path).ok_or(-2isize)?;
        let mut inode = fs.read_inode(ino).ok_or(-2isize)?;
        fs.write_block_data(&mut inode, ino, &data)?;
        fs.write_inode(ino, &inode)
    })
    .unwrap_or(Err(-2))
    .map_err(|e| e as i32)
}

pub fn create_file(path: &str, mode: u16) -> Result<(), i32> {
    with_fs_mut(|fs| fs.do_create_file(path, mode))
        .unwrap_or(Err(-2))
        .map_err(|e| e as i32)
}
// ===== GUESS: short alias =====
/// GUESS: alias of `sys_stat` for callers using `ext2::stat`.
#[inline]
pub fn stat(path: &str) -> Result<Ext2Stat, i32> { sys_stat(path) }
