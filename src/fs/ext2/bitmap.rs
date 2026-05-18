extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;
use super::superblock::{Ext2Fs, ENOSPC};

pub fn alloc_block(fs: &mut Ext2Fs) -> Result<u32, i32> { fs.alloc_block() }
pub fn alloc_inode(fs: &mut Ext2Fs) -> Result<u32, i32> { fs.alloc_inode() }
pub fn free_block(fs: &mut Ext2Fs, blkno: u32) { fs.free_block(blkno) }
pub fn free_inode(fs: &mut Ext2Fs, ino: u32) { fs.free_inode(ino) }
