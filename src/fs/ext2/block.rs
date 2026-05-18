extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;
use super::superblock::Ext2Fs;

pub fn read_block<'a>(fs: &'a Ext2Fs, blkno: u32) -> Option<&'a [u8]> {
    fs.block_slice(blkno)
}
pub fn write_block<'a>(fs: &'a mut Ext2Fs, blkno: u32) -> Option<&'a mut [u8]> {
    fs.block_slice_mut(blkno)
}
