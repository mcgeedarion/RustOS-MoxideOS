extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;
use super::superblock::{Ext2Fs, Ext2Stat};

pub fn lookup(fs: &Ext2Fs, path: &str) -> Option<u32> { fs.lookup_path(path) }
