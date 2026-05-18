extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::tree::BtrfsKey;
use super::superblock::*;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct BtrfsDirItem {
    pub location:  BtrfsKey,
    pub transid:   u64,
    pub data_len:  u16,
    pub name_len:  u16,
    pub file_type: u8,
}

impl BtrfsDirItem {
    pub fn from_bytes(b: &[u8]) -> Self {
        BtrfsDirItem {
            location:  BtrfsKey::from_bytes(&b[0..17]),
            transid:   u64::from_le_bytes(b[17..25].try_into().unwrap()),
            data_len:  u16::from_le_bytes(b[25..27].try_into().unwrap()),
            name_len:  u16::from_le_bytes(b[27..29].try_into().unwrap()),
            file_type: b[29],
        }
    }
}
