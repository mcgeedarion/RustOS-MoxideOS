extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::superblock::{BtrfsSuperblock, BtrfsChunkItem, BTRFS_MOUNTS};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub ty:       u8,
    pub offset:   u64,
}

impl BtrfsKey {
    pub fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        BtrfsKey { objectid, ty, offset }
    }
    pub fn from_bytes(b: &[u8]) -> Self {
        BtrfsKey {
            objectid: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            ty:       b[8],
            offset:   u64::from_le_bytes(b[9..17].try_into().unwrap()),
        }
    }
    pub fn to_bytes(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0..8].copy_from_slice(&self.objectid.to_le_bytes());
        out[8] = self.ty;
        out[9..17].copy_from_slice(&self.offset.to_le_bytes());
        out
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BtrfsHeader {
    csum:       [u8; 32],
    fsid:       [u8; 16],
    bytenr:     u64,
    flags:      u64,
    chunk_tree_uuid: [u8; 16],
    generation: u64,
    owner:      u64,
    nritems:    u32,
    level:      u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BtrfsItem {
    key:    [u8; 17],
    offset: u32,
    size:   u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BtrfsKeyPtr {
    key:        [u8; 17],
    blockptr:   u64,
    generation: u64,
}

pub struct BtrfsFs {
    pub superblock:   BtrfsSuperblock,
    pub chunk_map:    Vec<(u64, u64, BtrfsChunkItem)>,
    pub root_tree_root: u64,
    pub fs_tree_root:   u64,
    pub path_cache:   BTreeMap<String, u64>,
    pub alloc_cursor: u64,
}