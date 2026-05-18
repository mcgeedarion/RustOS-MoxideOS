extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::superblock::{BtrfsSuperblock, BtrfsChunkItem};

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub ty:       u8,
    pub offset:   u64,
}

impl BtrfsKey {
    pub fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        BtrfsKey { objectid, ty, offset }
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsHeader {
    pub csum:       [u8; 32],
    pub fsid:       [u8; 16],
    pub bytenr:     u64,
    pub flags:      u64,
    pub chunk_tree_uuid: [u8; 16],
    pub generation: u64,
    pub owner:      u64,
    pub nritems:    u32,
    pub level:      u8,
}

#[derive(Clone, Debug)]
pub struct BtrfsItem {
    pub key:    BtrfsKey,
    pub offset: u32,
    pub size:   u32,
}

#[derive(Clone, Debug)]
pub struct BtrfsKeyPtr {
    pub key:        BtrfsKey,
    pub blockptr:   u64,
    pub generation: u64,
}

#[derive(Clone, Debug)]
pub struct BtrfsFs {
    /// Parsed superblock.
    pub superblock: BtrfsSuperblock,
    /// Logical → physical byte translation table built from chunk tree.
    pub chunk_map: Vec<(u64, u64, BtrfsChunkItem)>,
    /// Root-tree root node logical byte offset.
    pub root_tree_root: u64,
    /// FS-tree root node logical byte offset (default subvolume).
    pub fs_tree_root: u64,
    /// Cache: path → inode number.
    pub path_cache: BTreeMap<String, u64>,
    /// Next logical byte offset for CoW allocation (monotonically increasing).
    pub alloc_cursor: u64,
}
