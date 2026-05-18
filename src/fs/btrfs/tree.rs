extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::superblock::{BtrfsChunkItem, BtrfsSuperblock, BTRFS_MOUNTS,
    BTRFS_NODE_LEAF, BTRFS_NODE_INTERNAL, BTRFS_MAX_LEAF_ITEMS,
    block_read};

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub ty:       u8,
    pub offset:   u64,
}

impl BtrfsKey {
    pub fn from_bytes(b: &[u8]) -> Self {
        BtrfsKey {
            objectid: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            ty:       b[8],
            offset:   u64::from_le_bytes(b[9..17].try_into().unwrap()),
        }
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

impl BtrfsHeader {
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut csum = [0u8; 32]; csum.copy_from_slice(&b[0..32]);
        let mut fsid = [0u8; 16]; fsid.copy_from_slice(&b[32..48]);
        let mut chunk_tree_uuid = [0u8; 16]; chunk_tree_uuid.copy_from_slice(&b[64..80]);
        BtrfsHeader {
            csum, fsid,
            bytenr:     u64::from_le_bytes(b[48..56].try_into().unwrap()),
            flags:      u64::from_le_bytes(b[56..64].try_into().unwrap()),
            chunk_tree_uuid,
            generation: u64::from_le_bytes(b[80..88].try_into().unwrap()),
            owner:      u64::from_le_bytes(b[88..96].try_into().unwrap()),
            nritems:    u32::from_le_bytes(b[96..100].try_into().unwrap()),
            level:      b[100],
        }
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsItem {
    pub key:      BtrfsKey,
    pub offset:   u32,
    pub size:     u32,
}

impl BtrfsItem {
    pub fn from_bytes(b: &[u8]) -> Self {
        BtrfsItem {
            key:    BtrfsKey::from_bytes(&b[0..17]),
            offset: u32::from_le_bytes(b[17..21].try_into().unwrap()),
            size:   u32::from_le_bytes(b[21..25].try_into().unwrap()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsKeyPtr {
    pub key:        BtrfsKey,
    pub blockptr:   u64,
    pub generation: u64,
}

impl BtrfsKeyPtr {
    pub fn from_bytes(b: &[u8]) -> Self {
        BtrfsKeyPtr {
            key:        BtrfsKey::from_bytes(&b[0..17]),
            blockptr:   u64::from_le_bytes(b[17..25].try_into().unwrap()),
            generation: u64::from_le_bytes(b[25..33].try_into().unwrap()),
        }
    }
}

pub struct BtrfsFs {
    pub superblock:     BtrfsSuperblock,
    pub chunk_map:      Vec<(u64, u64, BtrfsChunkItem)>,
    pub root_tree_root: u64,
    pub fs_tree_root:   u64,
    pub path_cache:     BTreeMap<String, u64>,
    pub alloc_cursor:   u64,
}

impl BtrfsFs {
    pub fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        for (start, end, chunk) in &self.chunk_map {
            if logical >= *start && logical < *end {
                let offset = logical - start;
                return Some(chunk.stripe_offset + offset);
            }
        }
        None
    }

    pub fn read_node(&self, logical: u64) -> Option<Vec<u8>> {
        let phys = self.logical_to_physical(logical)?;
        let size = self.superblock.nodesize as u64;
        let lba  = phys / 512;
        let secs = ((size + 511) / 512) as u32;
        Some(block_read(lba, secs))
    }

    pub fn btree_search<F>(&self, root: u64, cmp: F) -> Vec<(BtrfsKey, Vec<u8>)>
    where F: Fn(&BtrfsKey) -> core::cmp::Ordering
    {
        let mut results = Vec::new();
        self.btree_search_node(root, &cmp, &mut results, 0);
        results
    }

    fn btree_search_node<F>(&self, logical: u64, cmp: &F,
        out: &mut Vec<(BtrfsKey, Vec<u8>)>, depth: usize)
    where F: Fn(&BtrfsKey) -> core::cmp::Ordering
    {
        if depth > 16 { return; }
        let raw = match self.read_node(logical) { Some(r) => r, None => return };
        if raw.len() < 101 { return; }
        let hdr = BtrfsHeader::from_bytes(&raw);
        let nritems = hdr.nritems as usize;
        if hdr.level == BTRFS_NODE_LEAF {
            for i in 0..nritems.min(BTRFS_MAX_LEAF_ITEMS) {
                let item_off = 101 + i * 25;
                if item_off + 25 > raw.len() { break; }
                let item = BtrfsItem::from_bytes(&raw[item_off..item_off + 25]);
                match cmp(&item.key) {
                    core::cmp::Ordering::Equal => {
                        let data_start = 101 + item.offset as usize;
                        let data_end   = data_start + item.size as usize;
                        if data_end <= raw.len() {
                            out.push((item.key.clone(), raw[data_start..data_end].to_vec()));
                        }
                    }
                    _ => {}
                }
            }
        } else {
            for i in 0..nritems.min(BTRFS_MAX_LEAF_ITEMS) {
                let kp_off = 101 + i * 33;
                if kp_off + 33 > raw.len() { break; }
                let kp = BtrfsKeyPtr::from_bytes(&raw[kp_off..kp_off + 33]);
                let ord = cmp(&kp.key);
                if ord != core::cmp::Ordering::Greater {
                    self.btree_search_node(kp.blockptr, cmp, out, depth + 1);
                }
            }
        }
    }

    pub fn stat(&self, _path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> { Err(-38) }
    pub fn read_all(&self, _path: &str) -> Result<Vec<u8>, isize> { Err(-38) }
    pub fn write_all(&mut self, _path: &str, _data: &[u8]) -> Result<(), isize> { Err(-38) }
    pub fn readdir(&self, _path: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> { Err(-38) }
    pub fn create(&mut self, _path: &str) -> Result<(), isize> { Err(-38) }
    pub fn mkdir(&mut self, _path: &str) -> Result<(), isize> { Err(-38) }
    pub fn unlink(&mut self, _path: &str) -> Result<(), isize> { Err(-38) }
    pub fn rmdir(&mut self, _path: &str) -> Result<(), isize> { Err(-38) }
    pub fn rename(&mut self, _old: &str, _new: &str) -> Result<(), isize> { Err(-38) }
    pub fn link(&mut self, _existing: &str, _new: &str) -> Result<(), isize> { Err(-38) }
    pub fn symlink(&mut self, _target: &str, _link: &str) -> Result<(), isize> { Err(-38) }
    pub fn readlink(&self, _path: &str) -> Result<String, isize> { Err(-38) }
    pub fn chmod(&mut self, _path: &str, _mode: u16) -> Result<(), isize> { Err(-38) }
    pub fn chown(&mut self, _path: &str, _uid: u32, _gid: u32) -> Result<(), isize> { Err(-38) }
    pub fn set_times(&mut self, _path: &str, _a: u64, _m: u64) -> Result<(), isize> { Err(-38) }
    pub fn truncate(&mut self, _path: &str, _len: usize) -> Result<(), isize> { Err(-38) }
    pub fn statfs(&self) -> crate::fs::vfs_ops::KStatfs { crate::fs::vfs_ops::KStatfs::default() }
}
