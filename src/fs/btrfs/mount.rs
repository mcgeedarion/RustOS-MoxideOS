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

impl BtrfsFs {
    pub fn new(sb: BtrfsSuperblock) -> Self {
        BtrfsFs {
            superblock:     sb,
            chunk_map:      Vec::new(),
            root_tree_root: 0,
            fs_tree_root:   0,
            path_cache:     BTreeMap::new(),
            alloc_cursor:   0,
        }
    }

    pub fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        for (start, end, chunk) in &self.chunk_map {
            if logical >= *start && logical < *end {
                let stripe_offset = logical - start;
                // First stripe physical offset is immediately after BtrfsChunkItem header (48 bytes)
                // followed by BtrfsStripeItem (32 bytes each); stripe 0 offset is at bytes 48..56
                let stripe_phys: u64 = unsafe {
                    let ptr = chunk as *const BtrfsChunkItem as *const u8;
                    let off_bytes = core::slice::from_raw_parts(ptr.add(48), 8);
                    u64::from_le_bytes(off_bytes.try_into().unwrap())
                };
                return Some(stripe_phys + stripe_offset);
            }
        }
        None
    }

    pub fn read_node(&self, logical: u64) -> Option<Vec<u8>> {
        let phys  = self.logical_to_physical(logical)?;
        let lba   = phys / 512;
        let count = (self.superblock.nodesize as u64 + 511) / 512;
        let raw   = block_read(lba, count as u32);
        if raw.len() < self.superblock.nodesize as usize { return None; }
        Some(raw[..self.superblock.nodesize as usize].to_vec())
    }

    pub fn btree_search(&self, root_logical: u64, target: &BtrfsKey)
        -> Option<Vec<u8>>
    {
        let node_size = self.superblock.nodesize as usize;
        let hdr_size  = 101usize; // sizeof BtrfsHeader
        let item_size = 25usize;  // sizeof BtrfsItem
        let kptr_size = 33usize;  // sizeof BtrfsKeyPtr

        let mut current = root_logical;
        for _depth in 0..16 {
            let node = self.read_node(current)?;
            if node.len() < hdr_size { return None; }
            let level   = node[100];
            let nritems = u32::from_le_bytes(node[96..100].try_into().unwrap()) as usize;
            if level == 0 {
                // Leaf node: scan BtrfsItems
                for i in 0..nritems {
                    let off = hdr_size + i * item_size;
                    if off + item_size > node.len() { break; }
                    let k = BtrfsKey::from_bytes(&node[off..off+17]);
                    if k == *target {
                        let data_off  = u32::from_le_bytes(node[off+17..off+21].try_into().unwrap()) as usize;
                        let data_size = u32::from_le_bytes(node[off+21..off+25].try_into().unwrap()) as usize;
                        let base = hdr_size + nritems * item_size;
                        let start = base + data_off;
                        if start + data_size <= node.len() {
                            return Some(node[start..start+data_size].to_vec());
                        }
                    }
                }
                return None;
            } else {
                // Internal node: find child with largest key <= target
                let mut next = None;
                for i in 0..nritems {
                    let off = hdr_size + i * kptr_size;
                    if off + kptr_size > node.len() { break; }
                    let k = BtrfsKey::from_bytes(&node[off..off+17]);
                    if k <= *target {
                        let ptr = u64::from_le_bytes(node[off+17..off+25].try_into().unwrap());
                        next = Some(ptr);
                    } else {
                        break;
                    }
                }
                current = next?;
            }
        }
        None
    }

    pub fn btree_search_range(&self, root_logical: u64, min: &BtrfsKey, max: &BtrfsKey)
        -> Vec<(BtrfsKey, Vec<u8>)>
    {
        let node_size = self.superblock.nodesize as usize;
        let hdr_size  = 101usize;
        let item_size = 25usize;
        let kptr_size = 33usize;
        let mut results = Vec::new();
        let mut stack   = vec![root_logical];

        while let Some(current) = stack.pop() {
            let Some(node) = self.read_node(current) else { continue; };
            if node.len() < hdr_size { continue; }
            let level   = node[100];
            let nritems = u32::from_le_bytes(node[96..100].try_into().unwrap()) as usize;
            if level == 0 {
                for i in 0..nritems {
                    let off = hdr_size + i * item_size;
                    if off + item_size > node.len() { break; }
                    let k = BtrfsKey::from_bytes(&node[off..off+17]);
                    if k >= *min && k <= *max {
                        let data_off  = u32::from_le_bytes(node[off+17..off+21].try_into().unwrap()) as usize;
                        let data_size = u32::from_le_bytes(node[off+21..off+25].try_into().unwrap()) as usize;
                        let base  = hdr_size + nritems * item_size;
                        let start = base + data_off;
                        if start + data_size <= node.len() {
                            results.push((k, node[start..start+data_size].to_vec()));
                        }
                    }
                }
            } else {
                for i in 0..nritems {
                    let off = hdr_size + i * kptr_size;
                    if off + kptr_size > node.len() { break; }
                    let k = BtrfsKey::from_bytes(&node[off..off+17]);
                    if k <= *max {
                        let ptr = u64::from_le_bytes(node[off+17..off+25].try_into().unwrap());
                        stack.push(ptr);
                    }
                }
            }
        }
        results
    }
}