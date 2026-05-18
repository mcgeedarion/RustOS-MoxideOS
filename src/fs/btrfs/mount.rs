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

    /// Translate a logical byte offset to a physical (LBA-relative) byte offset
    /// using the chunk map built during mount.
    pub fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        for &(start, end, ref chunk) in &self.chunk_map {
            if logical >= start && logical < end {
                return Some(chunk.stripe_offset + (logical - start));
            }
        }
        None
    }

    /// Allocate a new logical address (simple bump allocator).
    pub fn alloc_logical(&mut self, size: u64) -> u64 {
        let addr = self.alloc_cursor;
        self.alloc_cursor += size;
        addr
    }

    /// Read `size` bytes from `logical` offset via the chunk map.
    pub fn read_logical(&self, logical: u64, size: usize) -> Vec<u8> {
        let Some(phys) = self.logical_to_physical(logical) else { return vec![0u8; size]; };
        let lba   = phys / 512;
        let off   = (phys % 512) as usize;
        let sects = ((off + size + 511) / 512) as u32;
        let raw   = crate::drivers::block::read_sectors_raw(lba, sects);
        if off + size <= raw.len() {
            raw[off..off + size].to_vec()
        } else {
            let mut out = raw[off..].to_vec();
            out.resize(size, 0);
            out
        }
    }

    /// Write `data` to `logical` offset via the chunk map.
    pub fn write_logical(&self, logical: u64, data: &[u8]) {
        let Some(phys) = self.logical_to_physical(logical) else { return; };
        let lba  = phys / 512;
        let off  = (phys % 512) as usize;
        let size = data.len();
        let sects = ((off + size + 511) / 512) as u32;
        let mut raw = crate::drivers::block::read_sectors_raw(lba, sects);
        raw[off..off + size].copy_from_slice(data);
        crate::drivers::block::write_sectors(lba, &raw);
    }

    /// Parse a B-tree node/leaf at `logical` and return all items whose key
    /// matches the given predicate.
    pub fn btree_search<F>(&self, root_logical: u64, mut pred: F) -> Vec<(BtrfsKey, Vec<u8>)>
    where
        F: FnMut(&BtrfsKey) -> core::cmp::Ordering,
    {
        let mut results = Vec::new();
        self.btree_search_node(root_logical, &mut pred, &mut results);
        results
    }

    fn btree_search_node<F>(
        &self,
        logical: u64,
        pred:    &mut F,
        out:     &mut Vec<(BtrfsKey, Vec<u8>)>,
    )
    where
        F: FnMut(&BtrfsKey) -> core::cmp::Ordering,
    {
        let node_size = self.superblock.nodesize as usize;
        let raw = self.read_logical(logical, node_size);
        if raw.len() < 101 { return; }

        // Parse header (101 bytes)
        let level = raw[100];
        let nritems = u32::from_le_bytes([raw[96], raw[97], raw[98], raw[99]]) as usize;

        if level == 0 {
            // Leaf node: header(101) + items(nritems * 25)
            for i in 0..nritems.min(BTRFS_MAX_LEAF_ITEMS) {
                let item_off = 101 + i * 25;
                if item_off + 25 > raw.len() { break; }
                let key = parse_key(&raw[item_off..item_off + 17]);
                let ord = pred(&key);
                match ord {
                    core::cmp::Ordering::Equal => {
                        let data_off = u32::from_le_bytes(
                            raw[item_off+17..item_off+21].try_into().unwrap_or([0;4])
                        ) as usize + 101;
                        let data_len = u32::from_le_bytes(
                            raw[item_off+21..item_off+25].try_into().unwrap_or([0;4])
                        ) as usize;
                        if data_off + data_len <= raw.len() {
                            out.push((key, raw[data_off..data_off+data_len].to_vec()));
                        }
                    }
                    core::cmp::Ordering::Less    => continue,
                    core::cmp::Ordering::Greater => break,
                }
            }
        } else {
            // Internal node: header(101) + key_ptrs(nritems * 33)
            for i in 0..nritems {
                let kp_off = 101 + i * 33;
                if kp_off + 33 > raw.len() { break; }
                let key = parse_key(&raw[kp_off..kp_off + 17]);
                let blockptr = u64::from_le_bytes(
                    raw[kp_off+17..kp_off+25].try_into().unwrap_or([0;8])
                );
                let ord = pred(&key);
                if ord != core::cmp::Ordering::Less {
                    self.btree_search_node(blockptr, pred, out);
                }
            }
        }
    }

    /// Look up the inode number for `path` (absolute, e.g. "/usr/bin/ls").
    pub fn lookup_inode(&mut self, path: &str) -> Option<u64> {
        if let Some(&ino) = self.path_cache.get(path) { return Some(ino); }
        let ino = self.walk_path(path)?;
        self.path_cache.insert(path.to_string(), ino);
        Some(ino)
    }

    fn walk_path(&self, path: &str) -> Option<u64> {
        let mut cur_ino = 256u64; // BTRFS_FIRST_FREE_OBJECTID (root dir)
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        for part in parts {
            cur_ino = self.dir_lookup(cur_ino, part)?;
        }
        Some(cur_ino)
    }

    fn dir_lookup(&self, dir_ino: u64, name: &str) -> Option<u64> {
        let results = self.btree_search(self.fs_tree_root, |k| {
            if k.objectid < dir_ino { return core::cmp::Ordering::Less; }
            if k.objectid > dir_ino { return core::cmp::Ordering::Greater; }
            if k.ty < 84 { return core::cmp::Ordering::Less; }
            if k.ty > 84 { return core::cmp::Ordering::Greater; }
            core::cmp::Ordering::Equal
        });
        for (_, data) in &results {
            if let Some(dir_item) = parse_dir_item(data) {
                if dir_item.name == name {
                    return Some(dir_item.key.objectid);
                }
            }
        }
        None
    }

    /// Read the inode item for `ino`.
    pub fn read_inode(&self, ino: u64) -> Option<super::inode::BtrfsInodeItem> {
        let results = self.btree_search(self.fs_tree_root, |k| {
            k.objectid.cmp(&ino)
                .then(k.ty.cmp(&1u8))   // BTRFS_INODE_ITEM_KEY
                .then(k.offset.cmp(&0))
        });
        results.into_iter().find(|(k, _)| k.ty == 1).map(|(_, d)| parse_inode_item(&d))
    }

    /// Read all directory entries under `dir_ino`.
    pub fn read_dir(&self, dir_ino: u64) -> Vec<super::directory::BtrfsDirItem> {
        let results = self.btree_search(self.fs_tree_root, |k| {
            if k.objectid < dir_ino { return core::cmp::Ordering::Less; }
            if k.objectid > dir_ino { return core::cmp::Ordering::Greater; }
            if k.ty == 84 || k.ty == 96 { return core::cmp::Ordering::Equal; }
            core::cmp::Ordering::Less
        });
        results.into_iter().filter_map(|(_, d)| parse_dir_item(&d)).collect()
    }

    /// Read the file data for inode `ino`.
    pub fn read_file_data(&self, ino: u64, inode: &super::inode::BtrfsInodeItem) -> Vec<u8> {
        let results = self.btree_search(self.fs_tree_root, |k| {
            if k.objectid < ino { return core::cmp::Ordering::Less; }
            if k.objectid > ino { return core::cmp::Ordering::Greater; }
            if k.ty == 108 { return core::cmp::Ordering::Equal; } // BTRFS_EXTENT_DATA_KEY
            core::cmp::Ordering::Less
        });
        let mut file_data = vec![0u8; inode.size as usize];
        for (key, data) in results {
            if key.ty != 108 { continue; }
            if data.len() < 21 { continue; }
            let ty = data[20];
            match ty {
                0 => { // inline
                    let inline = &data[21..];
                    let len = inline.len().min(file_data.len());
                    file_data[..len].copy_from_slice(&inline[..len]);
                }
                1 | 2 => { // regular / prealloc
                    if data.len() < 53 { continue; }
                    let disk_bytenr  = u64::from_le_bytes(data[21..29].try_into().unwrap_or([0;8]));
                    let _disk_bytes  = u64::from_le_bytes(data[29..37].try_into().unwrap_or([0;8]));
                    let extent_off   = u64::from_le_bytes(data[37..45].try_into().unwrap_or([0;8]));
                    let num_bytes    = u64::from_le_bytes(data[45..53].try_into().unwrap_or([0;8]));
                    let file_off     = key.offset as usize;
                    let ext_data = self.read_logical(disk_bytenr + extent_off, num_bytes as usize);
                    let copy_len = num_bytes as usize;
                    let dst_end  = (file_off + copy_len).min(file_data.len());
                    if file_off < file_data.len() {
                        let src_len = dst_end - file_off;
                        file_data[file_off..dst_end].copy_from_slice(&ext_data[..src_len]);
                    }
                }
                _ => {}
            }
        }
        file_data
    }

    /// Write `data` into the file at `ino`, CoW-allocating a new extent.
    pub fn write_file_data(&mut self, ino: u64, offset: u64, data: &[u8]) {
        let logical = self.alloc_logical(data.len() as u64);
        self.write_logical(logical, data);
        // TODO: insert BTRFS_EXTENT_DATA_KEY into the fs-tree
        let _ = (ino, offset, logical);
    }

    /// Truncate file to `new_size`.
    pub fn truncate_file(&mut self, ino: u64, new_size: u64) {
        // TODO: remove extent items beyond new_size and update inode
        let _ = (ino, new_size);
    }

    /// Create a new inode (file or dir).
    pub fn create_inode(&mut self, parent_ino: u64, name: &str, mode: u32) -> Option<u64> {
        let new_ino = self.alloc_cursor + 1000;
        self.alloc_cursor += 1;
        // TODO: insert BTRFS_INODE_ITEM_KEY and BTRFS_DIR_ITEM_KEY into fs-tree
        let _ = (parent_ino, name, mode, new_ino);
        Some(new_ino)
    }

    /// Remove a directory entry.
    pub fn remove_dentry(&mut self, parent_ino: u64, name: &str) -> bool {
        // TODO: delete BTRFS_DIR_ITEM_KEY from fs-tree
        let _ = (parent_ino, name);
        false
    }

    /// Update inode metadata (mtime, ctime, mode, uid, gid, size).
    pub fn update_inode(&mut self, ino: u64, inode: &super::inode::BtrfsInodeItem) {
        // TODO: CoW-update the inode item in the fs-tree
        let _ = (ino, inode);
    }

    /// Read a symlink target.
    pub fn read_symlink(&self, ino: u64) -> Option<String> {
        let inode = self.read_inode(ino)?;
        let data  = self.read_file_data(ino, &inode);
        String::from_utf8(data).ok()
    }
}

// ── On-disk parsing helpers ──────────────────────────────────────────────────

pub(crate) fn parse_key(raw: &[u8]) -> BtrfsKey {
    BtrfsKey {
        objectid: u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0;8])),
        ty:       raw[8],
        offset:   u64::from_le_bytes(raw[9..17].try_into().unwrap_or([0;8])),
    }
}

pub(crate) fn parse_inode_item(raw: &[u8]) -> super::inode::BtrfsInodeItem {
    use super::inode::BtrfsInodeItem;
    if raw.len() < 160 { return BtrfsInodeItem::default(); }
    BtrfsInodeItem {
        generation:  u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0;8])),
        transid:     u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0;8])),
        size:        u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0;8])),
        nbytes:      u64::from_le_bytes(raw[24..32].try_into().unwrap_or([0;8])),
        block_group: u64::from_le_bytes(raw[32..40].try_into().unwrap_or([0;8])),
        nlink:       u32::from_le_bytes(raw[40..44].try_into().unwrap_or([0;4])),
        uid:         u32::from_le_bytes(raw[44..48].try_into().unwrap_or([0;4])),
        gid:         u32::from_le_bytes(raw[48..52].try_into().unwrap_or([0;4])),
        mode:        u32::from_le_bytes(raw[52..56].try_into().unwrap_or([0;4])),
        rdev:        u64::from_le_bytes(raw[56..64].try_into().unwrap_or([0;8])),
        flags:       u64::from_le_bytes(raw[64..72].try_into().unwrap_or([0;8])),
        sequence:    u64::from_le_bytes(raw[72..80].try_into().unwrap_or([0;8])),
        atime_sec:   u64::from_le_bytes(raw[96..104].try_into().unwrap_or([0;8])),
        atime_nsec:  u32::from_le_bytes(raw[104..108].try_into().unwrap_or([0;4])),
        ctime_sec:   u64::from_le_bytes(raw[112..120].try_into().unwrap_or([0;8])),
        ctime_nsec:  u32::from_le_bytes(raw[120..124].try_into().unwrap_or([0;4])),
        mtime_sec:   u64::from_le_bytes(raw[128..136].try_into().unwrap_or([0;8])),
        mtime_nsec:  u32::from_le_bytes(raw[136..140].try_into().unwrap_or([0;4])),
        otime_sec:   u64::from_le_bytes(raw[144..152].try_into().unwrap_or([0;8])),
        otime_nsec:  u32::from_le_bytes(raw[152..156].try_into().unwrap_or([0;4])),
    }
}

pub(crate) fn parse_dir_item(raw: &[u8]) -> Option<super::directory::BtrfsDirItem> {
    use super::directory::BtrfsDirItem;
    if raw.len() < 30 { return None; }
    let key = parse_key(&raw[0..17]);
    let _transid   = u64::from_le_bytes(raw[17..25].try_into().unwrap_or([0;8]));
    let data_len   = u16::from_le_bytes(raw[25..27].try_into().unwrap_or([0;2])) as usize;
    let name_len   = u16::from_le_bytes(raw[27..29].try_into().unwrap_or([0;2])) as usize;
    let ty         = raw[29];
    let name_start = 30 + data_len;
    if name_start + name_len > raw.len() { return None; }
    let name = String::from_utf8_lossy(&raw[name_start..name_start+name_len]).into_owned();
    Some(BtrfsDirItem { key, transid: _transid, data_len: data_len as u16, name_len: name_len as u16, ty, name })
}

pub(crate) fn parse_sys_chunk_array(sb: &BtrfsSuperblock) -> Vec<(u64, u64, BtrfsChunkItem)> {
    let arr   = &sb.sys_chunk_array[..sb.sys_chunk_array_size as usize];
    let mut map = Vec::new();
    let mut off = 0usize;
    while off + 17 < arr.len() {
        let logical = u64::from_le_bytes(arr[off+9..off+17].try_into().unwrap_or([0;8]));
        off += 17; // skip key
        if off + 80 > arr.len() { break; }
        let length       = u64::from_le_bytes(arr[off..off+8].try_into().unwrap_or([0;8]));
        let stripe_off   = u64::from_le_bytes(arr[off+64..off+72].try_into().unwrap_or([0;8]));
        let chunk = BtrfsChunkItem {
            length,
            stripe_offset: stripe_off,
            ..Default::default()
        };
        map.push((logical, logical + length, chunk));
        off += 80 + 32; // chunk body + one stripe
    }
    map
}

pub(crate) fn parse_superblock(raw: &[u8]) -> Option<BtrfsSuperblock> {
    if raw.len() < 4096 { return None; }
    let magic = u64::from_le_bytes(raw[64..72].try_into().ok()?);
    if magic != 0x4D5F53665248425F { return None; }
    let mut csum    = [0u8; 32]; csum.copy_from_slice(&raw[0..32]);
    let mut fsid    = [0u8; 16]; fsid.copy_from_slice(&raw[32..48]);
    let mut label   = [0u8; 256]; label.copy_from_slice(&raw[299..555]);
    let mut sys_arr = [0u8; 2048]; sys_arr.copy_from_slice(&raw[2048..4096]);
    Some(BtrfsSuperblock {
        csum,
        fsid,
        bytenr:                 u64::from_le_bytes(raw[48..56].try_into().ok()?),
        flags:                  u64::from_le_bytes(raw[56..64].try_into().ok()?),
        magic,
        generation:             u64::from_le_bytes(raw[72..80].try_into().ok()?),
        root:                   u64::from_le_bytes(raw[80..88].try_into().ok()?),
        chunk_root:             u64::from_le_bytes(raw[88..96].try_into().ok()?),
        log_root:               u64::from_le_bytes(raw[96..104].try_into().ok()?),
        log_root_transid:       u64::from_le_bytes(raw[104..112].try_into().ok()?),
        total_bytes:            u64::from_le_bytes(raw[112..120].try_into().ok()?),
        bytes_used:             u64::from_le_bytes(raw[120..128].try_into().ok()?),
        root_dir_objectid:      u64::from_le_bytes(raw[128..136].try_into().ok()?),
        num_devices:            u64::from_le_bytes(raw[136..144].try_into().ok()?),
        sectorsize:             u32::from_le_bytes(raw[144..148].try_into().ok()?),
        nodesize:               u32::from_le_bytes(raw[148..152].try_into().ok()?),
        leafsize:               u32::from_le_bytes(raw[152..156].try_into().ok()?),
        stripesize:             u32::from_le_bytes(raw[156..160].try_into().ok()?),
        sys_chunk_array_size:   u32::from_le_bytes(raw[160..164].try_into().ok()?),
        chunk_root_generation:  u64::from_le_bytes(raw[164..172].try_into().ok()?),
        compat_flags:           u64::from_le_bytes(raw[172..180].try_into().ok()?),
        compat_ro_flags:        u64::from_le_bytes(raw[180..188].try_into().ok()?),
        incompat_flags:         u64::from_le_bytes(raw[188..196].try_into().ok()?),
        csum_type:              u16::from_le_bytes(raw[196..198].try_into().ok()?),
        root_level:             raw[198],
        chunk_root_level:       raw[199],
        log_root_level:         raw[200],
        label,
        sys_chunk_array:        sys_arr,
    })
}
