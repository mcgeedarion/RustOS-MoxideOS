//! Lower impl BtrfsFs: chunk-map resolution, B-tree traversal, read path.
//! Source lines 511–911 of the original btrfs.rs monolith.
extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use super::superblock::*;

impl BtrfsFs {
    fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        for (start, end, chunk) in &self.chunk_map {
            if logical >= *start && logical < *end {
                let offset = logical - start;
                return Some(chunk.offset + offset);
            }
        }
        None
    }

    fn read_node_bytes(&self, logical: u64) -> Option<Vec<u8>> {
        let physical = self.logical_to_physical(logical)?;
        let node_size = self.superblock.nodesize as usize;
        let lba = physical / 512;
        let sectors = ((node_size + 511) / 512) as u32;
        let raw = crate::drivers::block::read_sectors_vec(lba, sectors);
        if raw.len() < node_size { return None; }
        Some(raw[..node_size].to_vec())
    }

    fn btree_search<F>(&self, root_logical: u64, predicate: F) -> Vec<(BtrfsKey, Vec<u8>)>
    where
        F: Fn(&BtrfsKey) -> core::cmp::Ordering + Copy,
    {
        let mut results = Vec::new();
        self.btree_walk(root_logical, &predicate, &mut results, 0);
        results
    }

    fn btree_walk<F>(
        &self,
        node_logical: u64,
        predicate: &F,
        results: &mut Vec<(BtrfsKey, Vec<u8>)>,
        depth: usize,
    )
    where
        F: Fn(&BtrfsKey) -> core::cmp::Ordering + Copy,
    {
        if depth > 16 { return; }
        let raw = match self.read_node_bytes(node_logical) {
            Some(r) => r,
            None    => return,
        };
        if raw.len() < BTRFS_HEADER_SIZE { return; }
        let hdr = BtrfsHeader::from_bytes(&raw);
        let n   = hdr.nritems as usize;

        if hdr.level == 0 {
            // Leaf node
            for i in 0..n {
                let item_off = BTRFS_HEADER_SIZE + i * BTRFS_ITEM_SIZE;
                if item_off + BTRFS_ITEM_SIZE > raw.len() { break; }
                let item = BtrfsItem::from_bytes(&raw[item_off..item_off + BTRFS_ITEM_SIZE]);
                match predicate(&item.key) {
                    core::cmp::Ordering::Equal => {
                        let data_start = BTRFS_HEADER_SIZE + item.offset as usize;
                        let data_end   = data_start + item.size as usize;
                        if data_end <= raw.len() {
                            results.push((item.key, raw[data_start..data_end].to_vec()));
                        }
                    }
                    core::cmp::Ordering::Less    => continue,
                    core::cmp::Ordering::Greater => break,
                }
            }
        } else {
            // Internal node
            for i in 0..n {
                let ptr_off = BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE;
                if ptr_off + BTRFS_KEY_PTR_SIZE > raw.len() { break; }
                let kp = BtrfsKeyPtr::from_bytes(&raw[ptr_off..ptr_off + BTRFS_KEY_PTR_SIZE]);
                match predicate(&kp.key) {
                    core::cmp::Ordering::Greater => break,
                    _ => self.btree_walk(kp.block_ptr, predicate, results, depth + 1),
                }
            }
        }
    }

    fn lookup_item(&self, root: u64, key: BtrfsKey) -> Option<Vec<u8>> {
        let results = self.btree_search(root, |k| {
            (k.objectid, k.ty, k.offset).cmp(&(key.objectid, key.ty, key.offset))
        });
        results.into_iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    fn lookup_items_by_type(&self, root: u64, objectid: u64, ty: u8) -> Vec<(BtrfsKey, Vec<u8>)> {
        self.btree_search(root, |k| {
            if k.objectid != objectid { k.objectid.cmp(&objectid) }
            else if k.ty != ty        { k.ty.cmp(&ty) }
            else                      { core::cmp::Ordering::Equal }
        })
    }

    fn resolve_path(&self, path: &str) -> Option<u64> {
        if let Some(&ino) = self.path_cache.get(path) {
            return Some(ino);
        }
        let mut ino = 256u64; // BTRFS_FIRST_FREE_OBJECTID is root dir
        if path == "/" || path.is_empty() { return Some(ino); }
        for component in path.trim_start_matches('/').split('/') {
            if component.is_empty() { continue; }
            ino = self.dir_lookup(ino, component)?;
        }
        Some(ino)
    }

    fn dir_lookup(&self, dir_ino: u64, name: &str) -> Option<u64> {
        let hash = btrfs_name_hash(name.as_bytes());
        let key  = BtrfsKey::new(dir_ino, BTRFS_DIR_ITEM_KEY, hash);
        let data = self.lookup_item(self.fs_tree_root, key)?;
        let di   = BtrfsDirItem::from_bytes(&data)?;
        Some(di.child_key.objectid)
    }

    fn read_inode(&self, ino: u64) -> Option<BtrfsInodeItem> {
        let key  = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        let data = self.lookup_item(self.fs_tree_root, key)?;
        Some(BtrfsInodeItem::from_bytes(&data))
    }

    pub fn stat(&self, path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii  = self.read_inode(ino).ok_or(-2isize)?;
        Ok(crate::fs::vfs_ops::KStat {
            dev: 0, ino,
            mode: ii.mode as u16,
            nlink: ii.nlink,
            uid: ii.uid, gid: ii.gid,
            rdev: ii.rdev,
            size: ii.size as i64,
            blksize: self.superblock.sectorsize as i64,
            blocks: ((ii.size + 511) / 512) as i64,
            atime: ii.atime_sec as i64, atime_nsec: ii.atime_nsec as i64,
            mtime: ii.mtime_sec as i64, mtime_nsec: ii.mtime_nsec as i64,
            ctime: ii.ctime_sec as i64, ctime_nsec: ii.ctime_nsec as i64,
        })
    }

    pub fn read_all(&self, path: &str) -> Result<Vec<u8>, isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii  = self.read_inode(ino).ok_or(-2isize)?;
        if ii.mode & S_IFMT == S_IFDIR { return Err(-21); }
        self.read_inode_data(ino, ii.size)
    }

    fn read_inode_data(&self, ino: u64, file_size: u64) -> Result<Vec<u8>, isize> {
        let extents = self.lookup_items_by_type(
            self.fs_tree_root, ino, BTRFS_EXTENT_DATA_KEY,
        );
        if extents.is_empty() { return Ok(vec![0u8; file_size as usize]); }
        let mut out = vec![0u8; file_size as usize];
        for (key, data) in &extents {
            let file_offset = key.offset as usize;
            let Some(fe) = BtrfsFileExtentItem::from_bytes(data) else { continue; };
            match fe.ty {
                BTRFS_FILE_EXTENT_INLINE => {
                    let d = if fe.compression != 0 {
                        super::compression::decompress(fe.compression, &fe.inline_data, fe.ram_bytes as usize)
                    } else {
                        fe.inline_data.clone()
                    };
                    let n = d.len().min(out.len().saturating_sub(file_offset));
                    out[file_offset..file_offset + n].copy_from_slice(&d[..n]);
                }
                BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC => {
                    if fe.disk_bytenr == 0 { continue; } // hole
                    let phys = match self.logical_to_physical(fe.disk_bytenr) {
                        Some(p) => p,
                        None    => continue,
                    };
                    let extent_bytes = fe.disk_num_bytes as usize;
                    let lba     = (phys + fe.extent_offset) / 512;
                    let sectors = ((extent_bytes + 511) / 512) as u32;
                    let raw = crate::drivers::block::read_sectors_vec(lba, sectors);
                    let disk_data = if fe.compression != 0 {
                        super::compression::decompress(fe.compression, &raw[..extent_bytes.min(raw.len())], fe.ram_bytes as usize)
                    } else {
                        raw[..extent_bytes.min(raw.len())].to_vec()
                    };
                    let copy_len = (fe.num_bytes as usize)
                        .min(disk_data.len())
                        .min(out.len().saturating_sub(file_offset));
                    out[file_offset..file_offset + copy_len]
                        .copy_from_slice(&disk_data[..copy_len]);
                }
                _ => {}
            }
        }
        Ok(out)
    }

    pub fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii  = self.read_inode(ino).ok_or(-2isize)?;
        if ii.mode & S_IFMT == S_IFDIR { return Err(-21); }
        self.write_inode_data(ino, 0, data)?;
        self.write_inode_size(ino, data.len() as u64)
    }

    fn write_inode_data(&mut self, ino: u64, file_offset: u64, data: &[u8]) -> Result<(), isize> {
        // Align to node size for CoW
        let node_size = self.superblock.nodesize as u64;
        let alloc_logical = (self.alloc_cursor + node_size - 1) & !(node_size - 1);
        self.alloc_cursor = alloc_logical + data.len() as u64;

        let phys = self.logical_to_physical(alloc_logical).ok_or(-28isize)?;
        let lba  = phys / 512;
        let mut aligned = vec![0u8; ((data.len() + 511) / 512) * 512];
        aligned[..data.len()].copy_from_slice(data);
        crate::drivers::block::write_sectors(lba, &aligned);

        // Insert EXTENT_DATA item
        let key = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, file_offset);
        let mut fe = vec![0u8; 53];
        fe[20] = BTRFS_FILE_EXTENT_REG;
        fe[21..29].copy_from_slice(&alloc_logical.to_le_bytes());
        fe[29..37].copy_from_slice(&(data.len() as u64).to_le_bytes());
        fe[37..45].copy_from_slice(&0u64.to_le_bytes());
        fe[45..53].copy_from_slice(&(data.len() as u64).to_le_bytes());
        self.write_leaf_item(self.fs_tree_root, key, &fe)?;
        Ok(())
    }

    fn write_inode_size(&self, ino: u64, new_size: u64) -> Result<(), isize> {
        let key = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        let data = self.lookup_item(self.fs_tree_root, key.clone()).ok_or(-2isize)?;
        let mut ii = BtrfsInodeItem::from_bytes(&data);
        ii.size   = new_size;
        ii.nbytes = (new_size + 511) & !511;
        self.write_leaf_item(self.fs_tree_root, key, &ii.to_bytes())
    }

    fn insert_extent_item(
        &mut self,
        ino: u64,
        file_offset: u64,
        disk_logical: u64,
        disk_bytes: u64,
        num_bytes: u64,
    ) -> Result<(), isize> {
        let key = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, file_offset);
        let mut fe = vec![0u8; 53];
        fe[20] = BTRFS_FILE_EXTENT_REG;
        fe[21..29].copy_from_slice(&disk_logical.to_le_bytes());
        fe[29..37].copy_from_slice(&disk_bytes.to_le_bytes());
        fe[37..45].copy_from_slice(&0u64.to_le_bytes());
        fe[45..53].copy_from_slice(&num_bytes.to_le_bytes());
        self.write_leaf_item(self.fs_tree_root, key, &fe)
    }

    fn write_leaf_item(&self, root: u64, key: BtrfsKey, data: &[u8]) -> Result<(), isize> {
        self.write_leaf_item_recurse(root, key, data, 0)
    }

    fn write_leaf_item_recurse(&self, node_logical: u64, key: BtrfsKey, data: &[u8], depth: usize)
        -> Result<(), isize>
    {
        if depth > 16 { return Err(-28); }
        let mut raw = self.read_node_bytes(node_logical).ok_or(-5isize)?;
        let hdr = BtrfsHeader::from_bytes(&raw);
        let n   = hdr.nritems as usize;

        if hdr.level == 0 {
            // Leaf: find existing slot or append
            for i in 0..n {
                let off = BTRFS_HEADER_SIZE + i * BTRFS_ITEM_SIZE;
                let item = BtrfsItem::from_bytes(&raw[off..off + BTRFS_ITEM_SIZE]);
                if item.key == key {
                    // Overwrite data in place (same size only)
                    let data_start = BTRFS_HEADER_SIZE + item.offset as usize;
                    let copy = data.len().min(item.size as usize);
                    raw[data_start..data_start + copy].copy_from_slice(&data[..copy]);
                    let phys = self.logical_to_physical(node_logical).ok_or(-5isize)?;
                    let node_size = self.superblock.nodesize as usize;
                    let mut aligned = vec![0u8; node_size];
                    aligned[..raw.len().min(node_size)].copy_from_slice(&raw[..raw.len().min(node_size)]);
                    crate::drivers::block::write_sectors(phys / 512, &aligned);
                    return Ok(());
                }
            }
            Err(-28) // no slot — append not implemented in stub
        } else {
            for i in 0..n {
                let ptr_off = BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE;
                let kp = BtrfsKeyPtr::from_bytes(&raw[ptr_off..ptr_off + BTRFS_KEY_PTR_SIZE]);
                let is_last = i + 1 == n;
                let next_key = if !is_last {
                    let no = BTRFS_HEADER_SIZE + (i+1) * BTRFS_KEY_PTR_SIZE;
                    Some(BtrfsKeyPtr::from_bytes(&raw[no..no + BTRFS_KEY_PTR_SIZE]).key)
                } else { None };
                let in_range = next_key.map_or(true, |nk| key < nk);
                if in_range {
                    return self.write_leaf_item_recurse(kp.block_ptr, key, data, depth + 1);
                }
            }
            Err(-2)
        }
    }
}