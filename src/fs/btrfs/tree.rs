//! B-tree structures, traversal, chunk-map resolution, read/write path.
//! Merged from tree.rs + tree_impl.rs
extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::superblock::{BtrfsSuperblock, BtrfsChunkItem, BtrfsKey, BtrfsKeyPtr,
                        BtrfsHeader, BtrfsItem, BtrfsDirItem, BtrfsInodeItem,
                        BtrfsFileExtentItem, BTRFS_HEADER_SIZE, BTRFS_ITEM_SIZE,
                        BTRFS_KEY_PTR_SIZE, BTRFS_DIR_ITEM_KEY, BTRFS_INODE_ITEM_KEY,
                        BTRFS_EXTENT_DATA_KEY, BTRFS_FILE_EXTENT_INLINE,
                        BTRFS_FILE_EXTENT_REG, BTRFS_FILE_EXTENT_PREALLOC,
                        S_IFMT, S_IFDIR, S_IFREG, S_IFLNK,
                        btrfs_name_hash, BtrfsFs};

impl BtrfsFs {
    pub(crate) fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        for (start, end, chunk) in &self.chunk_map {
            if logical >= *start && logical < *end {
                return Some(chunk.offset + (logical - start));
            }
        }
        None
    }

    pub(crate) fn read_node_bytes(&self, logical: u64) -> Option<Vec<u8>> {
        let physical  = self.logical_to_physical(logical)?;
        let node_size = self.superblock.nodesize as usize;
        let raw = crate::drivers::block::read_sectors_vec(physical / 512,
            ((node_size + 511) / 512) as u32);
        if raw.len() < node_size { return None; }
        Some(raw[..node_size].to_vec())
    }

    pub(crate) fn btree_search<F>(
        &self, root_logical: u64, predicate: F,
    ) -> Vec<(BtrfsKey, Vec<u8>)>
    where F: Fn(&BtrfsKey) -> core::cmp::Ordering + Copy {
        let mut results = Vec::new();
        self.btree_walk(root_logical, &predicate, &mut results, 0);
        results
    }

    fn btree_walk<F>(
        &self, node_logical: u64, predicate: &F,
        results: &mut Vec<(BtrfsKey, Vec<u8>)>, depth: usize,
    )
    where F: Fn(&BtrfsKey) -> core::cmp::Ordering + Copy {
        if depth > 16 { return; }
        let raw = match self.read_node_bytes(node_logical) {
            Some(r) => r, None => return,
        };
        if raw.len() < BTRFS_HEADER_SIZE { return; }
        let hdr = BtrfsHeader::from_bytes(&raw);
        let n   = hdr.nritems as usize;

        if hdr.level == 0 {
            for i in 0..n {
                let off  = BTRFS_HEADER_SIZE + i * BTRFS_ITEM_SIZE;
                if off + BTRFS_ITEM_SIZE > raw.len() { break; }
                let item = BtrfsItem::from_bytes(&raw[off..off + BTRFS_ITEM_SIZE]);
                match predicate(&item.key) {
                    core::cmp::Ordering::Equal => {
                        let ds = BTRFS_HEADER_SIZE + item.offset as usize;
                        let de = ds + item.size as usize;
                        if de <= raw.len() {
                            results.push((item.key, raw[ds..de].to_vec()));
                        }
                    }
                    core::cmp::Ordering::Less    => continue,
                    core::cmp::Ordering::Greater => break,
                }
            }
        } else {
            for i in 0..n {
                let off = BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE;
                if off + BTRFS_KEY_PTR_SIZE > raw.len() { break; }
                let kp  = BtrfsKeyPtr::from_bytes(&raw[off..off + BTRFS_KEY_PTR_SIZE]);
                match predicate(&kp.key) {
                    core::cmp::Ordering::Greater => break,
                    _ => self.btree_walk(kp.block_ptr, predicate, results, depth + 1),
                }
            }
        }
    }

    pub(crate) fn lookup_item(&self, root: u64, key: BtrfsKey) -> Option<Vec<u8>> {
        self.btree_search(root, |k| {
            (k.objectid, k.ty, k.offset).cmp(&(key.objectid, key.ty, key.offset))
        }).into_iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    pub(crate) fn lookup_items_by_type(
        &self, root: u64, objectid: u64, ty: u8,
    ) -> Vec<(BtrfsKey, Vec<u8>)> {
        self.btree_search(root, |k| {
            if k.objectid != objectid { k.objectid.cmp(&objectid) }
            else if k.ty != ty        { k.ty.cmp(&ty) }
            else                      { core::cmp::Ordering::Equal }
        })
    }

    pub(crate) fn resolve_path(&self, path: &str) -> Option<u64> {
        if let Some(&ino) = self.path_cache.get(path) { return Some(ino); }
        let mut ino = 256u64;
        if path == "/" || path.is_empty() { return Some(ino); }
        for part in path.trim_start_matches('/').split('/') {
            if part.is_empty() { continue; }
            ino = self.dir_lookup(ino, part)?;
        }
        Some(ino)
    }

    pub(crate) fn dir_lookup(&self, dir_ino: u64, name: &str) -> Option<u64> {
        let hash = btrfs_name_hash(name.as_bytes());
        let key  = BtrfsKey::new(dir_ino, BTRFS_DIR_ITEM_KEY, hash);
        let data = self.lookup_item(self.fs_tree_root, key)?;
        Some(BtrfsDirItem::from_bytes(&data)?.child_key.objectid)
    }

    pub(crate) fn read_inode(&self, ino: u64) -> Option<BtrfsInodeItem> {
        let key  = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        let data = self.lookup_item(self.fs_tree_root, key)?;
        Some(BtrfsInodeItem::from_bytes(&data))
    }

    pub fn stat(&self, path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii  = self.read_inode(ino).ok_or(-2isize)?;
        Ok(crate::fs::vfs_ops::KStat {
            dev: 0, ino,
            mode: ii.mode as u16, nlink: ii.nlink,
            uid: ii.uid, gid: ii.gid, rdev: ii.rdev,
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

    pub(crate) fn read_inode_data(&self, ino: u64, file_size: u64) -> Result<Vec<u8>, isize> {
        let extents = self.lookup_items_by_type(
            self.fs_tree_root, ino, BTRFS_EXTENT_DATA_KEY);
        if extents.is_empty() { return Ok(vec![0u8; file_size as usize]); }
        let mut out = vec![0u8; file_size as usize];
        for (key, data) in &extents {
            let file_off = key.offset as usize;
            let Some(fe) = BtrfsFileExtentItem::from_bytes(data) else { continue; };
            match fe.ty {
                BTRFS_FILE_EXTENT_INLINE => {
                    let d = if fe.compression != 0 {
                        super::compression::decompress(fe.compression, &fe.inline_data, fe.ram_bytes as usize)
                    } else { fe.inline_data.clone() };
                    let n = d.len().min(out.len().saturating_sub(file_off));
                    out[file_off..file_off + n].copy_from_slice(&d[..n]);
                }
                BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC => {
                    if fe.disk_bytenr == 0 { continue; }
                    let phys = match self.logical_to_physical(fe.disk_bytenr) {
                        Some(p) => p, None => continue,
                    };
                    let eb   = fe.disk_num_bytes as usize;
                    let raw  = crate::drivers::block::read_sectors_vec(
                        (phys + fe.extent_offset) / 512, ((eb + 511) / 512) as u32);
                    let disk = if fe.compression != 0 {
                        super::compression::decompress(fe.compression, &raw[..eb.min(raw.len())], fe.ram_bytes as usize)
                    } else { raw[..eb.min(raw.len())].to_vec() };
                    let cp = (fe.num_bytes as usize).min(disk.len())
                        .min(out.len().saturating_sub(file_off));
                    out[file_off..file_off + cp].copy_from_slice(&disk[..cp]);
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

    pub(crate) fn write_inode_data(
        &mut self, ino: u64, file_offset: u64, data: &[u8],
    ) -> Result<(), isize> {
        let node_size     = self.superblock.nodesize as u64;
        let alloc_logical = (self.alloc_cursor + node_size - 1) & !(node_size - 1);
        self.alloc_cursor = alloc_logical + data.len() as u64;
        let phys = self.logical_to_physical(alloc_logical).ok_or(-28isize)?;
        let mut aligned = vec![0u8; ((data.len() + 511) / 512) * 512];
        aligned[..data.len()].copy_from_slice(data);
        crate::drivers::block::write_sectors(phys / 512, &aligned);
        let key = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, file_offset);
        let mut fe = vec![0u8; 53];
        fe[20] = BTRFS_FILE_EXTENT_REG;
        fe[21..29].copy_from_slice(&alloc_logical.to_le_bytes());
        fe[29..37].copy_from_slice(&(data.len() as u64).to_le_bytes());
        fe[45..53].copy_from_slice(&(data.len() as u64).to_le_bytes());
        self.write_leaf_item(self.fs_tree_root, key, &fe)
    }

    pub(crate) fn write_inode_size(&self, ino: u64, new_size: u64) -> Result<(), isize> {
        let key  = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        let data = self.lookup_item(self.fs_tree_root, key.clone()).ok_or(-2isize)?;
        let mut ii = BtrfsInodeItem::from_bytes(&data);
        ii.size   = new_size;
        ii.nbytes = (new_size + 511) & !511;
        self.write_leaf_item(self.fs_tree_root, key, &ii.to_bytes())
    }

    pub(crate) fn write_inode_item(&self, ino: u64, ii: &BtrfsInodeItem) -> Result<(), isize> {
        let key = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        self.write_leaf_item(self.fs_tree_root, key, &ii.to_bytes())
    }

    pub(crate) fn write_leaf_item(
        &self, root: u64, key: BtrfsKey, data: &[u8],
    ) -> Result<(), isize> {
        self.write_leaf_item_recurse(root, key, data, 0)
    }

    fn write_leaf_item_recurse(
        &self, node_logical: u64, key: BtrfsKey, data: &[u8], depth: usize,
    ) -> Result<(), isize> {
        if depth > 16 { return Err(-28); }
        let mut raw = self.read_node_bytes(node_logical).ok_or(-5isize)?;
        let hdr = BtrfsHeader::from_bytes(&raw);
        let n   = hdr.nritems as usize;
        if hdr.level == 0 {
            for i in 0..n {
                let off  = BTRFS_HEADER_SIZE + i * BTRFS_ITEM_SIZE;
                let item = BtrfsItem::from_bytes(&raw[off..off + BTRFS_ITEM_SIZE]);
                if item.key == key {
                    let ds   = BTRFS_HEADER_SIZE + item.offset as usize;
                    let copy = data.len().min(item.size as usize);
                    raw[ds..ds + copy].copy_from_slice(&data[..copy]);
                    let phys = self.logical_to_physical(node_logical).ok_or(-5isize)?;
                    let ns   = self.superblock.nodesize as usize;
                    let mut aligned = vec![0u8; ns];
                    let cl = raw.len().min(ns);
                    aligned[..cl].copy_from_slice(&raw[..cl]);
                    crate::drivers::block::write_sectors(phys / 512, &aligned);
                    return Ok(());
                }
            }
            Err(-28)
        } else {
            for i in 0..n {
                let po  = BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE;
                let kp  = BtrfsKeyPtr::from_bytes(&raw[po..po + BTRFS_KEY_PTR_SIZE]);
                let is_last  = i + 1 == n;
                let next_key = if !is_last {
                    let no = BTRFS_HEADER_SIZE + (i+1) * BTRFS_KEY_PTR_SIZE;
                    Some(BtrfsKeyPtr::from_bytes(&raw[no..no + BTRFS_KEY_PTR_SIZE]).key)
                } else { None };
                if next_key.map_or(true, |nk| key < nk) {
                    return self.write_leaf_item_recurse(kp.block_ptr, key, data, depth + 1);
                }
            }
            Err(-2)
        }
    }
}