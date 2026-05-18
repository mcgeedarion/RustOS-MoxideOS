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
    pub fn read_inode(&self, ino: u64) -> Option<super::inode::BtrfsInodeItem> {
        let key = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        let data = self.btree_search(self.fs_tree_root, &key)?;
        if data.len() < core::mem::size_of::<super::inode::BtrfsInodeItem>() { return None; }
        Some(unsafe { *(data.as_ptr() as *const super::inode::BtrfsInodeItem) })
    }

    pub fn resolve_path(&self, path: &str) -> Option<u64> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        let mut ino = crate::fs::btrfs::superblock::BTRFS_ROOT_TREE_DIR_OBJECTID as u64;
        for part in parts {
            ino = self.lookup_dir(ino, part)?;
        }
        Some(ino)
    }

    pub fn lookup_dir(&self, dir_ino: u64, name: &str) -> Option<u64> {
        use super::directory::BtrfsDirItem;
        let min = BtrfsKey::new(dir_ino, BTRFS_DIR_ITEM_KEY, 0);
        let max = BtrfsKey::new(dir_ino, BTRFS_DIR_ITEM_KEY, u64::MAX);
        let entries = self.btree_search_range(self.fs_tree_root, &min, &max);
        for (_, data) in entries {
            if data.len() < 30 { continue; }
            let di = BtrfsDirItem::from_bytes(&data);
            let name_bytes = di.name(&data);
            if name_bytes == name.as_bytes() {
                return Some(di.child_key.objectid);
            }
        }
        None
    }

    pub fn read_all(&self, path: &str) -> Result<Vec<u8>, isize> {
        let ino    = self.resolve_path(path).ok_or(-2isize)?;
        let inode  = self.read_inode(ino).ok_or(-5isize)?;
        let size   = { let s = inode; unsafe { core::ptr::read_unaligned(&s.size as *const u64) } };
        self.read_inode_data(ino, size)
    }

    fn read_inode_data(&self, ino: u64, file_size: u64) -> Result<Vec<u8>, isize> {
        use super::extent::BtrfsFileExtentItem;
        let min = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, 0);
        let max = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, u64::MAX);
        let extents = self.btree_search_range(self.fs_tree_root, &min, &max);

        let mut out = vec![0u8; file_size as usize];
        for (key, data) in extents {
            let file_off = key.offset as usize;
            if data.len() < 21 { continue; }
            let ext_type = data[20];
            if ext_type == BTRFS_FILE_EXTENT_INLINE {
                let inline_data = &data[21..];
                let end = (file_off + inline_data.len()).min(out.len());
                if file_off < out.len() {
                    out[file_off..end].copy_from_slice(&inline_data[..end - file_off]);
                }
            } else if ext_type == BTRFS_FILE_EXTENT_REG || ext_type == BTRFS_FILE_EXTENT_PREALLOC {
                if data.len() < core::mem::size_of::<BtrfsFileExtentItem>() + 21 { continue; }
                let fei: BtrfsFileExtentItem = unsafe {
                    core::ptr::read_unaligned(data.as_ptr().add(21) as *const BtrfsFileExtentItem)
                };
                let disk_bytenr  = unsafe { core::ptr::read_unaligned(&fei.disk_bytenr) };
                let disk_bytes   = unsafe { core::ptr::read_unaligned(&fei.disk_num_bytes) };
                let extent_off   = unsafe { core::ptr::read_unaligned(&fei.offset) };
                let num_bytes    = unsafe { core::ptr::read_unaligned(&fei.num_bytes) };
                if disk_bytenr == 0 { continue; } // hole
                let Some(phys) = self.logical_to_physical(disk_bytenr) else { continue; };
                let lba   = phys / 512;
                let count = (disk_bytes + 511) / 512;
                let raw   = block_read(lba, count as u32);
                let src_off = extent_off as usize;
                let copy_len = (num_bytes as usize).min(out.len().saturating_sub(file_off));
                if src_off + copy_len <= raw.len() && file_off + copy_len <= out.len() {
                    out[file_off..file_off+copy_len].copy_from_slice(&raw[src_off..src_off+copy_len]);
                }
            }
        }
        Ok(out)
    }

    pub fn readdir(&self, path: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
        use super::directory::BtrfsDirItem;
        let dir_ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii = self.read_inode(dir_ino).ok_or(-5isize)?;
        let mode = unsafe { core::ptr::read_unaligned(&ii.mode) };
        if mode & 0xF000 != 0x4000 { return Err(-20); } // ENOTDIR
        let min = BtrfsKey::new(dir_ino, BTRFS_DIR_ITEM_KEY, 0);
        let max = BtrfsKey::new(dir_ino, BTRFS_DIR_ITEM_KEY, u64::MAX);
        let items = self.btree_search_range(self.fs_tree_root, &min, &max);
        let mut out = Vec::new();
        for (_, data) in items {
            if data.len() < 30 { continue; }
            let di   = BtrfsDirItem::from_bytes(&data);
            let name = String::from_utf8_lossy(di.name(&data)).into_owned();
            let child_ino = di.child_key.objectid;
            let (child_mode, child_size) = self.read_inode(child_ino)
                .map(|ii| {
                    let m = unsafe { core::ptr::read_unaligned(&ii.mode) };
                    let s = unsafe { core::ptr::read_unaligned(&ii.size) };
                    (m, s)
                })
                .unwrap_or((0, 0));
            out.push(crate::fs::vfs_ops::DirEntry {
                name,
                ino:    child_ino,
                is_dir: child_mode & 0xF000 == 0x4000,
                mode:   child_mode as u32,
                size:   child_size,
            });
        }
        Ok(out)
    }
}