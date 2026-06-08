//! Upper impl BtrfsFs: readdir, create, mkdir, unlink, rename, link, symlink,

extern crate alloc;
use super::superblock::{
    btrfs_name_hash, BtrfsDirItem, BtrfsFs, BtrfsInodeItem, BtrfsKey, BTRFS_DIR_ITEM_KEY,
    BTRFS_INODE_ITEM_KEY, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG,
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};

impl BtrfsFs {
    pub fn readdir(&self, path: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii = self.read_inode(ino).ok_or(-2isize)?;
        if ii.mode & S_IFMT != S_IFDIR {
            return Err(-20);
        }
        let items = self.lookup_items_by_type(self.fs_tree_root, ino, BTRFS_DIR_ITEM_KEY);
        let mut entries = Vec::new();
        for (_, data) in &items {
            if let Some(di) = BtrfsDirItem::from_bytes(data) {
                entries.push(crate::fs::vfs_ops::DirEntry {
                    name: di.name.clone(),
                    inode: di.child_key.objectid,
                    ty: di.ty,
                });
            }
        }
        Ok(entries)
    }

    pub fn readlink(&self, path: &str) -> Result<String, isize> {
        Ok(String::from_utf8_lossy(&self.read_all(path)?).into_owned())
    }

    pub fn statfs(&self) -> crate::fs::vfs_ops::KStatfs {
        let sb = &self.superblock;
        let bs = sb.sectorsize as u64;
        let tot = sb.total_bytes / bs;
        let used = sb.bytes_used / bs;
        crate::fs::vfs_ops::KStatfs {
            ty: 0x9123683E,
            bsize: bs as i64,
            blocks: tot as i64,
            bfree: tot.saturating_sub(used) as i64,
            bavail: tot.saturating_sub(used) as i64,
            files: 0,
            ffree: 0,
            namelen: 255,
        }
    }

    fn alloc_ino(&self) -> u64 {
        let items = self.btree_search(self.fs_tree_root, |k| {
            if k.ty == BTRFS_INODE_ITEM_KEY {
                core::cmp::Ordering::Equal
            } else if k.ty < BTRFS_INODE_ITEM_KEY {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        });
        items.iter().map(|(k, _)| k.objectid).max().unwrap_or(255) + 1
    }

    fn alloc_logical_block(&mut self, size: usize) -> u64 {
        let ns = self.superblock.nodesize as u64;
        let aligned = (self.alloc_cursor + ns - 1) & !(ns - 1);
        self.alloc_cursor = aligned + size as u64;
        aligned
    }

    pub(crate) fn insert_dirent(
        &self,
        parent_ino: u64,
        name: &str,
        child_ino: u64,
        ty: u8,
    ) -> Result<(), isize> {
        let hash = btrfs_name_hash(name.as_bytes());
        let key = BtrfsKey::new(parent_ino, BTRFS_DIR_ITEM_KEY, hash);
        let name_b = name.as_bytes();
        let mut di = vec![0u8; 30 + name_b.len()];
        di[0..8].copy_from_slice(&child_ino.to_le_bytes());
        di[8] = BTRFS_INODE_ITEM_KEY;
        di[17..25].copy_from_slice(&self.superblock.generation.to_le_bytes());
        di[27..29].copy_from_slice(&(name_b.len() as u16).to_le_bytes());
        di[29] = ty;
        di[30..30 + name_b.len()].copy_from_slice(name_b);
        self.write_leaf_item(self.fs_tree_root, key, &di)
    }

    fn remove_dirent(&self, parent_ino: u64, name: &str) -> Result<(), isize> {
        let hash = btrfs_name_hash(name.as_bytes());
        let key = BtrfsKey::new(parent_ino, BTRFS_DIR_ITEM_KEY, hash);
        self.write_leaf_item(self.fs_tree_root, key, &vec![0u8; 30 + name.len()])
    }

    fn drop_inode(&self, ino: u64) -> Result<(), isize> {
        let key = BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0);
        self.write_leaf_item(self.fs_tree_root, key, &vec![0u8; 160])
    }

    fn make_inode(&self, mode: u32, nlink: u32) -> BtrfsInodeItem {
        let ts = crate::arch::time::current_unix_time_secs();
        BtrfsInodeItem {
            generation: self.superblock.generation,
            transid: self.superblock.generation,
            size: 0,
            nbytes: 0,
            block_group: 0,
            nlink,
            uid: 0,
            gid: 0,
            mode,
            rdev: 0,
            flags: 0,
            sequence: 0,
            atime_sec: ts,
            atime_nsec: 0,
            ctime_sec: ts,
            ctime_nsec: 0,
            mtime_sec: ts,
            mtime_nsec: 0,
            otime_sec: ts,
            otime_nsec: 0,
        }
    }

    pub fn create(&mut self, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        let ino = self.alloc_ino();
        self.write_inode_item(ino, &self.make_inode(S_IFREG | 0o644, 1))?;
        self.insert_dirent(parent_ino, name, ino, 1)
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        let ino = self.alloc_ino();
        self.write_inode_item(ino, &self.make_inode(S_IFDIR | 0o755, 2))?;
        self.insert_dirent(parent_ino, name, ino, 2)
    }

    pub fn unlink(&self, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        let child_ino = self.dir_lookup(parent_ino, name).ok_or(-2isize)?;
        let ii = self.read_inode(child_ino).ok_or(-2isize)?;
        if ii.mode & S_IFMT == S_IFDIR {
            return Err(-21);
        }
        self.remove_dirent(parent_ino, name)?;
        self.drop_inode(child_ino)
    }

    pub fn rmdir(&self, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        let child_ino = self.dir_lookup(parent_ino, name).ok_or(-2isize)?;
        if !self.readdir(path)?.is_empty() {
            return Err(-39);
        }
        self.remove_dirent(parent_ino, name)?;
        self.drop_inode(child_ino)
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), isize> {
        let (op, on) = split_path(old)?;
        let (np, nn) = split_path(new)?;
        let old_parent = self.resolve_path(op).ok_or(-2isize)?;
        let new_parent = self.resolve_path(np).ok_or(-2isize)?;
        let child_ino = self.dir_lookup(old_parent, on).ok_or(-2isize)?;
        let ty = if self.read_inode(child_ino).ok_or(-2isize)?.mode & S_IFMT == S_IFDIR {
            2u8
        } else {
            1u8
        };
        self.remove_dirent(old_parent, on)?;
        self.insert_dirent(new_parent, nn, child_ino, ty)
    }

    pub fn link(&self, existing: &str, new: &str) -> Result<(), isize> {
        let (np, nn) = split_path(new)?;
        let new_parent = self.resolve_path(np).ok_or(-2isize)?;
        let child_ino = self.resolve_path(existing).ok_or(-2isize)?;
        let mut ii = self.read_inode(child_ino).ok_or(-2isize)?;
        if ii.mode & S_IFMT == S_IFDIR {
            return Err(-21);
        }
        ii.nlink += 1;
        self.write_inode_item(child_ino, &ii)?;
        self.insert_dirent(new_parent, nn, child_ino, 1)
    }

    pub fn symlink(&mut self, target: &str, path: &str) -> Result<(), isize> {
        self.create(path)?;
        self.write_all(path, target.as_bytes())?;
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let data = self
            .lookup_item(
                self.fs_tree_root,
                BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0),
            )
            .ok_or(-2isize)?;
        let mut ii = BtrfsInodeItem::from_bytes(&data);
        ii.mode = S_IFLNK | 0o777;
        self.write_inode_item(ino, &ii)
    }

    pub fn chmod(&self, path: &str, mode: u32) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let data = self
            .lookup_item(
                self.fs_tree_root,
                BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0),
            )
            .ok_or(-2isize)?;
        let mut ii = BtrfsInodeItem::from_bytes(&data);
        ii.mode = (ii.mode & S_IFMT) | (mode & 0o7777);
        self.write_inode_item(ino, &ii)
    }

    pub fn chown(&self, path: &str, uid: u32, gid: u32) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let data = self
            .lookup_item(
                self.fs_tree_root,
                BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0),
            )
            .ok_or(-2isize)?;
        let mut ii = BtrfsInodeItem::from_bytes(&data);
        ii.uid = uid;
        ii.gid = gid;
        self.write_inode_item(ino, &ii)
    }

    pub fn set_times(&self, path: &str, atime_sec: u64, mtime_sec: u64) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let data = self
            .lookup_item(
                self.fs_tree_root,
                BtrfsKey::new(ino, BTRFS_INODE_ITEM_KEY, 0),
            )
            .ok_or(-2isize)?;
        let mut ii = BtrfsInodeItem::from_bytes(&data);
        ii.atime_sec = atime_sec;
        ii.mtime_sec = mtime_sec;
        self.write_inode_item(ino, &ii)
    }

    pub fn truncate(&mut self, path: &str, new_len: u64) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii = self.read_inode(ino).ok_or(-2isize)?;
        if new_len > ii.size {
            let extra = vec![0u8; (new_len - ii.size) as usize];
            self.write_inode_data(ino, ii.size, &extra)?;
        }
        self.write_inode_size(ino, new_len)
    }
}

fn split_path(path: &str) -> Result<(&str, &str), isize> {
    let path = path.trim_end_matches('/');
    let pos = path.rfind('/').ok_or(-22isize)?;
    Ok((if pos == 0 { "/" } else { &path[..pos] }, &path[pos + 1..]))
}
