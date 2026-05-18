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
use super::mount::{parse_key, parse_inode_item, parse_dir_item,
                   parse_sys_chunk_array, parse_superblock};

impl BtrfsFs {
    /// Walk the chunk tree rooted at `chunk_root` and populate `self.chunk_map`.
    pub fn build_chunk_map(&mut self) {
        let chunk_root = self.superblock.chunk_root;
        let results = self.btree_search(chunk_root, |k| {
            if k.ty == 228 { core::cmp::Ordering::Equal } // BTRFS_CHUNK_ITEM_KEY
            else if k.ty < 228 { core::cmp::Ordering::Less }
            else { core::cmp::Ordering::Greater }
        });
        for (key, data) in results {
            if data.len() < 80 { continue; }
            let length       = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0;8]));
            let stripe_off   = u64::from_le_bytes(data[64..72].try_into().unwrap_or([0;8]));
            let chunk = BtrfsChunkItem { length, stripe_offset: stripe_off, ..Default::default() };
            let logical = key.offset;
            self.chunk_map.push((logical, logical + length, chunk));
        }
    }

    /// Resolve the fs-tree root node address from the root tree.
    pub fn resolve_fs_tree_root(&mut self) {
        let root_tree = self.root_tree_root;
        let results = self.btree_search(root_tree, |k| {
            if k.objectid < 5 { return core::cmp::Ordering::Less; }   // BTRFS_FS_TREE_OBJECTID
            if k.objectid > 5 { return core::cmp::Ordering::Greater; }
            if k.ty == 132 { core::cmp::Ordering::Equal } // BTRFS_ROOT_ITEM_KEY
            else if k.ty < 132 { core::cmp::Ordering::Less }
            else { core::cmp::Ordering::Greater }
        });
        if let Some((_, data)) = results.into_iter().next() {
            if data.len() >= 176 {
                self.fs_tree_root = u64::from_le_bytes(data[168..176].try_into().unwrap_or([0;8]));
            }
        }
    }

    pub fn readdir(&self, path: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
        let ino = {
            let mut tmp = self.clone();
            tmp.walk_path(path).ok_or(-2isize)?
        };
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        if inode.mode & 0xF000 != 0x4000 { return Err(-20); } // ENOTDIR
        let entries = self.read_dir(ino);
        Ok(entries.into_iter().map(|e| crate::fs::vfs_ops::DirEntry {
            name:   e.name,
            is_dir: e.ty == 2,
            inode:  e.key.objectid,
            mode:   0,
        }).collect())
    }

    pub fn stat(&mut self, path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
        let ino = self.lookup_inode(path).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        Ok(inode_to_kstat(ino, &inode))
    }

    pub fn read_all(&mut self, path: &str) -> Result<Vec<u8>, isize> {
        let ino   = self.lookup_inode(path).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        Ok(self.read_file_data(ino, &inode))
    }

    pub fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), isize> {
        let ino = self.lookup_inode(path).ok_or(-2isize)?;
        self.write_file_data(ino, 0, data);
        Ok(())
    }

    pub fn create(&mut self, path: &str, mode: u32) -> Result<(), isize> {
        let (parent_path, name) = split_path(path);
        let parent_ino = self.lookup_inode(parent_path).ok_or(-2isize)?;
        self.create_inode(parent_ino, name, mode).ok_or(-28isize)?;
        Ok(())
    }

    pub fn mkdir_op(&mut self, path: &str, mode: u32) -> Result<(), isize> {
        self.create(path, mode | 0o040000)
    }

    pub fn unlink_op(&mut self, path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(path);
        let parent_ino = self.lookup_inode(parent_path).ok_or(-2isize)?;
        if self.remove_dentry(parent_ino, name) { Ok(()) } else { Err(-2) }
    }

    pub fn rmdir_op(&mut self, path: &str) -> Result<(), isize> {
        // Verify empty, then remove
        let ino = self.lookup_inode(path).ok_or(-2isize)?;
        let entries: Vec<_> = self.read_dir(ino).into_iter()
            .filter(|e| e.name != "." && e.name != "..")
            .collect();
        if !entries.is_empty() { return Err(-39); } // ENOTEMPTY
        self.unlink_op(path)
    }

    pub fn rename_op(&mut self, old: &str, new: &str) -> Result<(), isize> {
        let (old_parent, old_name) = split_path(old);
        let (new_parent, new_name) = split_path(new);
        let ino           = self.lookup_inode(old).ok_or(-2isize)?;
        let old_parent_ino = self.lookup_inode(old_parent).ok_or(-2isize)?;
        let new_parent_ino = self.lookup_inode(new_parent).ok_or(-2isize)?;
        self.remove_dentry(old_parent_ino, old_name);
        self.create_inode(new_parent_ino, new_name, 0); // TODO: proper link
        Ok(())
    }

    pub fn link_op(&mut self, target: &str, link_path: &str) -> Result<(), isize> {
        let ino = self.lookup_inode(target).ok_or(-2isize)?;
        let (parent, name) = split_path(link_path);
        let parent_ino = self.lookup_inode(parent).ok_or(-2isize)?;
        // TODO: insert a new dir-item pointing at ino, increment nlink
        Ok(())
    }

    pub fn symlink_op(&mut self, target: &str, link_path: &str) -> Result<(), isize> {
        self.create(link_path, 0o120777)?;
        let ino = self.lookup_inode(link_path).ok_or(-2isize)?;
        self.write_file_data(ino, 0, target.as_bytes());
        Ok(())
    }

    pub fn chmod_op(&mut self, path: &str, mode: u32) -> Result<(), isize> {
        let ino = self.lookup_inode(path).ok_or(-2isize)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        inode.mode = (inode.mode & 0xF000) | (mode & 0xFFF);
        self.update_inode(ino, &inode);
        Ok(())
    }

    pub fn chown_op(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), isize> {
        let ino = self.lookup_inode(path).ok_or(-2isize)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        if uid != u32::MAX { inode.uid = uid; }
        if gid != u32::MAX { inode.gid = gid; }
        self.update_inode(ino, &inode);
        Ok(())
    }

    pub fn set_times_op(&mut self, path: &str, atime: u64, mtime: u64) -> Result<(), isize> {
        let ino = self.lookup_inode(path).ok_or(-2isize)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        inode.atime_sec = atime;
        inode.mtime_sec = mtime;
        self.update_inode(ino, &inode);
        Ok(())
    }

    pub fn truncate_op(&mut self, path: &str, size: u64) -> Result<(), isize> {
        let ino = self.lookup_inode(path).ok_or(-2isize)?;
        self.truncate_file(ino, size);
        Ok(())
    }

    pub fn statfs_op(&self) -> crate::fs::vfs_ops::KStatfs {
        let total = self.superblock.total_bytes;
        let used  = self.superblock.bytes_used;
        crate::fs::vfs_ops::KStatfs {
            bsize:   self.superblock.sectorsize as u64,
            blocks:  total / self.superblock.sectorsize as u64,
            bfree:   (total - used) / self.superblock.sectorsize as u64,
            bavail:  (total - used) / self.superblock.sectorsize as u64,
            namelen: 255,
        }
    }
}

fn inode_to_kstat(ino: u64, inode: &super::inode::BtrfsInodeItem) -> crate::fs::vfs_ops::KStat {
    crate::fs::vfs_ops::KStat {
        ino,
        mode:    inode.mode as u16,
        nlink:   inode.nlink,
        uid:     inode.uid,
        gid:     inode.gid,
        size:    inode.size,
        blksize: 4096,
        blocks:  (inode.nbytes + 511) / 512,
        atime:   inode.atime_sec,
        mtime:   inode.mtime_sec,
        ctime:   inode.ctime_sec,
        rdev:    inode.rdev as u32,
    }
}

fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) | None => ("/", path.trim_start_matches('/')),
        Some(i)        => (&path[..i], &path[i+1..]),
    }
}
