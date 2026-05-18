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
    pub fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-5isize)?;
        let old_size = unsafe { core::ptr::read_unaligned(&inode.size) };
        let new_size = data.len() as u64;

        // Allocate a logical address for this extent
        let logical = self.alloc_logical(data.len() as u64);
        let phys    = self.logical_to_physical(logical).ok_or(-5isize)?;
        let lba     = phys / 512;
        let pad_len = align_up(data.len() as u64, 512) as usize;
        let mut sector_buf = vec![0u8; pad_len];
        sector_buf[..data.len()].copy_from_slice(data);
        block_write(lba, &sector_buf);

        // Update inode size in the tree
        self.update_inode_size(ino, new_size)?;
        // Insert / replace extent data key
        self.insert_extent_item(ino, 0, logical, data.len() as u64)?;
        Ok(())
    }

    pub fn create(&mut self, path: &str, mode: u32) -> Result<u64, isize> {
        let (parent_path, name) = split_path(path);
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        let new_ino    = self.alloc_ino();
        self.insert_inode(new_ino, mode, 0)?;
        self.insert_dir_item(parent_ino, name, new_ino, BTRFS_FT_REG_FILE)?;
        Ok(new_ino)
    }

    pub fn mkdir(&mut self, path: &str, mode: u32) -> Result<(), isize> {
        let (parent_path, name) = split_path(path);
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        let new_ino    = self.alloc_ino();
        self.insert_inode(new_ino, mode | 0x4000, 0)?;
        self.insert_dir_item(parent_ino, name, new_ino, BTRFS_FT_DIR)?;
        Ok(())
    }

    pub fn unlink(&mut self, path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(path);
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        let ino        = self.lookup_dir(parent_ino, name).ok_or(-2isize)?;
        self.remove_dir_item(parent_ino, name)?;
        self.remove_inode(ino);
        Ok(())
    }

    pub fn rename(&mut self, src: &str, dst: &str) -> Result<(), isize> {
        let (src_parent, src_name) = split_path(src);
        let (dst_parent, dst_name) = split_path(dst);
        let src_parent_ino = self.resolve_path(src_parent).ok_or(-2isize)?;
        let dst_parent_ino = self.resolve_path(dst_parent).ok_or(-2isize)?;
        let ino = self.lookup_dir(src_parent_ino, src_name).ok_or(-2isize)?;
        let ft  = self.inode_file_type(ino);
        self.remove_dir_item(src_parent_ino, src_name)?;
        self.insert_dir_item(dst_parent_ino, dst_name, ino, ft)?;
        Ok(())
    }

    pub fn symlink(&mut self, target: &str, link_path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(link_path);
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        let new_ino    = self.alloc_ino();
        self.insert_inode(new_ino, 0xA1FF, target.len() as u64)?;
        self.insert_inline_extent(new_ino, target.as_bytes())?;
        self.insert_dir_item(parent_ino, name, new_ino, BTRFS_FT_SYMLINK)?;
        Ok(())
    }

    pub fn readlink(&self, path: &str) -> Result<String, isize> {
        let ino  = self.resolve_path(path).ok_or(-2isize)?;
        let data = self.read_inode_data(ino, 4096)?;
        Ok(String::from_utf8_lossy(&data).trim_end_matches('\0').to_string())
    }

    fn read_inode_data(&self, ino: u64, max_bytes: u64) -> Result<Vec<u8>, isize> {
        let key = BtrfsKey::new(ino, BTRFS_EXTENT_DATA_KEY, 0);
        if let Some(data) = self.btree_search(self.fs_tree_root, &key) {
            if data.len() > 21 && data[20] == BTRFS_FILE_EXTENT_INLINE {
                return Ok(data[21..].to_vec());
            }
        }
        Ok(vec![0u8; max_bytes as usize])
    }

    pub fn chmod(&mut self, path: &str, mode: u32) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        self.update_inode_mode(ino, mode as u16)
    }

    pub fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        self.update_inode_ownership(ino, uid, gid)
    }

    pub fn truncate(&mut self, path: &str, new_size: u64) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        self.update_inode_size(ino, new_size)
    }

    pub fn set_times(&mut self, path: &str, atime: u64, mtime: u64) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        self.update_inode_times(ino, atime, mtime)
    }

    // ── internal helpers ───────────────────────────────────────────────────

    fn alloc_logical(&mut self, size: u64) -> u64 {
        let addr = self.alloc_cursor;
        self.alloc_cursor += align_up(size, 4096);
        addr
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.alloc_cursor | 0xFF00_0000_0000_0000;
        self.alloc_cursor += 1;
        ino
    }

    fn inode_file_type(&self, ino: u64) -> u8 {
        self.read_inode(ino).map(|ii| {
            let mode = unsafe { core::ptr::read_unaligned(&ii.mode) };
            match mode & 0xF000 {
                0x4000 => BTRFS_FT_DIR,
                0xA000 => BTRFS_FT_SYMLINK,
                _      => BTRFS_FT_REG_FILE,
            }
        }).unwrap_or(BTRFS_FT_REG_FILE)
    }

    fn insert_inode(&mut self, ino: u64, mode: u32, size: u64) -> Result<(), isize> {
        // Stub: in a real CoW tree this would insert a new BtrfsInodeItem leaf
        Ok(())
    }

    fn insert_dir_item(&mut self, dir_ino: u64, name: &str, child_ino: u64, ft: u8)
        -> Result<(), isize>
    { Ok(()) }

    fn remove_dir_item(&mut self, dir_ino: u64, name: &str) -> Result<(), isize> { Ok(()) }
    fn remove_inode(&mut self, ino: u64) {}

    fn insert_extent_item(&mut self, ino: u64, file_off: u64, logical: u64, len: u64)
        -> Result<(), isize>
    { Ok(()) }

    fn insert_inline_extent(&mut self, ino: u64, data: &[u8]) -> Result<(), isize> { Ok(()) }

    fn update_inode_size(&mut self, ino: u64, size: u64) -> Result<(), isize> { Ok(()) }
    fn update_inode_mode(&mut self, ino: u64, mode: u16) -> Result<(), isize> { Ok(()) }
    fn update_inode_ownership(&mut self, ino: u64, uid: u32, gid: u32) -> Result<(), isize> { Ok(()) }
    fn update_inode_times(&mut self, ino: u64, atime: u64, mtime: u64) -> Result<(), isize> { Ok(()) }
}

fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..i.max(1)], &path[i+1..]),
        None    => ("/", path),
    }
}

fn align_up(n: u64, align: u64) -> u64 { (n + align - 1) & !(align - 1) }