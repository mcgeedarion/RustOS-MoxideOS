//! impl Ext2Fs — path resolution, directory operations, metadata.
//! Source lines 641–1034 of the original ext2.rs monolith.
extern crate alloc;
use alloc::{vec, vec::Vec, string::{String, ToString}};
use super::structs::{Ext2Fs, Inode, DirEntry, Ext2Stat, Ext2DirEntry,
                     Ext2Statfs, EXT2_ROOT_INO, EXT2_S_IFMT, EXT2_S_IFDIR,
                     EXT2_S_IFREG, EXT2_S_IFLNK};

impl Ext2Fs {
    pub(crate) fn resolve_path(&self, path: &str) -> Option<u32> {
        let mut ino = EXT2_ROOT_INO;
        let path = path.trim_start_matches('/');
        if path.is_empty() { return Some(ino); }
        for component in path.split('/') {
            if component.is_empty() { continue; }
            ino = self.dir_lookup(ino, component)?;
        }
        Some(ino)
    }

    pub(crate) fn dir_lookup(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let inode = self.read_inode(dir_ino)?;
        if inode.mode & EXT2_S_IFMT != EXT2_S_IFDIR { return None; }
        let data  = self.read_inode_data(&inode);
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = DirEntry::from_bytes(&data[off..])?;
            if de.rec_len == 0 { break; }
            if de.inode != 0 && de.name == name { return Some(de.inode); }
            off += de.rec_len as usize;
        }
        None
    }

    pub(crate) fn read_dir_entries(&self, dir_ino: u32) -> Vec<DirEntry> {
        let inode = match self.read_inode(dir_ino) { Some(i) => i, None => return vec![] };
        let data  = self.read_inode_data(&inode);
        let mut entries = Vec::new();
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = match DirEntry::from_bytes(&data[off..]) { Some(d) => d, None => break };
            if de.rec_len == 0 { break; }
            if de.inode != 0 { entries.push(de.clone()); }
            off += de.rec_len as usize;
        }
        entries
    }

    fn append_dirent(
        &mut self, dir_ino: u32, child_ino: u32, name: &str, file_type: u8,
    ) -> Result<(), isize> {
        let inode = self.read_inode(dir_ino).ok_or(-2isize)?;
        let mut data = self.read_inode_data(&inode);
        // Find last real entry and expand its rec_len, then append
        let name_b   = name.as_bytes();
        let new_real = (8 + name_b.len() + 3) & !3;
        let block_size = self.block_size;
        // Walk to find last entry
        let mut last_off = 0usize;
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = DirEntry::from_bytes(&data[off..]).ok_or(-5isize)?;
            if de.rec_len == 0 { break; }
            last_off = off;
            off += de.rec_len as usize;
        }
        // Trim last entry rec_len to its real size
        let last_de = DirEntry::from_bytes(&data[last_off..]).ok_or(-5isize)?;
        let last_real = (8 + last_de.name_len as usize + 3) & !3;
        let last_rec  = last_de.rec_len as usize;
        let gap_off   = last_off + last_real;
        let gap_len   = last_off + last_rec - gap_off;
        if gap_len < new_real {
            // Need to extend directory data
            let new_block_count =
                (data.len() + new_real + block_size - 1) / block_size * block_size;
            data.resize(new_block_count, 0);
        }
        // Shrink last entry's rec_len
        let new_last_rec = last_real as u16;
        data[last_off + 4..last_off + 6].copy_from_slice(&new_last_rec.to_le_bytes());
        // Write new entry
        let entry_off = gap_off;
        let remaining = data.len() - entry_off;
        data[entry_off..entry_off + 4].copy_from_slice(&child_ino.to_le_bytes());
        data[entry_off + 4..entry_off + 6]
            .copy_from_slice(&(remaining as u16).to_le_bytes());
        data[entry_off + 6] = name_b.len() as u8;
        data[entry_off + 7] = file_type;
        data[entry_off + 8..entry_off + 8 + name_b.len()].copy_from_slice(name_b);
        // Write back
        let mut inode2 = inode.clone();
        self.write_block_data(&mut inode2, dir_ino, &data)?;
        inode2.mtime = crate::arch::time::current_unix_time_secs() as u32;
        self.write_inode(dir_ino, &inode2)
    }

    fn remove_dirent(&mut self, dir_ino: u32, name: &str) -> Result<(), isize> {
        let inode = self.read_inode(dir_ino).ok_or(-2isize)?;
        let mut data  = self.read_inode_data(&inode);
        let mut off   = 0usize;
        let mut prev_off: Option<usize> = None;
        loop {
            if off + 8 > data.len() { return Err(-2); }
            let de = DirEntry::from_bytes(&data[off..]).ok_or(-5isize)?;
            if de.rec_len == 0 { return Err(-2); }
            if de.inode != 0 && de.name == name {
                if let Some(po) = prev_off {
                    let prev_rec = u16::from_le_bytes(
                        data[po + 4..po + 6].try_into().unwrap()) as usize;
                    let new_rec  = (prev_rec + de.rec_len as usize) as u16;
                    data[po + 4..po + 6].copy_from_slice(&new_rec.to_le_bytes());
                } else {
                    // First entry — zero it
                    data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
                }
                let mut inode2 = inode.clone();
                self.write_block_data(&mut inode2, dir_ino, &data)?;
                return Ok(());
            }
            prev_off = Some(off);
            off += de.rec_len as usize;
        }
    }

    fn alloc_inode_entry(
        &mut self, parent_ino: u32, name: &str, mode: u16, is_dir: bool,
    ) -> Result<u32, isize> {
        let ino = self.alloc_inode(is_dir).ok_or(-28isize)?;
        let ts  = crate::arch::time::current_unix_time_secs() as u32;
        let new_inode = Inode {
            mode, uid: 0, size: 0,
            atime: ts, ctime: ts, mtime: ts, dtime: 0,
            gid: 0, links_count: 1, blocks: 0, flags: 0,
            block: [0u32; 15],
            generation: 0, file_acl: 0, dir_acl: 0, faddr: 0,
            uid_high: 0, gid_high: 0, inode_size: 0,
        };
        self.write_inode(ino, &new_inode)?;
        let ft = if is_dir { 2u8 } else { 1u8 };
        self.append_dirent(parent_ino, ino, name, ft)?;
        Ok(ino)
    }

    pub(crate) fn stat_ino(&self, ino: u32) -> Result<Ext2Stat, isize> {
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        Ok(Ext2Stat {
            ino,
            mode:   inode.mode,
            uid:    inode.uid as u32 | ((inode.uid_high as u32) << 16),
            gid:    inode.gid as u32 | ((inode.gid_high as u32) << 16),
            size:   inode.file_size(),
            atime:  inode.atime,
            mtime:  inode.mtime,
            ctime:  inode.ctime,
            nlink:  inode.links_count,
            blocks: inode.blocks,
        })
    }

    pub(crate) fn do_stat(&self, path: &str, follow: bool) -> Result<Ext2Stat, isize> {
        let ino = if follow {
            self.resolve_path(path).ok_or(-2isize)?
        } else {
            // lstat: only skip the final symlink resolution
            let (parent, name) = split_path(path)?;
            let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
            self.dir_lookup(parent_ino, name).ok_or(-2isize)?
        };
        self.stat_ino(ino)
    }

    pub(crate) fn do_readdir(&self, path: &str) -> Result<Vec<Ext2DirEntry>, isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT != EXT2_S_IFDIR { return Err(-20); }
        let raw = self.read_dir_entries(ino);
        Ok(raw.into_iter().map(|de| Ext2DirEntry {
            inode: de.inode,
            name:  de.name,
            file_type: de.file_type,
        }).collect())
    }

    pub(crate) fn do_readlink(&self, path: &str) -> Result<String, isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT != EXT2_S_IFLNK { return Err(-22); }
        // Fast symlink: target stored in block array
        if inode.file_size() <= 60 {
            let raw: &[u8] = unsafe {
                core::slice::from_raw_parts(inode.block.as_ptr() as *const u8, 60)
            };
            let len = inode.file_size() as usize;
            return Ok(String::from_utf8_lossy(&raw[..len]).into_owned());
        }
        let data = self.read_inode_data(&inode);
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    pub(crate) fn do_truncate(&mut self, path: &str, len: u64) -> Result<(), isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        let cur = inode.file_size();
        if len == cur { return Ok(()); }
        if len < cur {
            // Shrink
            let mut data = self.read_inode_data(&inode);
            data.truncate(len as usize);
            self.write_block_data(&mut inode, ino, &data)?;
        } else {
            // Extend with zeros
            let mut data = self.read_inode_data(&inode);
            data.resize(len as usize, 0);
            self.write_block_data(&mut inode, ino, &data)?;
        }
        self.write_inode(ino, &inode)
    }

    pub(crate) fn do_create_file(
        &mut self, path: &str, mode: u16,
    ) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        self.alloc_inode_entry(parent_ino, name, EXT2_S_IFREG | mode, false)?;
        Ok(())
    }

    pub(crate) fn do_mkdir(&mut self, path: &str, mode: u16) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        let new_ino = self.alloc_inode_entry(parent_ino, name,
            EXT2_S_IFDIR | mode, true)?;
        // Add . and .. entries
        self.append_dirent(new_ino, new_ino, ".", 2)?;
        self.append_dirent(new_ino, parent_ino, "..", 2)?;
        // Bump parent link count
        let mut parent_inode = self.read_inode(parent_ino).ok_or(-2isize)?;
        parent_inode.links_count += 1;
        self.write_inode(parent_ino, &parent_inode)
    }

    pub(crate) fn do_rmdir(&mut self, path: &str) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let entries = self.read_dir_entries(ino);
        let non_dot = entries.iter().filter(|e| e.name != "." && e.name != "..").count();
        if non_dot > 0 { return Err(-39); } // ENOTEMPTY
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        self.remove_dirent(parent_ino, name)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        inode.dtime = crate::arch::time::current_unix_time_secs() as u32;
        inode.links_count = 0;
        self.write_inode(ino, &inode)?;
        let mut parent_inode = self.read_inode(parent_ino).ok_or(-2isize)?;
        parent_inode.links_count = parent_inode.links_count.saturating_sub(1);
        self.write_inode(parent_ino, &parent_inode)
    }

    pub(crate) fn do_unlink(&mut self, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        let ino = self.dir_lookup(parent_ino, name).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT == EXT2_S_IFDIR { return Err(-21); }
        self.remove_dirent(parent_ino, name)?;
        let mut inode2 = inode.clone();
        inode2.links_count = inode.links_count.saturating_sub(1);
        if inode2.links_count == 0 {
            inode2.dtime = crate::arch::time::current_unix_time_secs() as u32;
        }
        self.write_inode(ino, &inode2)
    }

    pub(crate) fn do_rename(&mut self, old: &str, new: &str) -> Result<(), isize> {
        let (old_parent, old_name) = split_path(old)?;
        let (new_parent, new_name) = split_path(new)?;
        let old_parent_ino = self.resolve_path(old_parent).ok_or(-2isize)?;
        let new_parent_ino = self.resolve_path(new_parent).ok_or(-2isize)?;
        let child_ino = self.dir_lookup(old_parent_ino, old_name).ok_or(-2isize)?;
        let inode     = self.read_inode(child_ino).ok_or(-2isize)?;
        let ft = if inode.mode & EXT2_S_IFMT == EXT2_S_IFDIR { 2u8 } else { 1u8 };
        self.remove_dirent(old_parent_ino, old_name)?;
        self.append_dirent(new_parent_ino, child_ino, new_name, ft)
    }

    pub(crate) fn do_link(&mut self, existing: &str, new: &str) -> Result<(), isize> {
        let (new_parent, new_name) = split_path(new)?;
        let new_parent_ino = self.resolve_path(new_parent).ok_or(-2isize)?;
        let child_ino = self.resolve_path(existing).ok_or(-2isize)?;
        let mut inode = self.read_inode(child_ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT == EXT2_S_IFDIR { return Err(-21); }
        self.append_dirent(new_parent_ino, child_ino, new_name, 1)?;
        inode.links_count += 1;
        self.write_inode(child_ino, &inode)
    }

    pub(crate) fn do_symlink(&mut self, target: &str, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent).ok_or(-2isize)?;
        let ino = self.alloc_inode_entry(parent_ino, name, EXT2_S_IFLNK | 0o777, false)?;
        let target_b = target.as_bytes();
        if target_b.len() <= 60 {
            // Fast symlink
            let mut inode = self.read_inode(ino).ok_or(-2isize)?;
            let raw: &mut [u8] = unsafe {
                core::slice::from_raw_parts_mut(inode.block.as_mut_ptr() as *mut u8, 60)
            };
            raw[..target_b.len()].copy_from_slice(target_b);
            inode.size = target_b.len() as u32;
            return self.write_inode(ino, &inode);
        }
        // Slow symlink
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        self.write_block_data(&mut inode, ino, target_b)?;
        self.write_inode(ino, &inode)
    }

    pub(crate) fn do_chmod(&mut self, path: &str, mode: u16) -> Result<(), isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        inode.mode = (inode.mode & EXT2_S_IFMT) | (mode & 0o7777);
        self.write_inode(ino, &inode)
    }

    pub(crate) fn do_chown(
        &mut self, path: &str, uid: u32, gid: u32,
    ) -> Result<(), isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        inode.uid      = uid as u16;
        inode.uid_high = (uid >> 16) as u16;
        inode.gid      = gid as u16;
        inode.gid_high = (gid >> 16) as u16;
        self.write_inode(ino, &inode)
    }

    pub(crate) fn do_set_times(
        &mut self, path: &str, atime_ns: u64, mtime_ns: u64,
    ) -> Result<(), isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        inode.atime = (atime_ns / 1_000_000_000) as u32;
        inode.mtime = (mtime_ns / 1_000_000_000) as u32;
        self.write_inode(ino, &inode)
    }

    pub fn statfs(&self) -> Ext2Statfs {
        Ext2Statfs {
            block_size:   self.block_size as u32,
            total_blocks: self.sb.blocks_count,
            free_blocks:  self.sb.free_blocks_count,
            total_inodes: self.sb.inodes_count,
            free_inodes:  self.sb.free_inodes_count,
        }
    }
}

pub(crate) fn split_path(path: &str) -> Result<(&str, &str), isize> {
    let path = path.trim_end_matches('/');
    let pos  = path.rfind('/').ok_or(-22isize)?;
    let parent = if pos == 0 { "/" } else { &path[..pos] };
    Ok((parent, &path[pos + 1..]))
}