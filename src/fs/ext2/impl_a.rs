//! impl Ext2Fs — block/inode low-level I/O and bitmap allocation.
//! Source lines 258–640 of the original ext2.rs monolith.
extern crate alloc;
use alloc::{vec, vec::Vec, string::{String, ToString}};
use super::structs::{Ext2Fs, Inode, BgDesc, EXT2_ROOT_INO};

impl Ext2Fs {
    pub(crate) fn read_inode(&self, ino: u32) -> Option<Inode> {
        if ino == 0 { return None; }
        let ino_idx   = ino - 1;
        let group     = ino_idx / self.sb.inodes_per_group;
        let local_idx = ino_idx % self.sb.inodes_per_group;
        let gd        = self.read_group_desc(group)?;
        let inode_size= self.sb.inode_size();
        let offset_in_table = local_idx as usize * inode_size;
        let block_in_table  = offset_in_table / self.block_size;
        let offset_in_block = offset_in_table % self.block_size;
        let block = self.read_block(gd.inode_table + block_in_table as u32);
        Some(Inode::from_bytes(&block[offset_in_block..]))
    }

    pub(crate) fn write_inode(&self, ino: u32, inode: &Inode) -> Result<(), isize> {
        if ino == 0 { return Err(-22); }
        let ino_idx   = ino - 1;
        let group     = ino_idx / self.sb.inodes_per_group;
        let local_idx = ino_idx % self.sb.inodes_per_group;
        let gd        = self.read_group_desc(group).ok_or(-5isize)?;
        let inode_size= self.sb.inode_size();
        let offset_in_table = local_idx as usize * inode_size;
        let block_idx       = (gd.inode_table as usize) + offset_in_table / self.block_size;
        let offset_in_block = offset_in_table % self.block_size;
        let mut block = self.read_block(block_idx as u32);
        let bytes = inode.to_bytes();
        block[offset_in_block..offset_in_block + bytes.len()].copy_from_slice(&bytes);
        self.write_block(block_idx as u32, &block);
        Ok(())
    }

    pub(crate) fn read_block_indirect(
        &self, block_no: u32, depth: u32, data: &mut Vec<u8>, remaining: &mut usize,
    ) {
        if *remaining == 0 { return; }
        if depth == 0 {
            if block_no == 0 {
                let take = self.block_size.min(*remaining);
                data.extend(core::iter::repeat(0u8).take(take));
                *remaining -= take;
            } else {
                let b = self.read_block(block_no);
                let take = b.len().min(*remaining);
                data.extend_from_slice(&b[..take]);
                *remaining -= take;
            }
            return;
        }
        let ptrs = self.read_block(block_no);
        let ptrs_per_block = self.block_size / 4;
        for i in 0..ptrs_per_block {
            if *remaining == 0 { break; }
            let ptr = u32::from_le_bytes(ptrs[i*4..i*4+4].try_into().unwrap());
            self.read_block_indirect(ptr, depth - 1, data, remaining);
        }
    }

    pub(crate) fn read_inode_data(&self, inode: &Inode) -> Vec<u8> {
        let file_size = inode.file_size() as usize;
        let mut data  = Vec::with_capacity(file_size);
        let mut remaining = file_size;
        // Direct blocks (0..11)
        for i in 0..12usize {
            if remaining == 0 { break; }
            self.read_block_indirect(inode.block[i], 0, &mut data, &mut remaining);
        }
        // Singly indirect (12)
        if remaining > 0 && inode.block[12] != 0 {
            self.read_block_indirect(inode.block[12], 1, &mut data, &mut remaining);
        }
        // Doubly indirect (13)
        if remaining > 0 && inode.block[13] != 0 {
            self.read_block_indirect(inode.block[13], 2, &mut data, &mut remaining);
        }
        // Triply indirect (14)
        if remaining > 0 && inode.block[14] != 0 {
            self.read_block_indirect(inode.block[14], 3, &mut data, &mut remaining);
        }
        data.truncate(file_size);
        data
    }

    pub(crate) fn write_block_data(
        &mut self, inode: &mut Inode, ino: u32, data: &[u8],
    ) -> Result<(), isize> {
        // Simple strategy: allocate fresh blocks for the entire file
        let block_size = self.block_size;
        let n_blocks   = (data.len() + block_size - 1) / block_size;
        if n_blocks > 12 { return Err(-28); } // only direct blocks supported in write path
        // Free old blocks
        for i in 0..12usize {
            if inode.block[i] != 0 {
                self.free_block(inode.block[i]);
                inode.block[i] = 0;
            }
        }
        // Allocate and write new blocks
        for i in 0..n_blocks {
            let blk = self.alloc_block().ok_or(-28isize)?;
            let start = i * block_size;
            let end   = (start + block_size).min(data.len());
            let mut buf = vec![0u8; block_size];
            buf[..end - start].copy_from_slice(&data[start..end]);
            self.write_block(blk, &buf);
            inode.block[i] = blk;
        }
        inode.size = data.len() as u32;
        inode.blocks = (n_blocks * block_size / 512) as u32;
        Ok(())
    }

    fn free_block(&mut self, blkno: u32) {
        let group     = (blkno - self.sb.first_data_block) / self.sb.blocks_per_group;
        let local_bit = (blkno - self.sb.first_data_block) % self.sb.blocks_per_group;
        let mut gd = match self.read_group_desc(group) { Some(g) => g, None => return };
        let mut bmap = self.read_block(gd.block_bitmap);
        let byte = (local_bit / 8) as usize;
        let bit  = local_bit % 8;
        if byte < bmap.len() {
            bmap[byte] &= !(1 << bit);
            self.write_block(gd.block_bitmap, &bmap);
            gd.free_blocks = gd.free_blocks.saturating_add(1);
            self.write_group_desc(group, &gd);
        }
    }

    fn alloc_inode(&mut self, is_dir: bool) -> Option<u32> {
        for g in 0..self.group_descs.len() {
            let gd = self.group_descs[g].clone();
            if gd.free_inodes == 0 { continue; }
            let mut imap = self.read_block(gd.inode_bitmap);
            let inodes_in_group = self.sb.inodes_per_group as usize;
            for i in 0..inodes_in_group {
                let byte = i / 8;
                let bit  = i % 8;
                if byte >= imap.len() { break; }
                if imap[byte] & (1 << bit) == 0 {
                    imap[byte] |= 1 << bit;
                    self.write_block(gd.inode_bitmap, &imap);
                    let mut gd2 = gd.clone();
                    gd2.free_inodes -= 1;
                    if is_dir { gd2.used_dirs += 1; }
                    self.write_group_desc(g as u32, &gd2);
                    return Some((g as u32 * self.sb.inodes_per_group) + i as u32 + 1);
                }
            }
        }
        None
    }

    fn alloc_block(&mut self) -> Option<u32> {
        for g in 0..self.group_descs.len() {
            let gd = self.group_descs[g].clone();
            if gd.free_blocks == 0 { continue; }
            let mut bmap = self.read_block(gd.block_bitmap);
            let blocks_in_group = self.sb.blocks_per_group as usize;
            for i in 0..blocks_in_group {
                let byte = i / 8;
                let bit  = i % 8;
                if byte >= bmap.len() { break; }
                if bmap[byte] & (1 << bit) == 0 {
                    bmap[byte] |= 1 << bit;
                    self.write_block(gd.block_bitmap, &bmap);
                    let mut gd2 = gd.clone();
                    gd2.free_blocks -= 1;
                    self.write_group_desc(g as u32, &gd2);
                    return Some(self.sb.first_data_block
                        + g as u32 * self.sb.blocks_per_group + i as u32);
                }
            }
        }
        None
    }

    pub(crate) fn write_group_desc(&mut self, group: u32, gd: &BgDesc) {
        if let Some(slot) = self.group_descs.get_mut(group as usize) {
            *slot = gd.clone();
        }
        // Flush to disk: group descriptor table starts at block after superblock
        let bgdt_block = self.sb.first_data_block + 1;
        let gd_size    = 32usize;
        let per_block  = self.block_size / gd_size;
        let blk_idx    = bgdt_block + group / per_block as u32;
        let offset     = (group as usize % per_block) * gd_size;
        let mut block  = self.read_block(blk_idx);
        block[offset..offset + gd_size].copy_from_slice(&gd.to_bytes()[..gd_size]);
        self.write_block(blk_idx, &block);
    }
}