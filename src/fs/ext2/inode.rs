//! ext2 on-disk structures, inode types, and all Ext2Fs impl methods.
//! Merged from inode.rs + structs.rs + impl_a.rs + impl_b.rs
extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use super::superblock::*;
use super::block::*;
use super::bitmap::*;
use super::directory::*;
use super::symlink::*;
use crate::fs::vfs_ops::{KStat, KStatfs, DirEntry};

// ── on-disk types (from structs.rs) ──────────────────────────────────────────────────────
use spin::Mutex;

const EXT2_SUPER_MAGIC: u16 = 0xEF53;
const EXT2_ROOT_INO:    u32 = 2;
const EXT2_S_IFMT:      u16 = 0xF000;
const EXT2_S_IFREG:     u16 = 0x8000;
const EXT2_S_IFDIR:     u16 = 0x4000;
const EXT2_S_IFLNK:     u16 = 0xA000;

fn block_read(lba: u64, count: u32) -> Vec<u8> {
    let mut buf = vec![0u8; count as usize * 512];
    crate::drivers::block::read_sectors(lba, count, &mut buf);
    buf
}

fn block_write(lba: u64, data: &[u8]) {
    debug_assert!(data.len() % 512 == 0);
    crate::drivers::block::write_sectors(lba, data);
}

#[derive(Clone, Debug)]
struct Superblock {
    inodes_count: u32, blocks_count: u32, r_blocks_count: u32,
    free_blocks_count: u32, free_inodes_count: u32, first_data_block: u32,
    log_block_size: u32, log_frag_size: u32, blocks_per_group: u32,
    frags_per_group: u32, inodes_per_group: u32,
    mtime: u32, wtime: u32, mnt_count: u16, max_mnt_count: u16,
    magic: u16, state: u16, errors: u16, minor_rev_level: u16,
    lastcheck: u32, checkinterval: u32, creator_os: u32,
    rev_level: u32, def_resuid: u16, def_resgid: u16,
    first_ino: u32, inode_size: u16, block_group_nr: u16,
    feature_compat: u32, feature_incompat: u32, feature_ro_compat: u32,
    uuid: [u8; 16], volume_name: [u8; 16], last_mounted: [u8; 64],
    algo_bitmap: u32,
}

impl Superblock {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 1024 { return None; }
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        if r16(56) != EXT2_SUPER_MAGIC { return None; }
        let mut uuid = [0u8;16]; uuid.copy_from_slice(&b[104..120]);
        let mut vn   = [0u8;16]; vn.copy_from_slice(&b[120..136]);
        let mut lm   = [0u8;64]; lm.copy_from_slice(&b[136..200]);
        Some(Superblock {
            inodes_count: r32(0), blocks_count: r32(4), r_blocks_count: r32(8),
            free_blocks_count: r32(12), free_inodes_count: r32(16),
            first_data_block: r32(20), log_block_size: r32(24), log_frag_size: r32(28),
            blocks_per_group: r32(32), frags_per_group: r32(36), inodes_per_group: r32(40),
            mtime: r32(44), wtime: r32(48), mnt_count: r16(52), max_mnt_count: r16(54),
            magic: r16(56), state: r16(58), errors: r16(60), minor_rev_level: r16(62),
            lastcheck: r32(64), checkinterval: r32(68), creator_os: r32(72),
            rev_level: r32(76), def_resuid: r16(80), def_resgid: r16(82),
            first_ino: r32(84), inode_size: r16(88), block_group_nr: r16(90),
            feature_compat: r32(92), feature_incompat: r32(96), feature_ro_compat: r32(100),
            uuid, volume_name: vn, last_mounted: lm, algo_bitmap: r32(200),
        })
    }
    fn block_size(&self) -> usize { 1024 << self.log_block_size }
    fn inode_size(&self) -> usize {
        if self.rev_level >= 1 { self.inode_size as usize } else { 128 }
    }
}

#[derive(Clone, Debug)]
struct BgDesc {
    block_bitmap: u32, inode_bitmap: u32, inode_table: u32,
    free_blocks: u16, free_inodes: u16, used_dirs: u16,
}

impl BgDesc {
    fn from_bytes(b: &[u8]) -> Self {
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        BgDesc { block_bitmap: r32(0), inode_bitmap: r32(4), inode_table: r32(8),
                 free_blocks: r16(12), free_inodes: r16(14), used_dirs: r16(16) }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0..4].copy_from_slice(&self.block_bitmap.to_le_bytes());
        b[4..8].copy_from_slice(&self.inode_bitmap.to_le_bytes());
        b[8..12].copy_from_slice(&self.inode_table.to_le_bytes());
        b[12..14].copy_from_slice(&self.free_blocks.to_le_bytes());
        b[14..16].copy_from_slice(&self.free_inodes.to_le_bytes());
        b[16..18].copy_from_slice(&self.used_dirs.to_le_bytes());
        b
    }
}

#[derive(Clone, Debug)]
struct Inode {
    mode: u16, uid: u16, size: u32,
    atime: u32, ctime: u32, mtime: u32, dtime: u32,
    gid: u16, links_count: u16, blocks: u32, flags: u32,
    block: [u32; 15],
    generation: u32, file_acl: u32, dir_acl: u32, faddr: u32,
    uid_high: u16, gid_high: u16, inode_size: u16,
}

impl Inode {
    fn from_bytes(b: &[u8]) -> Self {
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        let mut block = [0u32; 15];
        for i in 0..15 { block[i] = r32(40 + i*4); }
        Inode {
            mode: r16(0), uid: r16(2), size: r32(4),
            atime: r32(8), ctime: r32(12), mtime: r32(16), dtime: r32(20),
            gid: r16(24), links_count: r16(26), blocks: r32(28), flags: r32(32),
            block, generation: r32(100), file_acl: r32(104), dir_acl: r32(108),
            faddr: r32(112), uid_high: r16(116), gid_high: r16(118),
            inode_size: if b.len() > 128 { r16(128) } else { 0 },
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        b[0..2].copy_from_slice(&self.mode.to_le_bytes());
        b[2..4].copy_from_slice(&self.uid.to_le_bytes());
        b[4..8].copy_from_slice(&self.size.to_le_bytes());
        b[8..12].copy_from_slice(&self.atime.to_le_bytes());
        b[12..16].copy_from_slice(&self.ctime.to_le_bytes());
        b[16..20].copy_from_slice(&self.mtime.to_le_bytes());
        b[20..24].copy_from_slice(&self.dtime.to_le_bytes());
        b[24..26].copy_from_slice(&self.gid.to_le_bytes());
        b[26..28].copy_from_slice(&self.links_count.to_le_bytes());
        b[28..32].copy_from_slice(&self.blocks.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        for i in 0..15 { b[40+i*4..44+i*4].copy_from_slice(&self.block[i].to_le_bytes()); }
        b[100..104].copy_from_slice(&self.generation.to_le_bytes());
        b[104..108].copy_from_slice(&self.file_acl.to_le_bytes());
        b[108..112].copy_from_slice(&self.dir_acl.to_le_bytes());
        b[112..116].copy_from_slice(&self.faddr.to_le_bytes());
        b[116..118].copy_from_slice(&self.uid_high.to_le_bytes());
        b[118..120].copy_from_slice(&self.gid_high.to_le_bytes());
        b
    }
    fn file_size(&self) -> u64 { self.size as u64 | ((self.dir_acl as u64) << 32) }
}

#[derive(Clone, Debug)]
struct RawDirEntry {
    inode: u32, rec_len: u16, name_len: u8, file_type: u8, name: alloc::string::String,
}

impl RawDirEntry {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 { return None; }
        let inode   = u32::from_le_bytes(b[0..4].try_into().ok()?);
        let rec_len = u16::from_le_bytes(b[4..6].try_into().ok()?);
        let name_len= b[6]; let file_type = b[7];
        let end = 8 + name_len as usize;
        if end > b.len() { return None; }
        let name = alloc::string::String::from_utf8_lossy(&b[8..end]).into_owned();
        Some(RawDirEntry { inode, rec_len, name_len, file_type, name })
    }
}

#[derive(Clone, Debug)] pub struct Ext2Stat {
    pub ino: u32, pub mode: u16, pub uid: u32, pub gid: u32,
    pub size: u64, pub atime: u32, pub mtime: u32, pub ctime: u32,
    pub nlink: u16, pub blocks: u32,
}
#[derive(Clone, Debug)] pub struct Ext2DirEntry {
    pub inode: u32, pub name: alloc::string::String, pub file_type: u8,
}
#[derive(Clone, Debug)] pub struct Ext2Statfs {
    pub block_size: u32, pub total_blocks: u32, pub free_blocks: u32,
    pub total_inodes: u32, pub free_inodes: u32,
}

pub struct Ext2Fs {
    pub(crate) sb:          Superblock,
    pub(crate) group_descs: Vec<BgDesc>,
    pub(crate) block_size:  usize,
    pub(crate) lba_offset:  u64,
}

pub(crate) static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);

impl Ext2Fs {
    fn block_to_lba(&self, block: u32) -> u64 {
        self.lba_offset + (block as u64 * self.block_size as u64 / 512)
    }
    pub(crate) fn read_block(&self, block: u32) -> Vec<u8> {
        block_read(self.block_to_lba(block), (self.block_size / 512) as u32)
    }
    pub(crate) fn write_block(&self, block: u32, data: &[u8]) {
        block_write(self.block_to_lba(block), data);
    }
    fn read_group_desc(&self, group: u32) -> Option<BgDesc> {
        self.group_descs.get(group as usize).cloned()
    }
}

// ── low-level block/inode I/O (from impl_a.rs) ────────────────────────────────────────────
impl Ext2Fs {
    pub(crate) fn read_inode(&self, ino: u32) -> Option<Inode> {
        if ino == 0 { return None; }
        let ino_idx   = ino - 1;
        let group     = ino_idx / self.sb.inodes_per_group;
        let local_idx = ino_idx % self.sb.inodes_per_group;
        let gd        = self.read_group_desc(group)?;
        let inode_size= self.sb.inode_size();
        let off_table = local_idx as usize * inode_size;
        let blk_in_tbl= off_table / self.block_size;
        let off_in_blk= off_table % self.block_size;
        let block = self.read_block(gd.inode_table + blk_in_tbl as u32);
        Some(Inode::from_bytes(&block[off_in_blk..]))
    }

    pub(crate) fn write_inode(&self, ino: u32, inode: &Inode) -> Result<(), isize> {
        if ino == 0 { return Err(-22); }
        let ino_idx   = ino - 1;
        let group     = ino_idx / self.sb.inodes_per_group;
        let local_idx = ino_idx % self.sb.inodes_per_group;
        let gd        = self.read_group_desc(group).ok_or(-5isize)?;
        let inode_size= self.sb.inode_size();
        let off_table = local_idx as usize * inode_size;
        let blk_idx   = gd.inode_table as usize + off_table / self.block_size;
        let off_in_blk= off_table % self.block_size;
        let mut block = self.read_block(blk_idx as u32);
        let bytes = inode.to_bytes();
        block[off_in_blk..off_in_blk + bytes.len()].copy_from_slice(&bytes);
        self.write_block(blk_idx as u32, &block);
        Ok(())
    }

    pub(crate) fn read_block_indirect(
        &self, blkno: u32, depth: u32, data: &mut Vec<u8>, remaining: &mut usize,
    ) {
        if *remaining == 0 { return; }
        if depth == 0 {
            if blkno == 0 {
                let take = self.block_size.min(*remaining);
                data.extend(core::iter::repeat(0u8).take(take));
                *remaining -= take;
            } else {
                let b = self.read_block(blkno);
                let take = b.len().min(*remaining);
                data.extend_from_slice(&b[..take]);
                *remaining -= take;
            }
            return;
        }
        let ptrs = self.read_block(blkno);
        let ppb  = self.block_size / 4;
        for i in 0..ppb {
            if *remaining == 0 { break; }
            let ptr = u32::from_le_bytes(ptrs[i*4..i*4+4].try_into().unwrap());
            self.read_block_indirect(ptr, depth - 1, data, remaining);
        }
    }

    pub(crate) fn read_inode_data(&self, inode: &Inode) -> Vec<u8> {
        let file_size = inode.file_size() as usize;
        let mut data  = Vec::with_capacity(file_size);
        let mut rem   = file_size;
        for i in 0..12usize { if rem == 0 { break; }
            self.read_block_indirect(inode.block[i], 0, &mut data, &mut rem); }
        if rem > 0 && inode.block[12] != 0 {
            self.read_block_indirect(inode.block[12], 1, &mut data, &mut rem); }
        if rem > 0 && inode.block[13] != 0 {
            self.read_block_indirect(inode.block[13], 2, &mut data, &mut rem); }
        if rem > 0 && inode.block[14] != 0 {
            self.read_block_indirect(inode.block[14], 3, &mut data, &mut rem); }
        data.truncate(file_size);
        data
    }

    pub(crate) fn write_block_data(
        &mut self, inode: &mut Inode, ino: u32, data: &[u8],
    ) -> Result<(), isize> {
        let bs       = self.block_size;
        let n_blocks = (data.len() + bs - 1) / bs;
        if n_blocks > 12 { return Err(-28); }
        for i in 0..12usize { if inode.block[i] != 0 {
            self.free_block(inode.block[i]); inode.block[i] = 0; } }
        for i in 0..n_blocks {
            let blk  = self.alloc_block_inner().ok_or(-28isize)?;
            let s    = i * bs; let e = (s + bs).min(data.len());
            let mut buf = vec![0u8; bs];
            buf[..e - s].copy_from_slice(&data[s..e]);
            self.write_block(blk, &buf);
            inode.block[i] = blk;
        }
        inode.size   = data.len() as u32;
        inode.blocks = (n_blocks * bs / 512) as u32;
        Ok(())
    }

    fn free_block(&mut self, blkno: u32) {
        let group     = (blkno - self.sb.first_data_block) / self.sb.blocks_per_group;
        let local_bit = (blkno - self.sb.first_data_block) % self.sb.blocks_per_group;
        let mut gd = match self.read_group_desc(group) { Some(g) => g, None => return };
        let mut bmap = self.read_block(gd.block_bitmap);
        let byte = (local_bit / 8) as usize; let bit = local_bit % 8;
        if byte < bmap.len() {
            bmap[byte] &= !(1 << bit);
            self.write_block(gd.block_bitmap, &bmap);
            gd.free_blocks = gd.free_blocks.saturating_add(1);
            self.write_group_desc(group, &gd);
        }
    }

    pub(crate) fn alloc_inode_inner(&mut self, is_dir: bool) -> Option<u32> {
        for g in 0..self.group_descs.len() {
            let gd = self.group_descs[g].clone();
            if gd.free_inodes == 0 { continue; }
            let mut imap = self.read_block(gd.inode_bitmap);
            for i in 0..self.sb.inodes_per_group as usize {
                let byte = i / 8; let bit = i % 8;
                if byte >= imap.len() { break; }
                if imap[byte] & (1 << bit) == 0 {
                    imap[byte] |= 1 << bit;
                    self.write_block(gd.inode_bitmap, &imap);
                    let mut gd2 = gd.clone();
                    gd2.free_inodes -= 1;
                    if is_dir { gd2.used_dirs += 1; }
                    self.write_group_desc(g as u32, &gd2);
                    return Some(g as u32 * self.sb.inodes_per_group + i as u32 + 1);
                }
            }
        }
        None
    }

    pub(crate) fn alloc_block_inner(&mut self) -> Option<u32> {
        for g in 0..self.group_descs.len() {
            let gd = self.group_descs[g].clone();
            if gd.free_blocks == 0 { continue; }
            let mut bmap = self.read_block(gd.block_bitmap);
            for i in 0..self.sb.blocks_per_group as usize {
                let byte = i / 8; let bit = i % 8;
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
        if let Some(s) = self.group_descs.get_mut(group as usize) { *s = gd.clone(); }
        let bgdt_block = self.sb.first_data_block + 1;
        let per_block  = self.block_size / 32;
        let blk_idx    = bgdt_block + group / per_block as u32;
        let offset     = (group as usize % per_block) * 32;
        let mut block  = self.read_block(blk_idx);
        block[offset..offset + 32].copy_from_slice(&gd.to_bytes()[..32]);
        self.write_block(blk_idx, &block);
    }
}

// ── path resolution, directory ops, metadata (from impl_b.rs) ────────────────────────
impl Ext2Fs {
    pub(crate) fn resolve_path(&self, path: &str) -> Option<u32> {
        let mut ino = EXT2_ROOT_INO;
        let path = path.trim_start_matches('/');
        if path.is_empty() { return Some(ino); }
        for part in path.split('/') {
            if part.is_empty() { continue; }
            ino = self.dir_lookup(ino, part)?;
        }
        Some(ino)
    }

    pub(crate) fn dir_lookup(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let inode = self.read_inode(dir_ino)?;
        if inode.mode & EXT2_S_IFMT != EXT2_S_IFDIR { return None; }
        let data  = self.read_inode_data(&inode);
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = RawDirEntry::from_bytes(&data[off..])?;
            if de.rec_len == 0 { break; }
            if de.inode != 0 && de.name == name { return Some(de.inode); }
            off += de.rec_len as usize;
        }
        None
    }

    fn read_raw_dir_entries(&self, dir_ino: u32) -> Vec<RawDirEntry> {
        let inode = match self.read_inode(dir_ino) { Some(i) => i, None => return vec![] };
        let data  = self.read_inode_data(&inode);
        let mut entries = Vec::new();
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = match RawDirEntry::from_bytes(&data[off..]) { Some(d) => d, None => break };
            if de.rec_len == 0 { break; }
            if de.inode != 0 { entries.push(de); }
            off += de.rec_len as usize;
        }
        entries
    }

    fn append_dirent(&mut self, dir_ino: u32, child_ino: u32, name: &str, ft: u8) -> Result<(), isize> {
        let inode    = self.read_inode(dir_ino).ok_or(-2isize)?;
        let mut data = self.read_inode_data(&inode);
        let name_b   = name.as_bytes();
        let new_real = (8 + name_b.len() + 3) & !3;
        let bs       = self.block_size;
        let mut last_off = 0usize; let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = RawDirEntry::from_bytes(&data[off..]).ok_or(-5isize)?;
            if de.rec_len == 0 { break; }
            last_off = off; off += de.rec_len as usize;
        }
        let last_de  = RawDirEntry::from_bytes(&data[last_off..]).ok_or(-5isize)?;
        let last_real= (8 + last_de.name_len as usize + 3) & !3;
        let last_rec = last_de.rec_len as usize;
        let gap_off  = last_off + last_real;
        let gap_len  = last_off + last_rec - gap_off;
        if gap_len < new_real {
            let new_sz = (data.len() + new_real + bs - 1) / bs * bs;
            data.resize(new_sz, 0);
        }
        data[last_off + 4..last_off + 6].copy_from_slice(&(last_real as u16).to_le_bytes());
        let remaining = data.len() - gap_off;
        data[gap_off..gap_off + 4].copy_from_slice(&child_ino.to_le_bytes());
        data[gap_off + 4..gap_off + 6].copy_from_slice(&(remaining as u16).to_le_bytes());
        data[gap_off + 6] = name_b.len() as u8;
        data[gap_off + 7] = ft;
        data[gap_off + 8..gap_off + 8 + name_b.len()].copy_from_slice(name_b);
        let mut inode2 = inode.clone();
        self.write_block_data(&mut inode2, dir_ino, &data)?;
        inode2.mtime = crate::arch::time::current_unix_time_secs() as u32;
        self.write_inode(dir_ino, &inode2)
    }

    fn remove_dirent(&mut self, dir_ino: u32, name: &str) -> Result<(), isize> {
        let inode    = self.read_inode(dir_ino).ok_or(-2isize)?;
        let mut data = self.read_inode_data(&inode);
        let mut off = 0usize; let mut prev_off: Option<usize> = None;
        loop {
            if off + 8 > data.len() { return Err(-2); }
            let de = RawDirEntry::from_bytes(&data[off..]).ok_or(-5isize)?;
            if de.rec_len == 0 { return Err(-2); }
            if de.inode != 0 && de.name == name {
                if let Some(po) = prev_off {
                    let pr = u16::from_le_bytes(data[po+4..po+6].try_into().unwrap()) as usize;
                    let nr = (pr + de.rec_len as usize) as u16;
                    data[po+4..po+6].copy_from_slice(&nr.to_le_bytes());
                } else {
                    data[off..off+4].copy_from_slice(&0u32.to_le_bytes());
                }
                let mut inode2 = inode.clone();
                self.write_block_data(&mut inode2, dir_ino, &data)?;
                return Ok(());
            }
            prev_off = Some(off); off += de.rec_len as usize;
        }
    }

    fn alloc_inode_entry(
        &mut self, parent_ino: u32, name: &str, mode: u16, is_dir: bool,
    ) -> Result<u32, isize> {
        let ino = self.alloc_inode_inner(is_dir).ok_or(-28isize)?;
        let ts  = crate::arch::time::current_unix_time_secs() as u32;
        let new_inode = Inode {
            mode, uid: 0, size: 0, atime: ts, ctime: ts, mtime: ts, dtime: 0,
            gid: 0, links_count: 1, blocks: 0, flags: 0, block: [0u32; 15],
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
            ino, mode: inode.mode,
            uid: inode.uid as u32 | ((inode.uid_high as u32) << 16),
            gid: inode.gid as u32 | ((inode.gid_high as u32) << 16),
            size: inode.file_size(), atime: inode.atime, mtime: inode.mtime,
            ctime: inode.ctime, nlink: inode.links_count, blocks: inode.blocks,
        })
    }

    pub(crate) fn do_stat(&self, path: &str, follow: bool) -> Result<Ext2Stat, isize> {
        let ino = if follow {
            self.resolve_path(path).ok_or(-2isize)?
        } else {
            let (parent, name) = split_path(path)?;
            let p = self.resolve_path(parent).ok_or(-2isize)?;
            self.dir_lookup(p, name).ok_or(-2isize)?
        };
        self.stat_ino(ino)
    }

    pub(crate) fn do_readdir(&self, path: &str) -> Result<Vec<Ext2DirEntry>, isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT != EXT2_S_IFDIR { return Err(-20); }
        Ok(self.read_raw_dir_entries(ino).into_iter().map(|de| Ext2DirEntry {
            inode: de.inode, name: de.name, file_type: de.file_type,
        }).collect())
    }

    pub(crate) fn do_readlink(&self, path: &str) -> Result<alloc::string::String, isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT != EXT2_S_IFLNK { return Err(-22); }
        if inode.file_size() <= 60 {
            let raw: &[u8] = unsafe {
                core::slice::from_raw_parts(inode.block.as_ptr() as *const u8, 60)
            };
            return Ok(alloc::string::String::from_utf8_lossy(&raw[..inode.file_size() as usize]).into_owned());
        }
        Ok(alloc::string::String::from_utf8_lossy(&self.read_inode_data(&inode)).into_owned())
    }

    pub(crate) fn do_truncate(&mut self, path: &str, len: u64) -> Result<(), isize> {
        let ino        = self.resolve_path(path).ok_or(-2isize)?;
        let mut inode  = self.read_inode(ino).ok_or(-2isize)?;
        let cur        = inode.file_size();
        if len == cur { return Ok(()); }
        let mut data   = self.read_inode_data(&inode);
        if len < cur { data.truncate(len as usize); }
        else          { data.resize(len as usize, 0); }
        self.write_block_data(&mut inode, ino, &data)?;
        self.write_inode(ino, &inode)
    }

    pub(crate) fn do_create_file(&mut self, path: &str, mode: u16) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let p = self.resolve_path(parent).ok_or(-2isize)?;
        self.alloc_inode_entry(p, name, EXT2_S_IFREG | mode, false)?;
        Ok(())
    }

    pub(crate) fn do_mkdir(&mut self, path: &str, mode: u16) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let p   = self.resolve_path(parent).ok_or(-2isize)?;
        let ino = self.alloc_inode_entry(p, name, EXT2_S_IFDIR | mode, true)?;
        self.append_dirent(ino, ino, ".", 2)?;
        self.append_dirent(ino, p, "..", 2)?;
        let mut pi = self.read_inode(p).ok_or(-2isize)?;
        pi.links_count += 1;
        self.write_inode(p, &pi)
    }

    pub(crate) fn do_rmdir(&mut self, path: &str) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let non_dot = self.read_raw_dir_entries(ino).iter()
            .filter(|e| e.name != "." && e.name != "..").count();
        if non_dot > 0 { return Err(-39); }
        let (parent, name) = split_path(path)?;
        let p = self.resolve_path(parent).ok_or(-2isize)?;
        self.remove_dirent(p, name)?;
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        inode.dtime = crate::arch::time::current_unix_time_secs() as u32;
        inode.links_count = 0;
        self.write_inode(ino, &inode)?;
        let mut pi = self.read_inode(p).ok_or(-2isize)?;
        pi.links_count = pi.links_count.saturating_sub(1);
        self.write_inode(p, &pi)
    }

    pub(crate) fn do_unlink(&mut self, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let p   = self.resolve_path(parent).ok_or(-2isize)?;
        let ino = self.dir_lookup(p, name).ok_or(-2isize)?;
        let inode = self.read_inode(ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT == EXT2_S_IFDIR { return Err(-21); }
        self.remove_dirent(p, name)?;
        let mut i2 = inode.clone();
        i2.links_count = inode.links_count.saturating_sub(1);
        if i2.links_count == 0 { i2.dtime = crate::arch::time::current_unix_time_secs() as u32; }
        self.write_inode(ino, &i2)
    }

    pub(crate) fn do_rename(&mut self, old: &str, new: &str) -> Result<(), isize> {
        let (op, on) = split_path(old)?;
        let (np, nn) = split_path(new)?;
        let op_ino   = self.resolve_path(op).ok_or(-2isize)?;
        let np_ino   = self.resolve_path(np).ok_or(-2isize)?;
        let child    = self.dir_lookup(op_ino, on).ok_or(-2isize)?;
        let inode    = self.read_inode(child).ok_or(-2isize)?;
        let ft = if inode.mode & EXT2_S_IFMT == EXT2_S_IFDIR { 2u8 } else { 1u8 };
        self.remove_dirent(op_ino, on)?;
        self.append_dirent(np_ino, child, nn, ft)
    }

    pub(crate) fn do_link(&mut self, existing: &str, new: &str) -> Result<(), isize> {
        let (np, nn)  = split_path(new)?;
        let np_ino    = self.resolve_path(np).ok_or(-2isize)?;
        let child_ino = self.resolve_path(existing).ok_or(-2isize)?;
        let mut inode = self.read_inode(child_ino).ok_or(-2isize)?;
        if inode.mode & EXT2_S_IFMT == EXT2_S_IFDIR { return Err(-21); }
        self.append_dirent(np_ino, child_ino, nn, 1)?;
        inode.links_count += 1;
        self.write_inode(child_ino, &inode)
    }

    pub(crate) fn do_symlink(&mut self, target: &str, path: &str) -> Result<(), isize> {
        let (parent, name) = split_path(path)?;
        let p   = self.resolve_path(parent).ok_or(-2isize)?;
        let ino = self.alloc_inode_entry(p, name, EXT2_S_IFLNK | 0o777, false)?;
        let tb  = target.as_bytes();
        if tb.len() <= 60 {
            let mut inode = self.read_inode(ino).ok_or(-2isize)?;
            let raw: &mut [u8] = unsafe {
                core::slice::from_raw_parts_mut(inode.block.as_mut_ptr() as *mut u8, 60)
            };
            raw[..tb.len()].copy_from_slice(tb);
            inode.size = tb.len() as u32;
            return self.write_inode(ino, &inode);
        }
        let mut inode = self.read_inode(ino).ok_or(-2isize)?;
        self.write_block_data(&mut inode, ino, tb)?;
        self.write_inode(ino, &inode)
    }

    pub(crate) fn do_chmod(&mut self, path: &str, mode: u16) -> Result<(), isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let mut i = self.read_inode(ino).ok_or(-2isize)?;
        i.mode    = (i.mode & EXT2_S_IFMT) | (mode & 0o7777);
        self.write_inode(ino, &i)
    }

    pub(crate) fn do_chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let mut i = self.read_inode(ino).ok_or(-2isize)?;
        i.uid = uid as u16; i.uid_high = (uid >> 16) as u16;
        i.gid = gid as u16; i.gid_high = (gid >> 16) as u16;
        self.write_inode(ino, &i)
    }

    pub(crate) fn do_set_times(&mut self, path: &str, atime_ns: u64, mtime_ns: u64) -> Result<(), isize> {
        let ino   = self.resolve_path(path).ok_or(-2isize)?;
        let mut i = self.read_inode(ino).ok_or(-2isize)?;
        i.atime   = (atime_ns / 1_000_000_000) as u32;
        i.mtime   = (mtime_ns / 1_000_000_000) as u32;
        self.write_inode(ino, &i)
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
    Ok((if pos == 0 { "/" } else { &path[..pos] }, &path[pos + 1..]))
}