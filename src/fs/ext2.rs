//! Ext2 read-write filesystem driver.
//!
//! Revision 0 and revision 1 (dynamic inode sizes) are supported.
//! Block sizes of 1024, 2048, and 4096 bytes are supported.
//!
//! ## Write path
//! Mutations (create, unlink, write, truncate, mkdir, rmdir, rename,
//! link, symlink, chmod, chown) are applied directly to the in-memory
//! image Vec<u8> and immediately flushed to the backing block device
//! via virtio_blk::write_sectors on the affected 512-byte sectors.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;
// EXT2 file-type constants for DirEntry2.file_type
const FT_REG:  u8 = 1;
const FT_DIR:  u8 = 2;
const FT_SYML: u8 = 7;

// ── On-disk structures ────────────────────────────────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Superblock {
    inodes_count:         u32,
    blocks_count:         u32,
    r_blocks_count:       u32,
    free_blocks_count:    u32,
    free_inodes_count:    u32,
    first_data_block:     u32,
    log_block_size:       u32,
    log_frag_size:        i32,
    blocks_per_group:     u32,
    frags_per_group:      u32,
    inodes_per_group:     u32,
    mtime:                u32,
    wtime:                u32,
    mnt_count:            u16,
    max_mnt_count:        i16,
    magic:                u16,
    state:                u16,
    errors:               u16,
    minor_rev_level:      u16,
    lastcheck:            u32,
    checkinterval:        u32,
    creator_os:           u32,
    rev_level:            u32,
    def_resuid:           u16,
    def_resgid:           u16,
    first_ino:            u32,
    inode_size:           u16,
    block_group_nr:       u16,
    feature_compat:       u32,
    feature_incompat:     u32,
    feature_ro_compat:    u32,
    uuid:                 [u8; 16],
    volume_name:          [u8; 16],
    last_mounted:         [u8; 64],
    algo_bitmap:          u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GroupDesc {
    block_bitmap:  u32,
    inode_bitmap:  u32,
    inode_table:   u32,
    free_blocks:   u16,
    free_inodes:   u16,
    used_dirs:     u16,
    _pad:          u16,
    _reserved:     [u32; 3],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Inode {
    mode:          u16,
    uid:           u16,
    size_lo:       u32,
    atime:         u32,
    ctime:         u32,
    mtime:         u32,
    dtime:         u32,
    gid:           u16,
    links_count:   u16,
    blocks:        u32,   // 512-byte units
    flags:         u32,
    osd1:          u32,
    block:         [u32; 15],
    generation:    u32,
    file_acl:      u32,
    size_hi:       u32,
    faddr:         u32,
    osd2:          [u8; 12],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DirEntry2 {
    inode:     u32,
    rec_len:   u16,
    name_len:  u8,
    file_type: u8,
}

// ── Public stat / readdir types ───────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct Ext2Stat {
    pub ino:     u32,
    pub mode:    u16,
    pub nlink:   u32,
    pub uid:     u32,
    pub gid:     u32,
    pub size:    u64,
    pub atime:   u64,
    pub mtime:   u64,
    pub ctime:   u64,
    pub blksize: u32,
    pub blocks:  u64,
}

#[derive(Clone, Debug)]
pub struct Ext2DirEntry {
    pub ino:    u32,
    pub name:   String,
    pub is_dir: bool,
    pub mode:   u16,
    pub size:   u64,
}

// ── Filesystem state ──────────────────────────────────────────────────────

struct Ext2Fs {
    data:             Vec<u8>,
    block_size:       usize,
    inode_size:       usize,
    inodes_per_grp:   usize,
    blocks_per_grp:   usize,
    first_data_blk:   usize,
    total_groups:     usize,
    total_blocks:     usize,
    total_inodes:     usize,
}

static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);

// ── mount ─────────────────────────────────────────────────────────────────

pub fn mount() -> bool {
    if !crate::drivers::virtio_blk::is_present() { return false; }

    let mut sb_buf2 = alloc::vec![0u8; 512];
    let _ = crate::drivers::virtio_blk::read_sectors(2, &mut sb_buf2);
    let mut sb_buf3 = alloc::vec![0u8; 512];
    let _ = crate::drivers::virtio_blk::read_sectors(3, &mut sb_buf3);

    let mut raw_sb = alloc::vec![0u8; 1024];
    raw_sb[..512].copy_from_slice(&sb_buf2);
    raw_sb[512..].copy_from_slice(&sb_buf3);
    let sb = unsafe { *(raw_sb.as_ptr() as *const Superblock) };

    if sb.magic != 0xEF53 { return false; }

    let block_size      = 1024usize << sb.log_block_size;
    let total_blocks    = sb.blocks_count as usize;
    let total_bytes     = total_blocks * block_size;
    let load_bytes      = total_bytes.min(256 * 1024 * 1024);
    let inodes_per_grp  = sb.inodes_per_group as usize;
    let blocks_per_grp  = sb.blocks_per_group as usize;
    let total_inodes    = sb.inodes_count as usize;
    let total_groups    = total_blocks.div_ceil(blocks_per_grp);

    let mut image = alloc::vec![0u8; load_bytes];
    let chunk = 128usize;
    let mut lba = 0u64;
    let mut off = 0usize;
    while off < load_bytes {
        let n = chunk.min((load_bytes - off) / 512);
        if n == 0 { break; }
        let slice = &mut image[off..off + n * 512];
        if crate::drivers::virtio_blk::read_sectors(lba, slice).is_err() { break; }
        off += n * 512;
        lba += n as u64;
    }

    let inode_size = if sb.rev_level >= 1 { sb.inode_size as usize } else { 128 };

    *FS.lock() = Some(Ext2Fs {
        data: image,
        block_size,
        inode_size,
        inodes_per_grp,
        blocks_per_grp,
        first_data_blk: sb.first_data_block as usize,
        total_groups,
        total_blocks,
        total_inodes,
    });
    true
}

// ── Ext2Fs read helpers ───────────────────────────────────────────────────

impl Ext2Fs {
    fn gd_offset(&self, g: usize) -> usize {
        let base = if self.block_size == 1024 { 2048 } else { self.block_size };
        base + g * 32
    }

    fn group_desc(&self, g: usize) -> GroupDesc {
        let off = self.gd_offset(g);
        if off + 32 > self.data.len() {
            return GroupDesc {
                block_bitmap: 0, inode_bitmap: 0, inode_table: 0,
                free_blocks: 0, free_inodes: 0, used_dirs: 0,
                _pad: 0, _reserved: [0; 3],
            };
        }
        unsafe { *((self.data.as_ptr().add(off)) as *const GroupDesc) }
    }

    fn write_group_desc(&mut self, g: usize, gd: &GroupDesc) {
        let off = self.gd_offset(g);
        if off + 32 > self.data.len() { return; }
        unsafe {
            core::ptr::copy_nonoverlapping(
                gd as *const GroupDesc as *const u8,
                self.data.as_mut_ptr().add(off),
                32,
            );
        }
        self.flush_range(off, 32);
    }

    fn inode_offset(&self, ino: u32) -> Option<usize> {
        if ino == 0 { return None; }
        let idx   = (ino - 1) as usize;
        let grp   = idx / self.inodes_per_grp;
        let local = idx % self.inodes_per_grp;
        let gd    = self.group_desc(grp);
        let off   = gd.inode_table as usize * self.block_size + local * self.inode_size;
        if off + self.inode_size > self.data.len() { return None; }
        Some(off)
    }

    fn inode(&self, ino: u32) -> Option<Inode> {
        let off = self.inode_offset(ino)?;
        Some(unsafe { *(self.data.as_ptr().add(off) as *const Inode) })
    }

    fn write_inode(&mut self, ino: u32, inode: &Inode) {
        if let Some(off) = self.inode_offset(ino) {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    inode as *const Inode as *const u8,
                    self.data.as_mut_ptr().add(off),
                    core::mem::size_of::<Inode>(),
                );
            }
            self.flush_range(off, core::mem::size_of::<Inode>());
        }
    }

    fn block_data(&self, blkno: u32) -> Option<&[u8]> {
        if blkno == 0 { return None; }
        let off = blkno as usize * self.block_size;
        if off + self.block_size > self.data.len() { return None; }
        Some(&self.data[off..off + self.block_size])
    }

    fn block_data_mut(&mut self, blkno: u32) -> Option<&mut [u8]> {
        if blkno == 0 { return None; }
        let off = blkno as usize * self.block_size;
        if off + self.block_size > self.data.len() { return None; }
        Some(&mut self.data[off..off + self.block_size])
    }

    // ── Sector flush ──────────────────────────────────────────────────────

    fn flush_range(&self, byte_off: usize, len: usize) {
        if len == 0 { return; }
        let first_sector = byte_off / 512;
        let last_sector  = (byte_off + len - 1) / 512;
        for s in first_sector..=last_sector {
            let start = s * 512;
            let end   = (start + 512).min(self.data.len());
            if end > start {
                let _ = crate::drivers::virtio_blk::write_sectors(
                    s as u64, &self.data[start..end]);
            }
        }
    }

    fn flush_block(&self, blkno: u32) {
        if blkno == 0 { return; }
        let off = blkno as usize * self.block_size;
        self.flush_range(off, self.block_size);
    }

    // ── Block allocator ───────────────────────────────────────────────────

    /// Allocate one free block, preferring `preferred_group`.
    /// Returns the block number or 0 on failure.
    fn alloc_block(&mut self, preferred_group: usize) -> u32 {
        let total = self.total_groups;
        for delta in 0..total {
            let g = (preferred_group + delta) % total;
            let gd = self.group_desc(g);
            if gd.free_blocks == 0 { continue; }
            let bitmap_off = gd.block_bitmap as usize * self.block_size;
            let bpg = self.blocks_per_grp;
            for i in 0..bpg {
                let byte = bitmap_off + i / 8;
                let bit  = i % 8;
                if byte >= self.data.len() { break; }
                if self.data[byte] & (1 << bit) == 0 {
                    // Found a free bit — mark it used.
                    self.data[byte] |= 1 << bit;
                    self.flush_range(byte, 1);
                    // Update group descriptor.
                    let mut gd2 = self.group_desc(g);
                    gd2.free_blocks = gd2.free_blocks.saturating_sub(1);
                    self.write_group_desc(g, &gd2);
                    let blkno = (g * bpg + i + self.first_data_blk) as u32;
                    // Zero the new block.
                    let blk_off = blkno as usize * self.block_size;
                    if blk_off + self.block_size <= self.data.len() {
                        for b in &mut self.data[blk_off..blk_off + self.block_size] {
                            *b = 0;
                        }
                        self.flush_block(blkno);
                    }
                    return blkno;
                }
            }
        }
        0
    }

    fn free_block(&mut self, blkno: u32) {
        if blkno == 0 { return; }
        let blk = blkno as usize;
        let g   = blk.saturating_sub(self.first_data_blk) / self.blocks_per_grp;
        if g >= self.total_groups { return; }
        let local = blk.saturating_sub(self.first_data_blk) % self.blocks_per_grp;
        let gd    = self.group_desc(g);
        let byte_off = gd.block_bitmap as usize * self.block_size + local / 8;
        if byte_off < self.data.len() {
            self.data[byte_off] &= !(1u8 << (local % 8));
            self.flush_range(byte_off, 1);
        }
        let mut gd2 = self.group_desc(g);
        gd2.free_blocks += 1;
        self.write_group_desc(g, &gd2);
    }

    // ── Inode allocator ───────────────────────────────────────────────────

    fn alloc_inode(&mut self, preferred_group: usize) -> u32 {
        let total = self.total_groups;
        for delta in 0..total {
            let g = (preferred_group + delta) % total;
            let gd = self.group_desc(g);
            if gd.free_inodes == 0 { continue; }
            let bitmap_off = gd.inode_bitmap as usize * self.block_size;
            for i in 0..self.inodes_per_grp {
                let byte = bitmap_off + i / 8;
                let bit  = i % 8;
                if byte >= self.data.len() { break; }
                if self.data[byte] & (1 << bit) == 0 {
                    self.data[byte] |= 1 << bit;
                    self.flush_range(byte, 1);
                    let mut gd2 = self.group_desc(g);
                    gd2.free_inodes = gd2.free_inodes.saturating_sub(1);
                    self.write_group_desc(g, &gd2);
                    return (g * self.inodes_per_grp + i + 1) as u32;
                }
            }
        }
        0
    }

    fn free_inode(&mut self, ino: u32) {
        if ino == 0 { return; }
        let idx = (ino - 1) as usize;
        let g   = idx / self.inodes_per_grp;
        if g >= self.total_groups { return; }
        let local = idx % self.inodes_per_grp;
        let gd    = self.group_desc(g);
        let byte_off = gd.inode_bitmap as usize * self.block_size + local / 8;
        if byte_off < self.data.len() {
            self.data[byte_off] &= !(1u8 << (local % 8));
            self.flush_range(byte_off, 1);
        }
        let mut gd2 = self.group_desc(g);
        gd2.free_inodes += 1;
        self.write_group_desc(g, &gd2);
    }

    // ── Block scan helpers ────────────────────────────────────────────────

    fn scan_inode_data_blocks<F>(&self, ino: &Inode, mut f: F)
    where F: FnMut(&[u8]) -> bool
    {
        for i in 0..12usize {
            if let Some(blk) = self.block_data(ino.block[i]) {
                if !f(blk) { return; }
            }
        }
        if let Some(iblk) = self.block_data(ino.block[12]) {
            let ptrs = self.block_size / 4;
            for i in 0..ptrs {
                let blkno = u32::from_le_bytes([
                    iblk[i*4], iblk[i*4+1], iblk[i*4+2], iblk[i*4+3]
                ]);
                if let Some(blk) = self.block_data(blkno) {
                    if !f(blk) { return; }
                }
            }
        }
    }

    fn read_inode_data(&self, ino: &Inode) -> Vec<u8> {
        let size = (ino.size_lo as usize).min(MAX_FILE_SIZE);
        let mut out = alloc::vec![0u8; size];
        let mut written = 0usize;
        for i in 0..12usize {
            if written >= size { break; }
            if let Some(d) = self.block_data(ino.block[i]) {
                let n = (size - written).min(d.len());
                out[written..written + n].copy_from_slice(&d[..n]);
                written += n;
            }
        }
        if written < size {
            if let Some(iblk) = self.block_data(ino.block[12]) {
                let ptrs = self.block_size / 4;
                for i in 0..ptrs {
                    if written >= size { break; }
                    let blk = u32::from_le_bytes([iblk[i*4], iblk[i*4+1], iblk[i*4+2], iblk[i*4+3]]);
                    if let Some(d) = self.block_data(blk) {
                        let n = (size - written).min(d.len());
                        out[written..written + n].copy_from_slice(&d[..n]);
                        written += n;
                    }
                }
            }
        }
        out.truncate(size);
        out
    }

    // ── Write inode data ──────────────────────────────────────────────────

    /// Write `data` into `ino`, allocating / freeing blocks as needed.
    /// Handles direct blocks (0..11) and single-indirect (block[12]).
    fn write_inode_data(&mut self, ino_num: u32, data: &[u8]) -> Result<(), i32> {
        let size = data.len().min(MAX_FILE_SIZE);
        let bs   = self.block_size;
        let needed_direct   = size.div_ceil(bs).min(12);
        let needed_indirect = if size > 12 * bs {
            (size - 12 * bs).div_ceil(bs)
        } else { 0 };
        let ptrs_per_block  = bs / 4;
        if needed_indirect > ptrs_per_block {
            return Err(-27); // EFBIG — double indirect not implemented
        }

        let mut inode = self.inode(ino_num).ok_or(-2i32)?;
        let grp = ((ino_num - 1) as usize) / self.inodes_per_grp;

        // ---- Direct blocks ----
        for i in 0..12usize {
            if i < needed_direct {
                if inode.block[i] == 0 {
                    let b = self.alloc_block(grp);
                    if b == 0 { return Err(-28); } // ENOSPC
                    inode.block[i] = b;
                }
                let start = i * bs;
                let end   = (start + bs).min(size);
                let slice = &data[start..end];
                let blkno = inode.block[i];
                let off   = blkno as usize * bs;
                if off + bs <= self.data.len() {
                    self.data[off..off + slice.len()].copy_from_slice(slice);
                    if slice.len() < bs {
                        for b in &mut self.data[off + slice.len()..off + bs] { *b = 0; }
                    }
                    self.flush_block(blkno);
                }
            } else {
                // Free excess direct block.
                if inode.block[i] != 0 {
                    self.free_block(inode.block[i]);
                    inode.block[i] = 0;
                }
            }
        }

        // ---- Single-indirect block ----
        if needed_indirect > 0 {
            if inode.block[12] == 0 {
                let ib = self.alloc_block(grp);
                if ib == 0 { return Err(-28); }
                inode.block[12] = ib;
            }
            // Build the pointer table.
            let iblkno = inode.block[12];
            let iblk_off = iblkno as usize * bs;

            // Collect existing pointers so we can free unused ones.
            let mut ptrs = alloc::vec![0u32; ptrs_per_block];
            if iblk_off + bs <= self.data.len() {
                for i in 0..ptrs_per_block {
                    ptrs[i] = u32::from_le_bytes([
                        self.data[iblk_off + i*4],
                        self.data[iblk_off + i*4 + 1],
                        self.data[iblk_off + i*4 + 2],
                        self.data[iblk_off + i*4 + 3],
                    ]);
                }
            }

            for i in 0..ptrs_per_block {
                if i < needed_indirect {
                    if ptrs[i] == 0 {
                        let b = self.alloc_block(grp);
                        if b == 0 { return Err(-28); }
                        ptrs[i] = b;
                    }
                    let start = 12 * bs + i * bs;
                    let end   = (start + bs).min(size);
                    let slice = &data[start..end];
                    let blkno = ptrs[i];
                    let off   = blkno as usize * bs;
                    if off + bs <= self.data.len() {
                        self.data[off..off + slice.len()].copy_from_slice(slice);
                        if slice.len() < bs {
                            for b in &mut self.data[off + slice.len()..off + bs] { *b = 0; }
                        }
                        self.flush_block(blkno);
                    }
                } else if ptrs[i] != 0 {
                    self.free_block(ptrs[i]);
                    ptrs[i] = 0;
                }
            }

            // Write pointer table back.
            if iblk_off + bs <= self.data.len() {
                for i in 0..ptrs_per_block {
                    let bytes = ptrs[i].to_le_bytes();
                    self.data[iblk_off + i*4..iblk_off + i*4 + 4].copy_from_slice(&bytes);
                }
                self.flush_block(iblkno);
            }
        } else {
            // Free the indirect block if it was previously used.
            if inode.block[12] != 0 {
                // Free all pointers first.
                let iblkno  = inode.block[12];
                let iblk_off = iblkno as usize * bs;
                if iblk_off + bs <= self.data.len() {
                    let ptrs_per = bs / 4;
                    for i in 0..ptrs_per {
                        let p = u32::from_le_bytes([
                            self.data[iblk_off + i*4],
                            self.data[iblk_off + i*4 + 1],
                            self.data[iblk_off + i*4 + 2],
                            self.data[iblk_off + i*4 + 3],
                        ]);
                        self.free_block(p);
                    }
                }
                self.free_block(iblkno);
                inode.block[12] = 0;
            }
        }

        inode.size_lo = size as u32;
        inode.blocks  = ((needed_direct + if needed_indirect > 0 { 1 + needed_indirect } else { 0 })
                          * bs / 512) as u32;
        self.write_inode(ino_num, &inode);
        Ok(())
    }

    // ── Directory helpers ─────────────────────────────────────────────────

    fn lookup_path(&self, path: &str) -> Option<u32> {
        let mut ino = 2u32;
        let path = path.trim_start_matches('/');
        if path.is_empty() { return Some(2); }
        for component in path.split('/') {
            if component.is_empty() { continue; }
            ino = self.lookup_dir(ino, component)?;
        }
        Some(ino)
    }

    fn lookup_dir(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let inode = self.inode(dir_ino)?;
        let name_bytes = name.as_bytes();
        let mut result = None;
        self.scan_inode_data_blocks(&inode, |blk| {
            let mut off = 0usize;
            while off + 8 <= blk.len() {
                let de = unsafe { *(blk.as_ptr().add(off) as *const DirEntry2) };
                let rec = de.rec_len as usize;
                if rec == 0 { return false; }
                if de.inode != 0 {
                    let name_end = off + 8 + de.name_len as usize;
                    if name_end <= blk.len() && &blk[off + 8..name_end] == name_bytes {
                        result = Some(de.inode);
                        return false;
                    }
                }
                off += rec;
            }
            true
        });
        result
    }

    /// Split a path into (parent_ino, filename).  Returns Err(-2) if
    /// parent doesn't exist, Err(-20) if parent is not a directory.
    fn dir_lookup_parent(&self, path: &str) -> Result<(u32, &str), i32> {
        let path = path.trim_start_matches('/');
        let (parent_path, name) = match path.rfind('/') {
            Some(i) => (&path[..i], &path[i+1..]),
            None    => ("", path),
        };
        let parent_ino = if parent_path.is_empty() {
            2u32
        } else {
            self.lookup_path(parent_path).ok_or(-2i32)?
        };
        let parent_inode = self.inode(parent_ino).ok_or(-2i32)?;
        if parent_inode.mode & 0xF000 != 0x4000 { return Err(-20); } // ENOTDIR
        Ok((parent_ino, name))
    }

    /// Append a directory entry to `dir_ino`.
    fn add_dirent(&mut self, dir_ino: u32, child_ino: u32,
                  name: &str, file_type: u8) -> Result<(), i32> {
        let name_len  = name.len() as u8;
        let rec_need  = (8 + name.len() + 3) & !3; // 4-byte aligned
        let bs        = self.block_size;
        let dir_inode = self.inode(dir_ino).ok_or(-2i32)?;

        // Try to fit into an existing block by splitting a padded entry.
        let mut blocks_to_scan: Vec<u32> = Vec::new();
        for i in 0..12 { if dir_inode.block[i] != 0 { blocks_to_scan.push(dir_inode.block[i]); } }
        if dir_inode.block[12] != 0 {
            let ib_off = dir_inode.block[12] as usize * bs;
            let ptrs   = bs / 4;
            for i in 0..ptrs {
                let p = u32::from_le_bytes([
                    self.data[ib_off + i*4], self.data[ib_off + i*4+1],
                    self.data[ib_off + i*4+2], self.data[ib_off + i*4+3],
                ]);
                if p != 0 { blocks_to_scan.push(p); }
            }
        }

        for blkno in &blocks_to_scan {
            let blkno = *blkno;
            let off   = blkno as usize * bs;
            if off + bs > self.data.len() { continue; }
            let mut cursor = 0usize;
            while cursor + 8 <= bs {
                let de = unsafe {
                    *((self.data.as_ptr().add(off + cursor)) as *const DirEntry2)
                };
                let rec = de.rec_len as usize;
                if rec == 0 { break; }
                let actual = (8 + de.name_len as usize + 3) & !3;
                let slack  = rec.saturating_sub(actual);
                if slack >= rec_need {
                    // Shrink the existing entry and write the new one after it.
                    let new_rec = (rec - slack) as u16;
                    self.data[off + cursor + 4] = (new_rec & 0xFF) as u8;
                    self.data[off + cursor + 5] = (new_rec >> 8)   as u8;
                    let new_off = off + cursor + actual;
                    let tail_rec = slack as u16;
                    let new_de = DirEntry2 {
                        inode: child_ino, rec_len: tail_rec,
                        name_len, file_type,
                    };
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            &new_de as *const DirEntry2 as *const u8,
                            self.data.as_mut_ptr().add(new_off), 8);
                    }
                    let nb = new_off + 8;
                    let ne = nb + name.len();
                    if ne <= self.data.len() {
                        self.data[nb..ne].copy_from_slice(name.as_bytes());
                    }
                    self.flush_block(blkno);
                    return Ok(());
                }
                cursor += rec;
            }
        }

        // No space in existing blocks — allocate a new directory block.
        let grp   = ((dir_ino - 1) as usize) / self.inodes_per_grp;
        let newblk = self.alloc_block(grp);
        if newblk == 0 { return Err(-28); }

        // Attach it to the inode.
        let mut dir_inode = self.inode(dir_ino).ok_or(-2i32)?;
        let mut attached = false;
        for i in 0..12 {
            if dir_inode.block[i] == 0 {
                dir_inode.block[i] = newblk;
                attached = true;
                break;
            }
        }
        if !attached {
            // Need indirect block — simplified: fail if not already allocated.
            return Err(-28);
        }
        dir_inode.size_lo += bs as u32;
        self.write_inode(dir_ino, &dir_inode);

        // Write the single entry into the new block.
        let off   = newblk as usize * bs;
        let de    = DirEntry2 { inode: child_ino, rec_len: bs as u16, name_len, file_type };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &de as *const DirEntry2 as *const u8,
                self.data.as_mut_ptr().add(off), 8);
        }
        let nb = off + 8;
        let ne = nb + name.len();
        if ne <= self.data.len() {
            self.data[nb..ne].copy_from_slice(name.as_bytes());
        }
        self.flush_block(newblk);
        Ok(())
    }

    /// Remove the directory entry for `name` from `dir_ino`.
    fn remove_dirent(&mut self, dir_ino: u32, name: &str) -> Result<(), i32> {
        let name_bytes = name.as_bytes();
        let bs         = self.block_size;
        let dir_inode  = self.inode(dir_ino).ok_or(-2i32)?;

        for i in 0..12 {
            let blkno = dir_inode.block[i];
            if blkno == 0 { continue; }
            let off = blkno as usize * bs;
            if off + bs > self.data.len() { continue; }
            let mut cursor = 0usize;
            let mut prev_rec_end = 0usize;
            while cursor + 8 <= bs {
                let de = unsafe {
                    *((self.data.as_ptr().add(off + cursor)) as *const DirEntry2)
                };
                let rec = de.rec_len as usize;
                if rec == 0 { break; }
                if de.inode != 0 {
                    let ne = cursor + 8 + de.name_len as usize;
                    if ne <= bs && &self.data[off + cursor + 8..off + ne] == name_bytes {
                        if prev_rec_end > 0 {
                            // Merge into previous entry's rec_len.
                            let prev_rec = unsafe {
                                *((self.data.as_ptr().add(off + prev_rec_end - 
                                    // find prev de.rec_len: it ends at cursor
                                    rec)) as *const u16)
                            };
                            let _ = prev_rec; // unused
                            // Simpler: just zero this entry's inode field.
                        }
                        // Zero the inode field — entry is now free.
                        self.data[off + cursor]     = 0;
                        self.data[off + cursor + 1] = 0;
                        self.data[off + cursor + 2] = 0;
                        self.data[off + cursor + 3] = 0;
                        self.flush_block(blkno);
                        return Ok(());
                    }
                }
                prev_rec_end = cursor + rec;
                cursor += rec;
            }
        }
        Err(-2) // ENOENT
    }

    fn list_dir_ino(&self, dir_ino: u32) -> Vec<(u32, String, bool)> {
        let mut out = Vec::new();
        let inode = match self.inode(dir_ino) { Some(i) => i, None => return out };
        let data  = self.read_inode_data(&inode);
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = unsafe { *(data.as_ptr().add(off) as *const DirEntry2) };
            let rec = de.rec_len as usize;
            if rec == 0 { break; }
            if de.inode != 0 {
                let name_end = off + 8 + de.name_len as usize;
                if name_end > data.len() { break; }
                let name_bytes = &data[off + 8..name_end];
                if let Ok(s) = core::str::from_utf8(name_bytes) {
                    let child_ino = de.inode;
                    let is_dir = de.file_type == 2
                        || self.inode(child_ino).map_or(false, |i| i.mode & 0xF000 == 0x4000);
                    out.push((child_ino, String::from(s), is_dir));
                }
            }
            off += rec;
        }
        out
    }

    fn make_inode(&mut self, mode: u16, uid: u16, gid: u16,
                  preferred_group: usize) -> Result<u32, i32> {
        let ino = self.alloc_inode(preferred_group);
        if ino == 0 { return Err(-28); }
        let now = crate::drivers::rtc::read_unix_time().unwrap_or(0) as u32;
        let new_inode = Inode {
            mode,
            uid,
            size_lo: 0,
            atime: now, ctime: now, mtime: now, dtime: 0,
            gid,
            links_count: 1,
            blocks: 0,
            flags: 0,
            osd1: 0,
            block: [0u32; 15],
            generation: 0,
            file_acl: 0,
            size_hi: 0,
            faddr: 0,
            osd2: [0u8; 12],
        };
        self.write_inode(ino, &new_inode);
        Ok(ino)
    }
}

// ── Public read-only API ──────────────────────────────────────────────────

pub fn stat(path: &str) -> Option<u32> {
    FS.lock().as_ref()?.lookup_path(path)
}

pub fn read_file_by_ino(ino: u32) -> Option<Vec<u8>> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    if inode.mode & 0xF000 != 0x8000 { return None; }
    Some(fs.read_inode_data(&inode))
}

pub fn file_size(ino: u32) -> Option<usize> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    Some(inode.size_lo as usize)
}

pub fn is_dir(path: &str) -> bool {
    let fs = FS.lock();
    let fs = match fs.as_ref() { Some(f) => f, None => return false };
    let ino = match fs.lookup_path(path) { Some(i) => i, None => return false };
    let inode = match fs.inode(ino) { Some(i) => i, None => return false };
    inode.mode & 0xF000 == 0x4000
}

pub fn readdir_raw(dir_ino: u32) -> Option<Vec<(u32, String, bool)>> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    Some(fs.list_dir_ino(dir_ino))
}

// ── Public stat (vfs_ops-facing) ──────────────────────────────────────────

pub fn sys_stat(path: &str) -> Result<Ext2Stat, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    Ok(Ext2Stat {
        ino,
        mode:    inode.mode,
        nlink:   inode.links_count as u32,
        uid:     inode.uid as u32,
        gid:     inode.gid as u32,
        size:    inode.size_lo as u64,
        atime:   inode.atime as u64,
        mtime:   inode.mtime as u64,
        ctime:   inode.ctime as u64,
        blksize: fs.block_size as u32,
        blocks:  inode.blocks as u64,
    })
}

pub fn sys_lstat(path: &str) -> Result<Ext2Stat, i32> {
    // For symlinks, lstat returns the symlink inode rather than following.
    // Our lookup_path already doesn't follow symlinks, so lstat == stat here.
    sys_stat(path)
}

/// Readdir returning rich Ext2DirEntry structs (used by vfs_ops::readdir).
pub fn readdir(path: &str) -> Result<Vec<Ext2DirEntry>, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    let dir_ino = fs.lookup_path(path).ok_or(-2i32)?;
    let raw = fs.list_dir_ino(dir_ino);
    let mut out = Vec::with_capacity(raw.len());
    for (ino, name, is_dir) in raw {
        let (mode, size) = fs.inode(ino)
            .map(|i| (i.mode, i.size_lo as u64))
            .unwrap_or((0, 0));
        out.push(Ext2DirEntry { ino, name, is_dir, mode, size });
    }
    Ok(out)
}

// ── Public write API ──────────────────────────────────────────────────────

pub fn sys_write_file(path: &str, data: &[u8]) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    fs.write_inode_data(ino, data)
}

pub fn sys_truncate(path: &str, size: u64) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let current = fs.read_inode_data(&fs.inode(ino).ok_or(-2i32)?);
    let new_len  = (size as usize).min(MAX_FILE_SIZE);
    let mut new_data = alloc::vec![0u8; new_len];
    let copy_len = new_len.min(current.len());
    new_data[..copy_len].copy_from_slice(&current[..copy_len]);
    fs.write_inode_data(ino, &new_data)
}

pub fn sys_create(path: &str) -> Result<u32, i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    // Return EEXIST if path already exists.
    if fs.lookup_path(path).is_some() { return Err(-17); }
    let (parent_ino, name) = fs.dir_lookup_parent(path)?;
    let grp = ((parent_ino - 1) as usize) / fs.inodes_per_grp;
    let ino = fs.make_inode(0o100644, 0, 0, grp)?;
    fs.add_dirent(parent_ino, ino, name, FT_REG)?;
    Ok(ino)
}

pub fn sys_mkdir(path: &str, mode: u16) -> Result<u32, i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    if fs.lookup_path(path).is_some() { return Err(-17); }
    let (parent_ino, name) = fs.dir_lookup_parent(path)?;
    let grp = ((parent_ino - 1) as usize) / fs.inodes_per_grp;
    let dir_mode = 0o040000 | (mode & 0o7777);
    let ino = fs.make_inode(dir_mode, 0, 0, grp)?;
    // Add . and .. entries.
    fs.add_dirent(ino, ino, ".", FT_DIR)?;
    fs.add_dirent(ino, parent_ino, "..", FT_DIR)?;
    fs.add_dirent(parent_ino, ino, name, FT_DIR)?;
    // Increment parent's links_count (for the .. entry).
    let mut parent_inode = fs.inode(parent_ino).ok_or(-2i32)?;
    parent_inode.links_count += 1;
    fs.write_inode(parent_ino, &parent_inode);
    // Update used_dirs in group descriptor.
    let mut gd = fs.group_desc(grp);
    gd.used_dirs += 1;
    fs.write_group_desc(grp, &gd);
    Ok(ino)
}

pub fn sys_unlink(path: &str) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    if inode.mode & 0xF000 == 0x4000 { return Err(-21); } // EISDIR
    let (parent_ino, name) = fs.dir_lookup_parent(path)?;
    fs.remove_dirent(parent_ino, name)?;
    // Decrement link count; free inode+blocks if zero.
    let mut inode = fs.inode(ino).ok_or(-2i32)?;
    inode.links_count = inode.links_count.saturating_sub(1);
    if inode.links_count == 0 {
        // Free data blocks.
        let empty: &[u8] = &[];
        let _ = fs.write_inode_data(ino, empty);
        inode = fs.inode(ino).ok_or(-2i32)?;
        inode.dtime = crate::drivers::rtc::read_unix_time().unwrap_or(0) as u32;
        fs.write_inode(ino, &inode);
        fs.free_inode(ino);
    } else {
        fs.write_inode(ino, &inode);
    }
    Ok(())
}

pub fn sys_rmdir(path: &str) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    if inode.mode & 0xF000 != 0x4000 { return Err(-20); } // ENOTDIR
    // Must be empty (only . and ..).
    let entries = fs.list_dir_ino(ino);
    let non_dot = entries.iter().filter(|(_, n, _)| n != "." && n != "..").count();
    if non_dot > 0 { return Err(-39); } // ENOTEMPTY
    let (parent_ino, name) = fs.dir_lookup_parent(path)?;
    fs.remove_dirent(parent_ino, name)?;
    // Decrement parent link count (for the .. we're removing).
    let mut parent_inode = fs.inode(parent_ino).ok_or(-2i32)?;
    parent_inode.links_count = parent_inode.links_count.saturating_sub(1);
    fs.write_inode(parent_ino, &parent_inode);
    // Free the directory inode.
    let mut inode = fs.inode(ino).ok_or(-2i32)?;
    inode.links_count = 0;
    inode.dtime = crate::drivers::rtc::read_unix_time().unwrap_or(0) as u32;
    fs.write_inode(ino, &inode);
    fs.free_inode(ino);
    let grp = ((ino - 1) as usize) / fs.inodes_per_grp;
    let mut gd = fs.group_desc(grp);
    gd.used_dirs = gd.used_dirs.saturating_sub(1);
    fs.write_group_desc(grp, &gd);
    Ok(())
}

pub fn sys_rename(old: &str, new: &str) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(old).ok_or(-2i32)?;
    // If new already exists, unlink it first (POSIX atomic rename).
    if let Some(existing) = fs.lookup_path(new) {
        let ex_inode = fs.inode(existing).ok_or(-2i32)?;
        let (new_parent, new_name) = fs.dir_lookup_parent(new)?;
        fs.remove_dirent(new_parent, new_name)?;
        let mut ex = fs.inode(existing).ok_or(-2i32)?;
        ex.links_count = ex.links_count.saturating_sub(1);
        if ex.links_count == 0 {
            if ex_inode.mode & 0xF000 != 0x4000 {
                let _ = fs.write_inode_data(existing, &[]);
            }
            fs.free_inode(existing);
        } else {
            fs.write_inode(existing, &ex);
        }
    }
    let (old_parent, old_name) = fs.dir_lookup_parent(old)?;
    let (new_parent, new_name) = fs.dir_lookup_parent(new)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    let ft = if inode.mode & 0xF000 == 0x4000 { FT_DIR } else { FT_REG };
    fs.remove_dirent(old_parent, old_name)?;
    fs.add_dirent(new_parent, ino, new_name, ft)?;
    Ok(())
}

pub fn sys_link(old: &str, new: &str) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(old).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    if inode.mode & 0xF000 == 0x4000 { return Err(-21); } // EISDIR
    if fs.lookup_path(new).is_some() { return Err(-17); }
    let (new_parent, new_name) = fs.dir_lookup_parent(new)?;
    fs.add_dirent(new_parent, ino, new_name, FT_REG)?;
    let mut inode = fs.inode(ino).ok_or(-2i32)?;
    inode.links_count += 1;
    fs.write_inode(ino, &inode);
    Ok(())
}

pub fn sys_symlink(target: &str, path: &str) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    if fs.lookup_path(path).is_some() { return Err(-17); }
    let (parent_ino, name) = fs.dir_lookup_parent(path)?;
    let grp = ((parent_ino - 1) as usize) / fs.inodes_per_grp;
    let ino = fs.make_inode(0o120777, 0, 0, grp)?;
    fs.write_inode_data(ino, target.as_bytes())?;
    fs.add_dirent(parent_ino, ino, name, FT_SYML)?;
    Ok(())
}

pub fn sys_readlink(path: &str) -> Result<String, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    if inode.mode & 0xF000 != 0xA000 { return Err(-22); } // EINVAL — not a symlink
    let data = fs.read_inode_data(&inode);
    String::from_utf8(data).map_err(|_| -22i32)
}

pub fn sys_chmod(path: &str, mode: u16) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let mut inode = fs.inode(ino).ok_or(-2i32)?;
    inode.mode = (inode.mode & 0xF000) | (mode & 0o7777);
    fs.write_inode(ino, &inode);
    Ok(())
}

pub fn sys_chown(path: &str, uid: u32, gid: u32) -> Result<(), i32> {
    let mut fs_lock = FS.lock();
    let fs = fs_lock.as_mut().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let mut inode = fs.inode(ino).ok_or(-2i32)?;
    inode.uid = uid as u16;
    inode.gid = gid as u16;
    fs.write_inode(ino, &inode);
    Ok(())
}
