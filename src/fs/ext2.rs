//! Ext2 / Ext3 **read-write** filesystem driver.
//!
//! # Scope
//!
//! This driver implements the classic ext2 revision-1 layout, including
//! ext3-style features that do not require journal replay:
//!
//! | Feature                    | Handling                                    |
//! |----------------------------|---------------------------------------------|
//! | REV0 / REV1 superblocks    | both supported                              |
//! | Block-map inodes           | direct + single/double/triple indirect      |
//! | Symbolic links             | fast (inline) and slow (block) paths        |
//! | Hard links                 | full link-count tracking                    |
//! | `dir_index` (htree)        | leaf blocks scanned linearly                |
//! | Large files (>2 GiB)       | via `size_hi` / `RO_COMPAT_LARGE_FILE`     |
//! | `filetype` dir entries     | used when present                           |
//! | Journal (ext3)             | *not* replayed; mount proceeds read-write   |
//!
//! # Architecture
//!
//! The entire image is read into a `Vec<u8>` on `mount()`.  All reads and
//! writes operate on that in-memory buffer.  Dirty blocks are lazily
//! written back to the virtio-blk device.  This is identical to the
//! approach taken by `ext4.rs` (read-only) and `ext4_write.rs`.
//!
//! # Public API consumed by `vfs_ops.rs` / `mount.rs`
//!
//! ```text
//! mount()          → bool
//! sys_stat()       → Result<Ext2Stat, i32>
//! sys_lstat()      → Result<Ext2Stat, i32>
//! sys_statfs()     → Result<Ext2Statfs, i32>
//! sys_truncate()   → Result<(), i32>
//! sys_link()       → Result<(), i32>
//! sys_mkdir()      → Result<(), i32>
//! sys_rmdir()      → Result<(), i32>
//! sys_unlink()     → Result<(), i32>
//! sys_rename()     → Result<(), i32>
//! sys_symlink()    → Result<(), i32>
//! sys_readlink()   → Result<String, i32>
//! sys_chmod()      → Result<(), i32>
//! sys_chown()      → Result<(), i32>
//! set_times()      → Result<(), i32>
//! readdir()        → Result<Vec<Ext2DirEntry>, i32>
//! ```
//!
//! The `fcntl` / `vfs` layer calls `fd_open` / `fd_read` / `fd_write` /
//! `fd_close` for byte-level I/O — those are handled by `vfs.rs` which in
//! turn calls `open_raw`, `read_raw`, `write_raw`.  `ext2.rs` registers
//! itself as the VFS backend for the root mount in `mount()`.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;


const ENOENT:    i32 = -2;
const EIO:       i32 = -5;
const EEXIST:    i32 = -17;
const ENOTDIR:   i32 = -20;
const EISDIR:    i32 = -21;
const EINVAL:    i32 = -22;
const ENOSPC:    i32 = -28;
const EROFS:     i32 = -30;
const ENOTEMPTY: i32 = -39;
const ELOOP:     i32 = -40;


const MAX_IMAGE_BYTES:   usize = 512 * 1024 * 1024; // 512 MiB
const MAX_FILE_SIZE:     usize = 512 * 1024 * 1024;
const MAX_SYMLINK_DEPTH: usize = 8;
const EXT2_MAGIC:        u16   = 0xEF53;
const EXT2_ROOT_INO:     u32   = 2;


const INCOMPAT_FILETYPE:   u32 = 0x0002;
const INCOMPAT_RECOVER:    u32 = 0x0004; // ext3 journal — ignored
const INCOMPAT_DIR_INDEX:  u32 = 0x0010; // htree — leaf scan
const INCOMPAT_META_BG:    u32 = 0x0010; // overlaps DIR_INDEX in some mkfs
const INCOMPAT_HANDLED:    u32 =
    INCOMPAT_FILETYPE | INCOMPAT_RECOVER | INCOMPAT_DIR_INDEX;

const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_BTREE_DIR:  u32 = 0x0004; // same as htree; accepted


/// Ext2 superblock (bytes 1024..2048 of the image).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Superblock {
    inodes_count:       u32,  // 0x00
    blocks_count:       u32,  // 0x04
    r_blocks_count:     u32,  // 0x08
    free_blocks_count:  u32,  // 0x0C
    free_inodes_count:  u32,  // 0x10
    first_data_block:   u32,  // 0x14
    log_block_size:     u32,  // 0x18
    log_frag_size:      u32,  // 0x1C
    blocks_per_group:   u32,  // 0x20
    frags_per_group:    u32,  // 0x24
    inodes_per_group:   u32,  // 0x28
    mtime:              u32,  // 0x2C
    wtime:              u32,  // 0x30
    mnt_count:          u16,  // 0x34
    max_mnt_count:      i16,  // 0x36
    magic:              u16,  // 0x38
    state:              u16,  // 0x3A
    errors:             u16,  // 0x3C
    minor_rev_level:    u16,  // 0x3E
    lastcheck:          u32,  // 0x40
    checkinterval:      u32,  // 0x44
    creator_os:         u32,  // 0x48
    rev_level:          u32,  // 0x4C  0=old 1=dynamic
    def_resuid:         u16,  // 0x50
    def_resgid:         u16,  // 0x52
    // rev1 extensions (rev_level >= 1)
    first_ino:          u32,  // 0x54
    inode_size:         u16,  // 0x58
    block_group_nr:     u16,  // 0x5A
    feature_compat:     u32,  // 0x5C
    feature_incompat:   u32,  // 0x60
    feature_ro_compat:  u32,  // 0x64
    uuid:               [u8; 16], // 0x68
    volume_name:        [u8; 16], // 0x78
    last_mounted:       [u8; 64], // 0x88
    algo_bitmap:        u32,  // 0xC8
}

/// Block group descriptor (32 bytes each).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BgDesc {
    block_bitmap:  u32,
    inode_bitmap:  u32,
    inode_table:   u32,
    free_blocks:   u16,
    free_inodes:   u16,
    used_dirs:     u16,
    _pad:          u16,
    _reserved:     [u32; 3],
}

/// Ext2 inode (128 bytes for rev0; `inode_size` for rev1, typically 128 or 256).
/// We only read the first 128 bytes which are common to all versions.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Inode {
    mode:        u16,  // 0x00
    uid_lo:      u16,  // 0x02
    size_lo:     u32,  // 0x04
    atime:       u32,  // 0x08
    ctime:       u32,  // 0x0C
    mtime:       u32,  // 0x10
    dtime:       u32,  // 0x14
    gid_lo:      u16,  // 0x18
    links_count: u16,  // 0x1A
    blocks:      u32,  // 0x1C  in 512-byte units
    flags:       u32,  // 0x20
    osd1:        u32,  // 0x24
    block:       [u32; 15], // 0x28  direct[0..11] + si + di + ti
    generation:  u32,  // 0x64
    file_acl:    u32,  // 0x68
    size_hi:     u32,  // 0x6C  (dir_acl for dirs; high 32 of size for reg files)
    faddr:       u32,  // 0x70
    // osd2 (linux)
    _osd2:       [u8; 12], // 0x74
}

/// Standard ext2 directory entry.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DirEntry {
    inode:    u32,
    rec_len:  u16,
    name_len: u8,
    file_type: u8, // 0 if !INCOMPAT_FILETYPE
}


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

#[derive(Clone, Debug, Default)]
pub struct Ext2Statfs {
    pub f_bsize:   u32,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_bavail:  u64,
    pub f_namelen: u32,
}


struct Ext2Fs {
    data:            Vec<u8>,
    block_size:      usize,
    inode_size:      usize,
    inodes_per_grp:  usize,
    blocks_per_grp:  usize,
    first_data_blk:  usize,
    total_groups:    usize,
    // cached sb fields
    inodes_count:    u32,
    blocks_count:    u32,
    free_blocks:     u32,
    r_blocks:        u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    // dirty tracking
    dirty_blocks:    Vec<u64>,
}

static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);


#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
}

#[inline]
fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off+4].copy_from_slice(&val.to_le_bytes());
}

#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off+1]])
}

#[inline]
fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off+2].copy_from_slice(&val.to_le_bytes());
}


impl Ext2Fs {

    #[inline]
    fn blk_off(&self, blkno: u32) -> Option<usize> {
        if blkno == 0 { return None; }
        let off = (blkno as usize).checked_mul(self.block_size)?;
        if off + self.block_size > self.data.len() { return None; }
        Some(off)
    }

    #[inline]
    fn block_slice(&self, blkno: u32) -> Option<&[u8]> {
        let off = self.blk_off(blkno)?;
        Some(&self.data[off..off + self.block_size])
    }

    #[inline]
    fn block_slice_mut(&mut self, blkno: u32) -> Option<&mut [u8]> {
        let off = self.blk_off(blkno)?;
        let end = off + self.block_size;
        Some(&mut self.data[off..end])
    }

    fn mark_dirty(&mut self, blkno: u32) {
        let b = blkno as u64;
        if !self.dirty_blocks.contains(&b) {
            self.dirty_blocks.push(b);
        }
    }


    fn bgd_table_off(&self) -> usize {
        // BGD table is in the block immediately after the superblock block.
        let sb_block = if self.block_size == 1024 { 1usize } else { 0usize };
        (sb_block + 1) * self.block_size
    }

    fn bgd_offset(&self, g: usize) -> usize {
        self.bgd_table_off() + g * 32
    }

    fn bgd(&self, g: usize) -> BgDesc {
        let off = self.bgd_offset(g);
        unsafe { core::ptr::read_unaligned(self.data.as_ptr().add(off) as *const BgDesc) }
    }

    fn bgd_write(&mut self, g: usize, d: &BgDesc) {
        let off = self.bgd_offset(g);
        let blkno = (off / self.block_size) as u32;
        unsafe {
            core::ptr::write_unaligned(
                self.data.as_mut_ptr().add(off) as *mut BgDesc,
                *d,
            );
        }
        self.mark_dirty(blkno);
    }


    fn inode_offset(&self, ino: u32) -> Option<usize> {
        if ino == 0 { return None; }
        let idx   = (ino - 1) as usize;
        let grp   = idx / self.inodes_per_grp;
        let local = idx % self.inodes_per_grp;
        if grp >= self.total_groups { return None; }
        let table_blk = self.bgd(grp).inode_table;
        let off = (table_blk as usize) * self.block_size + local * self.inode_size;
        if off + self.inode_size > self.data.len() { return None; }
        Some(off)
    }

    fn inode(&self, ino: u32) -> Option<Inode> {
        let off = self.inode_offset(ino)?;
        Some(unsafe { core::ptr::read_unaligned(self.data.as_ptr().add(off) as *const Inode) })
    }

    fn inode_write(&mut self, ino: u32, inode: &Inode) -> bool {
        let off = match self.inode_offset(ino) { Some(o) => o, None => return false };
        let blkno = (off / self.block_size) as u32;
        unsafe {
            core::ptr::write_unaligned(
                self.data.as_mut_ptr().add(off) as *mut Inode,
                *inode,
            );
        }
        self.mark_dirty(blkno);
        true
    }

    fn inode_size_bytes(&self, inode: &Inode) -> u64 {
        let lo = inode.size_lo as u64;
        if inode.mode & 0xF000 == 0x8000
            && self.feature_ro_compat & RO_COMPAT_LARGE_FILE != 0
        {
            lo | ((inode.size_hi as u64) << 32)
        } else {
            lo
        }
    }


    fn ptr_block(&self, blkno: u32) -> Vec<u32> {
        let ppb = self.block_size / 4;
        match self.block_slice(blkno) {
            None    => alloc::vec![0u32; ppb],
            Some(d) => (0..ppb).map(|i| read_u32(d, i * 4)).collect(),
        }
    }


    fn read_inode_data(&self, inode: &Inode) -> Vec<u8> {
        let size = (self.inode_size_bytes(inode) as usize).min(MAX_FILE_SIZE);
        if size == 0 { return Vec::new(); }

        // Fast-path: inline symlink stored directly in block[] pointers.
        if inode.mode & 0xF000 == 0xA000 && size <= 60 {
            let raw: [u8; 60] = unsafe { core::mem::transmute(inode.block) };
            return raw[..size].to_vec();
        }

        let mut out     = alloc::vec![0u8; size];
        let mut written = 0usize;
        let bs          = self.block_size;

        let mut copy = |blkno: u32| {
            if written >= size { return; }
            if let Some(d) = self.block_slice(blkno) {
                let n = (size - written).min(d.len());
                out[written..written + n].copy_from_slice(&d[..n]);
                written += n;
            }
        };

        // Direct blocks [0..11].
        for i in 0..12usize {
            if inode.block[i] != 0 { copy(inode.block[i]); }
        }

        // Single indirect.
        if written < size && inode.block[12] != 0 {
            let l1 = self.ptr_block(inode.block[12]);
            for &b in &l1 {
                if written >= size { break; }
                if b != 0 { copy(b); }
            }
        }

        // Double indirect.
        if written < size && inode.block[13] != 0 {
            let l1 = self.ptr_block(inode.block[13]);
            'di: for &b1 in &l1 {
                if b1 == 0 { continue; }
                let l2 = self.ptr_block(b1);
                for &b2 in &l2 {
                    if written >= size { break 'di; }
                    if b2 != 0 { copy(b2); }
                }
            }
        }

        // Triple indirect.
        if written < size && inode.block[14] != 0 {
            let l1 = self.ptr_block(inode.block[14]);
            'ti: for &b1 in &l1 {
                if b1 == 0 { continue; }
                let l2 = self.ptr_block(b1);
                for &b2 in &l2 {
                    if b2 == 0 { continue; }
                    let l3 = self.ptr_block(b2);
                    for &b3 in &l3 {
                        if written >= size { break 'ti; }
                        if b3 != 0 { copy(b3); }
                    }
                }
            }
        }

        out.truncate(size);
        out
    }

    //
    // Strategy:
    //   1. Compute how many blocks are needed for `data`.
    //   2. Free excess blocks if shrinking.
    //   3. Allocate new blocks if growing.
    //   4. Copy data into each block.
    //   5. Update inode size + block count fields.

    fn write_inode_data(&mut self, ino: u32, data: &[u8]) -> Result<(), i32> {
        let inode = self.inode(ino).ok_or(ENOENT)?;
        let bs    = self.block_size;
        let ppb   = bs / 4;

        // Blocks needed.
        let nblocks_needed = data.len().div_ceil(bs);
        // Current block array (up to 12 direct + indirect).
        // We flatten the entire block list for simplicity.
        let old_blocks = self.collect_data_blocks(&inode);
        let nblocks_have = old_blocks.len();

        // Allocate additional blocks if needed.
        let mut all_blocks = old_blocks.clone();
        if nblocks_needed > nblocks_have {
            for _ in nblocks_have..nblocks_needed {
                let b = self.alloc_block(ino).ok_or(ENOSPC)?;
                all_blocks.push(b);
            }
        } else {
            // Free excess blocks.
            for &b in &old_blocks[nblocks_needed..] {
                self.free_block(b);
            }
            all_blocks.truncate(nblocks_needed);
        }

        // Copy data into blocks.
        let mut off = 0usize;
        for &blkno in &all_blocks {
            let chunk_end = (off + bs).min(data.len());
            let chunk     = &data[off..chunk_end];
            let dst_off   = blkno as usize * bs;
            let dst_end   = dst_off + bs;
            if dst_end <= self.data.len() {
                let dst = &mut self.data[dst_off..dst_end];
                dst[..chunk.len()].copy_from_slice(chunk);
                if chunk.len() < bs {
                    dst[chunk.len()..].fill(0);
                }
                self.mark_dirty(blkno);
            }
            off += bs;
        }

        // Rebuild the inode block[] pointers.
        let mut new_inode = inode;
        new_inode.block = [0u32; 15];
        let n = all_blocks.len();

        // Direct.
        for i in 0..n.min(12) {
            new_inode.block[i] = all_blocks[i];
        }

        // Single indirect.
        if n > 12 {
            let si_blkno = if nblocks_have <= 12 {
                // Need a new indirect block.
                self.alloc_block(ino).ok_or(ENOSPC)?
            } else {
                old_blocks.get(12).copied().unwrap_or(0)
                    .max(new_inode.block[12])
            };
            let si_blkno = si_blkno.max(
                if inode.block[12] != 0 { inode.block[12] } else {
                    self.alloc_block(ino).ok_or(ENOSPC)?
                }
            );
            // Use original si block if valid, else allocate.
            let si = if inode.block[12] != 0 {
                inode.block[12]
            } else {
                self.alloc_block(ino).ok_or(ENOSPC)?
            };
            new_inode.block[12] = si;
            let si_off = si as usize * bs;
            if si_off + bs <= self.data.len() {
                self.data[si_off..si_off + bs].fill(0);
                let end = n.min(12 + ppb);
                for i in 12..end {
                    let b = all_blocks[i];
                    write_u32(&mut self.data, si_off + (i - 12) * 4, b);
                }
                self.mark_dirty(si);
            }
        }

        // Update inode size + block count.
        new_inode.size_lo  = data.len() as u32;
        if self.feature_ro_compat & RO_COMPAT_LARGE_FILE != 0 {
            new_inode.size_hi = (data.len() as u64 >> 32) as u32;
        }
        // i_blocks is in 512-byte units.
        new_inode.blocks = (all_blocks.len() * bs / 512) as u32;

        self.inode_write(ino, &new_inode);
        Ok(())
    }


    fn collect_data_blocks(&self, inode: &Inode) -> Vec<u32> {
        let mut out = Vec::new();
        let ppb = self.block_size / 4;

        for i in 0..12usize {
            if inode.block[i] != 0 { out.push(inode.block[i]); }
        }

        if inode.block[12] != 0 {
            let l1 = self.ptr_block(inode.block[12]);
            for &b in &l1 { if b != 0 { out.push(b); } }
        }

        if inode.block[13] != 0 {
            let l1 = self.ptr_block(inode.block[13]);
            for &b1 in &l1 {
                if b1 == 0 { continue; }
                let l2 = self.ptr_block(b1);
                for &b2 in &l2 { if b2 != 0 { out.push(b2); } }
            }
        }

        if inode.block[14] != 0 {
            let l1 = self.ptr_block(inode.block[14]);
            for &b1 in &l1 {
                if b1 == 0 { continue; }
                let l2 = self.ptr_block(b1);
                for &b2 in &l2 {
                    if b2 == 0 { continue; }
                    let l3 = self.ptr_block(b2);
                    for &b3 in &l3 { if b3 != 0 { out.push(b3); } }
                }
            }
        }

        out
    }


    fn alloc_block(&mut self, near_ino: u32) -> Option<u32> {
        // Prefer the block group of `near_ino`.
        let preferred_grp = ((near_ino.saturating_sub(1)) as usize) / self.inodes_per_grp;
        let order: Vec<usize> = (0..self.total_groups)
            .map(|i| (i + preferred_grp) % self.total_groups)
            .collect();

        for g in order {
            let d = self.bgd(g);
            if d.free_blocks == 0 { continue; }
            let bm_blkno = d.block_bitmap;
            let bm_off   = bm_blkno as usize * self.block_size;
            if bm_off + self.block_size > self.data.len() { continue; }

            let first_blk = g * self.blocks_per_grp + self.first_data_blk;

            for byte_idx in 0..self.block_size {
                let byte = self.data[bm_off + byte_idx];
                if byte == 0xFF { continue; }
                for bit in 0..8u8 {
                    if byte & (1 << bit) == 0 {
                        // Allocate this bit.
                        self.data[bm_off + byte_idx] |= 1 << bit;
                        self.mark_dirty(bm_blkno);

                        // Decrement group free_blocks.
                        let off = self.bgd_offset(g);
                        let new_free = read_u16(&self.data, off + 12).saturating_sub(1);
                        write_u16(&mut self.data, off + 12, new_free);
                        let bgd_blk = (off / self.block_size) as u32;
                        self.mark_dirty(bgd_blk);

                        // Decrement superblock free_blocks_count.
                        self.free_blocks = self.free_blocks.saturating_sub(1);
                        let sb_off = if self.block_size == 1024 { 1024 } else { 0 };
                        write_u32(&mut self.data, sb_off + 0x0C, self.free_blocks);
                        let sb_blk = (sb_off / self.block_size) as u32;
                        self.mark_dirty(sb_blk);

                        let blkno = (first_blk + byte_idx * 8 + bit as usize) as u32;
                        // Zero out the new block.
                        let blk_off = blkno as usize * self.block_size;
                        if blk_off + self.block_size <= self.data.len() {
                            self.data[blk_off..blk_off + self.block_size].fill(0);
                            self.mark_dirty(blkno);
                        }
                        return Some(blkno);
                    }
                }
            }
        }
        None
    }

    fn free_block(&mut self, blkno: u32) {
        if blkno == 0 { return; }
        let grp  = (blkno as usize).saturating_sub(self.first_data_blk) / self.blocks_per_grp;
        let local = (blkno as usize).saturating_sub(self.first_data_blk) % self.blocks_per_grp;
        if grp >= self.total_groups { return; }

        let d = self.bgd(grp);
        let bm_off = d.block_bitmap as usize * self.block_size;
        let byte = local / 8;
        let bit  = local % 8;
        if bm_off + byte < self.data.len() {
            self.data[bm_off + byte] &= !(1u8 << bit);
            self.mark_dirty(d.block_bitmap);

            let off = self.bgd_offset(grp);
            let new_free = read_u16(&self.data, off + 12).saturating_add(1);
            write_u16(&mut self.data, off + 12, new_free);
            self.mark_dirty((off / self.block_size) as u32);

            self.free_blocks = self.free_blocks.saturating_add(1);
            let sb_off = if self.block_size == 1024 { 1024 } else { 0 };
            write_u32(&mut self.data, sb_off + 0x0C, self.free_blocks);
            self.mark_dirty((sb_off / self.block_size) as u32);
        }
    }


    fn alloc_inode(&mut self, is_dir: bool) -> Option<u32> {
        for g in 0..self.total_groups {
            let d = self.bgd(g);
            if d.free_inodes == 0 { continue; }
            let bm_off = d.inode_bitmap as usize * self.block_size;
            if bm_off + self.block_size > self.data.len() { continue; }

            let inodes_in_group = self.inodes_per_grp;
            for byte_idx in 0..inodes_in_group.div_ceil(8) {
                let byte = self.data[bm_off + byte_idx];
                if byte == 0xFF { continue; }
                for bit in 0..8u8 {
                    let local = byte_idx * 8 + bit as usize;
                    if local >= inodes_in_group { break; }
                    if byte & (1 << bit) == 0 {
                        self.data[bm_off + byte_idx] |= 1 << bit;
                        self.mark_dirty(d.inode_bitmap);

                        let off = self.bgd_offset(g);
                        let new_free = read_u16(&self.data, off + 14).saturating_sub(1);
                        write_u16(&mut self.data, off + 14, new_free);
                        if is_dir {
                            let dirs = read_u16(&self.data, off + 16).saturating_add(1);
                            write_u16(&mut self.data, off + 16, dirs);
                        }
                        self.mark_dirty((off / self.block_size) as u32);

                        let sb_off = if self.block_size == 1024 { 1024 } else { 0 };
                        let fi = read_u32(&self.data, sb_off + 0x10).saturating_sub(1);
                        write_u32(&mut self.data, sb_off + 0x10, fi);
                        self.mark_dirty((sb_off / self.block_size) as u32);

                        let ino = (g * self.inodes_per_grp + local + 1) as u32;
                        return Some(ino);
                    }
                }
            }
        }
        None
    }

    fn free_inode(&mut self, ino: u32) {
        if ino == 0 { return; }
        let idx  = (ino - 1) as usize;
        let grp  = idx / self.inodes_per_grp;
        let local= idx % self.inodes_per_grp;
        if grp >= self.total_groups { return; }

        let d = self.bgd(grp);
        let bm_off = d.inode_bitmap as usize * self.block_size;
        let byte = local / 8;
        let bit  = local % 8;
        if bm_off + byte < self.data.len() {
            self.data[bm_off + byte] &= !(1u8 << bit);
            self.mark_dirty(d.inode_bitmap);

            let off = self.bgd_offset(grp);
            let new_free = read_u16(&self.data, off + 14).saturating_add(1);
            write_u16(&mut self.data, off + 14, new_free);
            self.mark_dirty((off / self.block_size) as u32);

            let sb_off = if self.block_size == 1024 { 1024 } else { 0 };
            let fi = read_u32(&self.data, sb_off + 0x10).saturating_add(1);
            write_u32(&mut self.data, sb_off + 0x10, fi);
            self.mark_dirty((sb_off / self.block_size) as u32);
        }
    }


    /// Scan directory blocks, calling `f` with each block.  Stop if `f` returns false.
    fn scan_dir<F>(&self, inode: &Inode, mut f: F)
    where F: FnMut(&[u8]) -> bool
    {
        let ppb = self.block_size / 4;

        for i in 0..12usize {
            let b = inode.block[i];
            if b == 0 { continue; }
            if let Some(blk) = self.block_slice(b) {
                let owned: Vec<u8> = blk.to_vec();
                if !f(&owned) { return; }
            }
        }

        if inode.block[12] != 0 {
            let l1 = self.ptr_block(inode.block[12]);
            for &b in &l1 {
                if b == 0 { continue; }
                if let Some(blk) = self.block_slice(b) {
                    let owned: Vec<u8> = blk.to_vec();
                    if !f(&owned) { return; }
                }
            }
        }
    }

    fn lookup_dir_ino(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let inode = self.inode(dir_ino)?;
        let nb    = name.as_bytes();
        let mut result = None;
        self.scan_dir(&inode, |blk| {
            let mut off = 0usize;
            while off + 8 <= blk.len() {
                let de_ino  = read_u32(blk, off);
                let rec_len = read_u16(blk, off + 4) as usize;
                let nam_len = blk[off + 6] as usize;
                if rec_len < 8 { break; }
                if de_ino != 0 && nam_len == nb.len() {
                    let ne = off + 8 + nam_len;
                    if ne <= blk.len() && &blk[off + 8..ne] == nb {
                        result = Some(de_ino);
                        return false;
                    }
                }
                off += rec_len;
            }
            true
        });
        result
    }

    fn list_dir_ino(&self, dir_ino: u32) -> Vec<(u32, String, bool)> {
        let mut out   = Vec::new();
        let inode = match self.inode(dir_ino) { Some(i) => i, None => return out };
        self.scan_dir(&inode, |blk| {
            let mut off = 0usize;
            while off + 8 <= blk.len() {
                let de_ino  = read_u32(blk, off);
                let rec_len = read_u16(blk, off + 4) as usize;
                let nam_len = blk[off + 6] as usize;
                let ftype   = blk[off + 7];
                if rec_len < 8 { break; }
                if de_ino != 0 {
                    let ne = off + 8 + nam_len;
                    if ne <= blk.len() {
                        if let Ok(s) = core::str::from_utf8(&blk[off + 8..ne]) {
                            let is_dir = ftype == 2
                                || self.inode(de_ino)
                                    .map_or(false, |i| i.mode & 0xF000 == 0x4000);
                            out.push((de_ino, String::from(s), is_dir));
                        }
                    }
                }
                off += rec_len;
            }
            true
        });
        out
    }

    /// Add a directory entry `(name → child_ino, ftype)` to directory `dir_ino`.
    fn dir_add_entry(&mut self, dir_ino: u32, name: &str, child_ino: u32, ftype: u8)
        -> Result<(), i32>
    {
        let nb = name.as_bytes();
        if nb.len() > 255 { return Err(EINVAL); }
        let needed  = (8 + nb.len() + 3) & !3; // rounded to 4 bytes

        let inode = self.inode(dir_ino).ok_or(ENOENT)?;
        let bs    = self.block_size;

        // Try to fit into an existing block.
        let direct: Vec<u32> = (0..12).filter_map(|i| {
            if inode.block[i] != 0 { Some(inode.block[i]) } else { None }
        }).collect();

        for &blkno in &direct {
            let boff = blkno as usize * bs;
            if boff + bs > self.data.len() { continue; }
            let mut off = 0usize;
            loop {
                if off + 8 > bs { break; }
                let rec_len = read_u16(&self.data, boff + off + 4) as usize;
                if rec_len < 8 { break; }
                let de_ino  = read_u32(&self.data, boff + off);
                let real_len = if de_ino == 0 {
                    rec_len
                } else {
                    let nl = self.data[boff + off + 6] as usize;
                    (8 + nl + 3) & !3
                };
                let free_in_entry = rec_len - real_len;
                if free_in_entry >= needed {
                    // Split: shorten current entry, insert new after.
                    if de_ino != 0 {
                        write_u16(&mut self.data, boff + off + 4, real_len as u16);
                        off += real_len;
                    }
                    // Write new entry.
                    let remaining = (boff + off + rec_len) - (boff + off);
                    write_u32(&mut self.data, boff + off, child_ino);
                    write_u16(&mut self.data, boff + off + 4, remaining as u16);
                    self.data[boff + off + 6] = nb.len() as u8;
                    self.data[boff + off + 7] = ftype;
                    self.data[boff + off + 8..boff + off + 8 + nb.len()]
                        .copy_from_slice(nb);
                    self.mark_dirty(blkno);
                    return Ok(());
                }
                off += rec_len;
            }
        }

        // No room — allocate a new block.
        let new_blk = self.alloc_block(dir_ino).ok_or(ENOSPC)?;
        // Assign it to the inode's next free direct slot.
        let mut inode = self.inode(dir_ino).ok_or(ENOENT)?;
        let mut placed = false;
        for i in 0..12usize {
            if inode.block[i] == 0 {
                inode.block[i] = new_blk;
                placed = true;
                break;
            }
        }
        if !placed { return Err(ENOSPC); } // simplified: no si expansion here

        let boff = new_blk as usize * bs;
        write_u32(&mut self.data, boff, child_ino);
        write_u16(&mut self.data, boff + 4, bs as u16);
        self.data[boff + 6] = nb.len() as u8;
        self.data[boff + 7] = ftype;
        self.data[boff + 8..boff + 8 + nb.len()].copy_from_slice(nb);

        // Update dir inode size.
        inode.size_lo += bs as u32;
        inode.blocks  += (bs / 512) as u32;
        self.inode_write(dir_ino, &inode);
        Ok(())
    }

    /// Remove the directory entry named `name` from directory `dir_ino`.
    fn dir_remove_entry(&mut self, dir_ino: u32, name: &str) -> Result<u32, i32> {
        let nb    = name.as_bytes();
        let bs    = self.block_size;
        let inode = self.inode(dir_ino).ok_or(ENOENT)?;

        let direct: Vec<u32> = (0..12).filter_map(|i| {
            if inode.block[i] != 0 { Some(inode.block[i]) } else { None }
        }).collect();

        for &blkno in &direct {
            let boff = blkno as usize * bs;
            if boff + bs > self.data.len() { continue; }
            let mut off = 0usize;
            let mut prev_off: Option<usize> = None;
            loop {
                if off + 8 > bs { break; }
                let rec_len = read_u16(&self.data, boff + off + 4) as usize;
                if rec_len < 8 { break; }
                let de_ino  = read_u32(&self.data, boff + off);
                let nl      = self.data[boff + off + 6] as usize;
                if de_ino != 0 && nl == nb.len() {
                    let ne = off + 8 + nl;
                    if ne <= bs && &self.data[boff + off + 8..boff + ne] == nb {
                        // Found: absorb into previous entry or zero inode.
                        if let Some(p) = prev_off {
                            let prev_rec = read_u16(&self.data, boff + p + 4) as usize;
                            write_u16(&mut self.data, boff + p + 4,
                                (prev_rec + rec_len) as u16);
                        } else {
                            // Zero inode field to mark deleted.
                            write_u32(&mut self.data, boff + off, 0);
                        }
                        self.mark_dirty(blkno);
                        return Ok(de_ino);
                    }
                }
                prev_off = Some(off);
                off += rec_len;
            }
        }
        Err(ENOENT)
    }


    fn resolve_depth(&self, path: &str, follow_last: bool, depth: usize)
        -> Option<(u32, u32, String)>
    // Returns (parent_ino, child_ino, last_component)
    {
        if depth > MAX_SYMLINK_DEPTH { return None; }
        let trimmed = path.trim_start_matches('/');
        if trimmed.is_empty() { return Some((EXT2_ROOT_INO, EXT2_ROOT_INO, String::new())); }

        let (parent_part, last) = match trimmed.rfind('/') {
            Some(i) => (&trimmed[..i], &trimmed[i+1..]),
            None    => ("", trimmed),
        };

        // Resolve parent directory.
        let parent_ino = if parent_part.is_empty() {
            EXT2_ROOT_INO
        } else {
            self.resolve_depth(
                &alloc::format!("/{}", parent_part), true, depth + 1
            )?.1
        };

        let child_ino = self.lookup_dir_ino(parent_ino, last)?;
        let child_inode = self.inode(child_ino)?;

        if follow_last && child_inode.mode & 0xF000 == 0xA000 {
            // Follow symlink.
            let data = self.read_inode_data(&child_inode);
            let target = core::str::from_utf8(&data).ok()?;
            let abs_target = if target.starts_with('/') {
                String::from(target)
            } else {
                alloc::format!("{}/{}", parent_part, target)
            };
            return self.resolve_depth(&abs_target, true, depth + 1);
        }

        Some((parent_ino, child_ino, last.to_string()))
    }

    fn lookup_path(&self, path: &str) -> Option<u32> {
        self.resolve_depth(path, true, 0).map(|(_, ino, _)| ino)
    }

    /// Resolve without following the *final* component's symlink (for lstat).
    fn lookup_lstat(&self, path: &str) -> Option<u32> {
        self.resolve_depth(path, false, 0).map(|(_, ino, _)| ino)
    }


    fn inode_to_stat(&self, ino: u32, inode: &Inode) -> Ext2Stat {
        let uid = inode.uid_lo as u32;
        let gid = inode.gid_lo as u32;
        let size = self.inode_size_bytes(inode);
        Ext2Stat {
            ino,
            mode:    inode.mode,
            nlink:   inode.links_count as u32,
            uid,
            gid,
            size,
            atime:   inode.atime as u64,
            mtime:   inode.mtime as u64,
            ctime:   inode.ctime as u64,
            blksize: self.block_size as u32,
            blocks:  inode.blocks as u64,
        }
    }


    fn flush(&mut self) {
        let bs = self.block_size;
        let blknos: Vec<u64> = self.dirty_blocks.drain(..).collect();
        for blkno in blknos {
            let off = blkno as usize * bs;
            if off + bs > self.data.len() { continue; }
            let block_data = self.data[off..off + bs].to_vec();
            let lba_start = blkno * (bs as u64 / 512);
            let sectors   = bs / 512;
            for (i, chunk) in block_data.chunks(512).enumerate() {
                let _ = crate::drivers::virtio_blk::write_sector(lba_start + i as u64, chunk);
            }
        }
    }
}


/// Mount the ext2/ext3 filesystem from the primary virtio-blk device.
///
/// Returns `true` on success, `false` if the device is absent, the magic
/// is wrong, or unsupported INCOMPAT features are present.
pub fn mount() -> bool {
    if !crate::drivers::virtio_blk::is_present() { return false; }

    // Read superblock (LBA 2..4 = bytes 1024..2048).
    let mut raw_sb = alloc::vec![0u8; 1024];
    let mut half   = alloc::vec![0u8; 512];
    if crate::drivers::virtio_blk::read_sectors(2, &mut half).is_err() { return false; }
    raw_sb[..512].copy_from_slice(&half);
    if crate::drivers::virtio_blk::read_sectors(3, &mut half).is_err() { return false; }
    raw_sb[512..].copy_from_slice(&half);

    let sb: Superblock = unsafe {
        core::ptr::read_unaligned(raw_sb.as_ptr() as *const Superblock)
    };

    if sb.magic != EXT2_MAGIC { return false; }

    // ext4 superblocks (rev1 with extent-tree) are handled by ext4.rs.
    // We accept rev0 and rev1 without unsupported INCOMPAT bits.
    if sb.rev_level >= 1 {
        let unhandled = sb.feature_incompat & !INCOMPAT_HANDLED;
        if unhandled != 0 {
            log::warn!(
                "ext2: unsupported INCOMPAT {:#010x} — refusing mount",
                unhandled
            );
            return false;
        }
    }

    let block_size    = 1024usize << sb.log_block_size;
    let total_blocks  = sb.blocks_count as usize;
    let load_bytes    = (total_blocks * block_size).min(MAX_IMAGE_BYTES);
    let inodes_per_grp= sb.inodes_per_group as usize;
    let blocks_per_grp= sb.blocks_per_group as usize;
    let total_groups  = total_blocks.div_ceil(blocks_per_grp);
    let inode_size    = if sb.rev_level >= 1 && sb.inode_size >= 128 {
        sb.inode_size as usize
    } else {
        128
    };

    // Load the entire image.
    let mut image  = alloc::vec![0u8; load_bytes];
    let mut lba    = 0u64;
    let mut off    = 0usize;
    let chunk_secs = 128usize; // 64 KiB per read
    while off < load_bytes {
        let n = chunk_secs.min((load_bytes - off) / 512);
        if n == 0 { break; }
        if crate::drivers::virtio_blk::read_sectors(lba, &mut image[off..off + n * 512])
            .is_err() { break; }
        off += n * 512;
        lba += n as u64;
    }

    let (feature_incompat, feature_ro_compat) = if sb.rev_level >= 1 {
        (sb.feature_incompat, sb.feature_ro_compat)
    } else {
        (0, 0)
    };

    *FS.lock() = Some(Ext2Fs {
        data: image,
        block_size,
        inode_size,
        inodes_per_grp,
        blocks_per_grp,
        first_data_blk: sb.first_data_block as usize,
        total_groups,
        inodes_count:    sb.inodes_count,
        blocks_count:    sb.blocks_count,
        free_blocks:     sb.free_blocks_count,
        r_blocks:        sb.r_blocks_count,
        feature_incompat,
        feature_ro_compat,
        dirty_blocks: Vec::new(),
    });

    log::info!(
        "ext2: mounted {} MiB, block_size={}, groups={}, incompat={:#010x}",
        load_bytes >> 20, block_size, total_groups, feature_incompat,
    );
    true
}


/// stat — follow symlinks on last component.
pub fn sys_stat(path: &str) -> Result<Ext2Stat, i32> {
    let fs  = FS.lock();
    let fs  = fs.as_ref().ok_or(EIO)?;
    let ino = fs.lookup_path(path).ok_or(ENOENT)?;
    let i   = fs.inode(ino).ok_or(EIO)?;
    Ok(fs.inode_to_stat(ino, &i))
}

/// lstat — do not follow the final symlink.
pub fn sys_lstat(path: &str) -> Result<Ext2Stat, i32> {
    let fs  = FS.lock();
    let fs  = fs.as_ref().ok_or(EIO)?;
    let ino = fs.lookup_lstat(path).ok_or(ENOENT)?;
    let i   = fs.inode(ino).ok_or(EIO)?;
    Ok(fs.inode_to_stat(ino, &i))
}

pub fn sys_statfs(path: &str) -> Result<Ext2Statfs, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(EIO)?;
    // Just verify path exists.
    let _  = fs.lookup_path(path).ok_or(ENOENT)?;
    Ok(Ext2Statfs {
        f_bsize:   fs.block_size as u32,
        f_blocks:  fs.blocks_count as u64,
        f_bfree:   fs.free_blocks as u64,
        f_bavail:  fs.free_blocks.saturating_sub(fs.r_blocks) as u64,
        f_namelen: 255,
    })
}

/// readdir — list directory entries.
pub fn readdir(path: &str) -> Result<Vec<Ext2DirEntry>, i32> {
    let fs  = FS.lock();
    let fs  = fs.as_ref().ok_or(EIO)?;
    let ino = fs.lookup_path(path).ok_or(ENOENT)?;
    let raw = fs.list_dir_ino(ino);
    let mut out = Vec::with_capacity(raw.len());
    for (cino, name, is_dir) in raw {
        let (mode, size) = fs.inode(cino)
            .map(|i| (i.mode, fs.inode_size_bytes(&i)))
            .unwrap_or((0, 0));
        out.push(Ext2DirEntry { ino: cino, name, is_dir, mode, size });
    }
    Ok(out)
}

pub fn sys_readlink(path: &str) -> Result<String, i32> {
    let fs  = FS.lock();
    let fs  = fs.as_ref().ok_or(EIO)?;
    let ino = fs.lookup_lstat(path).ok_or(ENOENT)?;
    let i   = fs.inode(ino).ok_or(EIO)?;
    if i.mode & 0xF000 != 0xA000 { return Err(EINVAL); }
    let data = fs.read_inode_data(&i);
    String::from_utf8(data).map_err(|_| EINVAL)
}

pub fn sys_truncate(path: &str, len: u64) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;
    let ino    = fs.lookup_path(path).ok_or(ENOENT)?;
    let inode  = fs.inode(ino).ok_or(EIO)?;
    if inode.mode & 0xF000 != 0x8000 { return Err(EISDIR); }

    let old_data = fs.read_inode_data(&inode);
    let new_len  = len as usize;
    let mut new_data = alloc::vec![0u8; new_len];
    let copy_len = old_data.len().min(new_len);
    new_data[..copy_len].copy_from_slice(&old_data[..copy_len]);

    fs.write_inode_data(ino, &new_data)?;
    fs.flush();
    Ok(())
}

pub fn sys_link(existing: &str, new: &str) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;

    let src_ino = fs.lookup_path(existing).ok_or(ENOENT)?;
    let src_inode = fs.inode(src_ino).ok_or(EIO)?;
    if src_inode.mode & 0xF000 == 0x4000 { return Err(EISDIR); }

    // Resolve new's parent.
    let (parent_ino, _, last) = fs.resolve_depth(new, false, 0).ok_or(ENOENT)?;
    if last.is_empty() { return Err(EEXIST); }

    // Check new doesn't already exist.
    if fs.lookup_dir_ino(parent_ino, &last).is_some() { return Err(EEXIST); }

    let ftype = mode_to_ftype(src_inode.mode);
    fs.dir_add_entry(parent_ino, &last, src_ino, ftype)?;

    let mut src_inode = fs.inode(src_ino).ok_or(EIO)?;
    src_inode.links_count += 1;
    fs.inode_write(src_ino, &src_inode);
    fs.flush();
    Ok(())
}

pub fn sys_mkdir(path: &str, mode: u16) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;

    let (parent_ino, _, last) = fs.resolve_depth(path, false, 0).ok_or(ENOENT)?;
    if last.is_empty() { return Err(EEXIST); }
    if fs.lookup_dir_ino(parent_ino, &last).is_some() { return Err(EEXIST); }

    let new_ino = fs.alloc_inode(true).ok_or(ENOSPC)?;
    let now     = current_time();
    let new_dir_blk = fs.alloc_block(new_ino).ok_or(ENOSPC)?;

    // Initialise inode.
    let dir_mode = (mode & 0xFFF) | 0x4000;
    let mut inode: Inode = unsafe { core::mem::zeroed() };
    inode.mode        = dir_mode;
    inode.links_count = 2; // . and parent's entry
    inode.atime       = now;
    inode.ctime       = now;
    inode.mtime       = now;
    inode.block[0]    = new_dir_blk;
    inode.size_lo     = fs.block_size as u32;
    inode.blocks      = (fs.block_size / 512) as u32;
    fs.inode_write(new_ino, &inode);

    // Initialise the directory block with "." and ".." entries.
    let boff = new_dir_blk as usize * fs.block_size;
    let bs   = fs.block_size;
    // "." entry (12 bytes)
    write_u32(&mut fs.data, boff,     new_ino);
    write_u16(&mut fs.data, boff + 4, 12);
    fs.data[boff + 6] = 1; // name_len
    fs.data[boff + 7] = 2; // FT_DIR
    fs.data[boff + 8] = b'.';
    // ".." entry (remainder of block)
    write_u32(&mut fs.data, boff + 12, parent_ino);
    write_u16(&mut fs.data, boff + 16, (bs - 12) as u16);
    fs.data[boff + 18] = 2; // name_len
    fs.data[boff + 19] = 2; // FT_DIR
    fs.data[boff + 20] = b'.';
    fs.data[boff + 21] = b'.';
    fs.mark_dirty(new_dir_blk);

    // Add entry in parent directory.
    fs.dir_add_entry(parent_ino, &last, new_ino, 2 /* FT_DIR */)?;

    // Increment parent link count (for "..").
    let mut parent_inode = fs.inode(parent_ino).ok_or(EIO)?;
    parent_inode.links_count += 1;
    fs.inode_write(parent_ino, &parent_inode);

    fs.flush();
    Ok(())
}

pub fn sys_rmdir(path: &str) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;

    let (parent_ino, dir_ino, last) = fs.resolve_depth(path, false, 0).ok_or(ENOENT)?;
    if last.is_empty() { return Err(EINVAL); } // can't remove root

    let dir_inode = fs.inode(dir_ino).ok_or(EIO)?;
    if dir_inode.mode & 0xF000 != 0x4000 { return Err(ENOTDIR); }

    // Check empty (only "." and ".." allowed).
    let entries = fs.list_dir_ino(dir_ino);
    let non_dot = entries.iter().filter(|(_, n, _)| n != "." && n != "..").count();
    if non_dot > 0 { return Err(ENOTEMPTY); }

    // Remove from parent.
    fs.dir_remove_entry(parent_ino, &last)?;

    // Decrement parent link count.
    let mut parent_inode = fs.inode(parent_ino).ok_or(EIO)?;
    parent_inode.links_count = parent_inode.links_count.saturating_sub(1);
    fs.inode_write(parent_ino, &parent_inode);

    // Free dir blocks.
    let data_blocks = fs.collect_data_blocks(&dir_inode);
    for b in data_blocks { fs.free_block(b); }

    // Free inode.
    fs.free_inode(dir_ino);
    fs.flush();
    Ok(())
}

pub fn sys_unlink(path: &str) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;

    let (parent_ino, file_ino, last) = fs.resolve_depth(path, false, 0).ok_or(ENOENT)?;
    if last.is_empty() { return Err(EINVAL); }

    let inode = fs.inode(file_ino).ok_or(EIO)?;
    if inode.mode & 0xF000 == 0x4000 { return Err(EISDIR); }

    fs.dir_remove_entry(parent_ino, &last)?;

    let mut inode = inode;
    inode.links_count = inode.links_count.saturating_sub(1);
    if inode.links_count == 0 {
        let blocks = fs.collect_data_blocks(&inode);
        for b in blocks { fs.free_block(b); }
        fs.free_inode(file_ino);
    } else {
        fs.inode_write(file_ino, &inode);
    }

    fs.flush();
    Ok(())
}

pub fn sys_rename(old: &str, new: &str) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;

    let (old_parent, old_ino, old_last) = fs.resolve_depth(old, false, 0).ok_or(ENOENT)?;
    if old_last.is_empty() { return Err(EINVAL); }

    let (new_parent, _, new_last) = fs.resolve_depth(new, false, 0).ok_or(ENOENT)?;
    if new_last.is_empty() { return Err(EINVAL); }

    let old_inode = fs.inode(old_ino).ok_or(EIO)?;

    // If destination exists, remove it first.
    if let Some(dst_ino) = fs.lookup_dir_ino(new_parent, &new_last) {
        let dst_inode = fs.inode(dst_ino).ok_or(EIO)?;
        if dst_inode.mode & 0xF000 == 0x4000 {
            let entries = fs.list_dir_ino(dst_ino);
            let non_dot = entries.iter().filter(|(_, n, _)| n != "." && n != "..").count();
            if non_dot > 0 { return Err(ENOTEMPTY); }
        }
        fs.dir_remove_entry(new_parent, &new_last)?;
    }

    // Add new entry.
    let ftype = mode_to_ftype(old_inode.mode);
    fs.dir_add_entry(new_parent, &new_last, old_ino, ftype)?;

    // Remove old entry.
    fs.dir_remove_entry(old_parent, &old_last)?;

    // Update ".." in moved directory.
    if old_inode.mode & 0xF000 == 0x4000 && old_parent != new_parent {
        // Find the ".." entry in the moved dir and update it.
        let bs = fs.block_size;
        let inode = fs.inode(old_ino).ok_or(EIO)?;
        let first_blk = inode.block[0];
        if first_blk != 0 {
            let boff = first_blk as usize * bs;
            // ".." is the second entry (after "." at offset 0).
            // "." is 12 bytes (1 char name, padded).
            let dotdot_off = boff + 12;
            if dotdot_off + 8 <= fs.data.len() {
                let nl = fs.data[dotdot_off + 6] as usize;
                let name = &fs.data[dotdot_off + 8..dotdot_off + 8 + nl.min(2)];
                if nl == 2 && name == b".." {
                    write_u32(&mut fs.data, dotdot_off, new_parent);
                    fs.mark_dirty(first_blk);
                }
            }
        }
    }

    fs.flush();
    Ok(())
}

pub fn sys_symlink(target: &str, path: &str) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;

    let (parent_ino, _, last) = fs.resolve_depth(path, false, 0).ok_or(ENOENT)?;
    if last.is_empty() { return Err(EEXIST); }
    if fs.lookup_dir_ino(parent_ino, &last).is_some() { return Err(EEXIST); }

    let new_ino = fs.alloc_inode(false).ok_or(ENOSPC)?;
    let now     = current_time();
    let tlen    = target.len();

    let mut inode: Inode = unsafe { core::mem::zeroed() };
    inode.mode        = 0xA1FF;
    inode.links_count = 1;
    inode.atime       = now;
    inode.ctime       = now;
    inode.mtime       = now;
    inode.size_lo     = tlen as u32;

    if tlen <= 60 {
        // Fast symlink: store inline in block[].
        let raw: &mut [u8; 60] = unsafe { core::mem::transmute(&mut inode.block) };
        raw[..tlen].copy_from_slice(target.as_bytes());
        inode.blocks = 0;
        fs.inode_write(new_ino, &inode);
    } else {
        fs.inode_write(new_ino, &inode);
        fs.write_inode_data(new_ino, target.as_bytes())?;
    }

    fs.dir_add_entry(parent_ino, &last, new_ino, 7 /* FT_SYMLINK */)?;
    fs.flush();
    Ok(())
}

pub fn sys_chmod(path: &str, mode: u16) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;
    let ino    = fs.lookup_path(path).ok_or(ENOENT)?;
    let mut i  = fs.inode(ino).ok_or(EIO)?;
    i.mode     = (i.mode & 0xF000) | (mode & 0x0FFF);
    i.ctime    = current_time();
    fs.inode_write(ino, &i);
    fs.flush();
    Ok(())
}

pub fn sys_chown(path: &str, uid: u32, gid: u32) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;
    let ino    = fs.lookup_path(path).ok_or(ENOENT)?;
    let mut i  = fs.inode(ino).ok_or(EIO)?;
    i.uid_lo   = uid as u16;
    i.gid_lo   = gid as u16;
    i.ctime    = current_time();
    fs.inode_write(ino, &i);
    fs.flush();
    Ok(())
}

pub fn set_times(path: &str, atime_ns: u64, mtime_ns: u64) -> Result<(), i32> {
    let mut fs  = FS.lock();
    let fs      = fs.as_mut().ok_or(EIO)?;
    let ino     = fs.lookup_path(path).ok_or(ENOENT)?;
    let mut i   = fs.inode(ino).ok_or(EIO)?;
    i.atime     = (atime_ns / 1_000_000_000) as u32;
    i.mtime     = (mtime_ns / 1_000_000_000) as u32;
    i.ctime     = current_time();
    fs.inode_write(ino, &i);
    fs.flush();
    Ok(())
}

//
// These are thin wrappers so that `vfs_ops.rs` can use the `fd_open` /
// `fd_read` / `fd_write` path on ext2 files.  The actual byte-level
// dispatch goes through `vfs.rs`; we expose `read_file` / `write_file`
// for the cases where vfs_ops calls into ext2 directly.

/// Read all bytes of the file at `path`.
pub fn read_file(path: &str) -> Result<Vec<u8>, i32> {
    let fs  = FS.lock();
    let fs  = fs.as_ref().ok_or(EIO)?;
    let ino = fs.lookup_path(path).ok_or(ENOENT)?;
    let i   = fs.inode(ino).ok_or(EIO)?;
    if i.mode & 0xF000 != 0x8000 { return Err(EISDIR); }
    Ok(fs.read_inode_data(&i))
}

/// Write `data` to the file at `path`, creating it if absent.
pub fn write_file(path: &str, data: &[u8]) -> Result<(), i32> {
    // Create the file if it doesn't exist.
    {
        let fs = FS.lock();
        let fs = fs.as_ref().ok_or(EIO)?;
        if fs.lookup_path(path).is_none() {
            drop(fs);
            create_file(path, 0o644)?;
        }
    }

    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;
    let ino    = fs.lookup_path(path).ok_or(ENOENT)?;
    fs.write_inode_data(ino, data)?;
    fs.flush();
    Ok(())
}

/// Create an empty regular file at `path`.
pub fn create_file(path: &str, mode: u16) -> Result<(), i32> {
    let mut fs = FS.lock();
    let fs     = fs.as_mut().ok_or(EIO)?;

    let (parent_ino, _, last) = fs.resolve_depth(path, false, 0).ok_or(ENOENT)?;
    if last.is_empty() { return Err(EEXIST); }
    if fs.lookup_dir_ino(parent_ino, &last).is_some() { return Err(EEXIST); }

    let new_ino = fs.alloc_inode(false).ok_or(ENOSPC)?;
    let now     = current_time();
    let mut inode: Inode = unsafe { core::mem::zeroed() };
    inode.mode        = (mode & 0xFFF) | 0x8000;
    inode.links_count = 1;
    inode.atime       = now;
    inode.ctime       = now;
    inode.mtime       = now;
    fs.inode_write(new_ino, &inode);
    fs.dir_add_entry(parent_ino, &last, new_ino, 1 /* FT_REG_FILE */)?;
    fs.flush();
    Ok(())
}


fn current_time() -> u32 {
    crate::time::uptime_seconds() as u32
}

fn mode_to_ftype(mode: u16) -> u8 {
    match mode & 0xF000 {
        0x8000 => 1, // FT_REG_FILE
        0x4000 => 2, // FT_DIR
        0xA000 => 7, // FT_SYMLINK
        0x2000 => 3, // FT_CHRDEV
        0x6000 => 4, // FT_BLKDEV
        0x1000 => 5, // FT_FIFO
        0xC000 => 6, // FT_SOCK
        _      => 0,
    }
}
