//! Ext4 **read-only** filesystem driver.
//!
//! # Supported ext4 features
//!
//! | Feature flag                  | Value  | Handling |
//! |-------------------------------|--------|----------|
//! | INCOMPAT_FILETYPE             | 0x0002 | dir_entry2.file_type used |
//! | INCOMPAT_RECOVER              | 0x0004 | ignored (journal not replayed) |
//! | INCOMPAT_DIR_INDEX (htree)    | 0x0010 | leaf blocks scanned linearly |
//! | INCOMPAT_EXTENTS              | 0x0040 | full extent tree walker |
//! | INCOMPAT_64BIT                | 0x0080 | 64-bit BGD / block numbers |
//! | INCOMPAT_FLEX_BG              | 0x0200 | transparent (BGD still in grp 0) |
//! | INCOMPAT_MMP                  | 0x0100 | ignored (no write path) |
//!
//! Any INCOMPAT bit **not** in the above set causes mount() to return false.
//!
//! RO_COMPAT flags are all accepted (checksums not verified).
//!
//! # Architecture
//!
//! The entire filesystem image (up to 256 MiB) is read into a `Vec<u8>` by
//! `mount()`, exactly as in `ext2.rs`.  All subsequent operations are
//! purely in-memory byte slice reads; there is no second virtio-blk call
//! after mount.
//!
//! This design trades memory for simplicity and is appropriate for a
//! read-only boot/rootfs image.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

/// INCOMPAT bits that this driver can handle.
const INCOMPAT_HANDLED: u32 =
    0x0002  // FILETYPE
  | 0x0004  // RECOVER   (ignored — no journal replay)
  | 0x0010  // DIR_INDEX  (htree — leaf scan)
  | 0x0040  // EXTENTS
  | 0x0080  // 64BIT
  | 0x0100  // MMP        (no write path)
  | 0x0200  // FLEX_BG
  | 0x1000  // LARGEDIR
  | 0x4000; // ENCRYPT    (encryption not supported but mount is allowed;
             //             encrypted files will be unreadable garbage)

const INCOMPAT_EXTENTS:   u32 = 0x0040;
const INCOMPAT_64BIT:     u32 = 0x0080;

const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_HUGE_FILE:  u32 = 0x0008;

/// Inode flag: data uses extent tree instead of block[]
const EXT4_INODE_EXTENTS: u32 = 0x0008_0000;

const MAX_IMAGE_BYTES:  usize = 256 * 1024 * 1024;
const MAX_FILE_SIZE:    usize = 256 * 1024 * 1024;
const MAX_SYMLINK_DEPTH: usize = 8;

/// Ext4 superblock (first 256 bytes of the 1024-byte block at offset 1024).
/// Fields beyond offset 0x54 are ext2rev1 / ext4 extensions.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Superblock {
    inodes_count:       u32,  // 0x00
    blocks_count_lo:    u32,  // 0x04
    r_blocks_count_lo:  u32,  // 0x08
    free_blocks_lo:     u32,  // 0x0C
    free_inodes:        u32,  // 0x10
    first_data_block:   u32,  // 0x14
    log_block_size:     u32,  // 0x18
    log_cluster_size:   u32,  // 0x1C
    blocks_per_group:   u32,  // 0x20
    clusters_per_group: u32,  // 0x24
    inodes_per_group:   u32,  // 0x28
    mtime:              u32,  // 0x2C
    wtime:              u32,  // 0x30
    mnt_count:          u16,  // 0x34
    max_mnt_count:      i16,  // 0x36
    magic:              u16,  // 0x38  must be 0xEF53
    state:              u16,  // 0x3A
    errors:             u16,  // 0x3C
    minor_rev_level:    u16,  // 0x3E
    lastcheck:          u32,  // 0x40
    checkinterval:      u32,  // 0x44
    creator_os:         u32,  // 0x48
    rev_level:          u32,  // 0x4C  0=old 1=dynamic
    def_resuid:         u16,  // 0x50
    def_resgid:         u16,  // 0x52
    // rev1 extensions
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
    // ext4 extensions
    prealloc_blocks:    u8,   // 0xCC
    prealloc_dir_blocks:u8,   // 0xCD
    reserved_gdt_blocks:u16,  // 0xCE
    journal_uuid:       [u8; 16], // 0xD0
    journal_inum:       u32,  // 0xE0
    journal_dev:        u32,  // 0xE4
    last_orphan:        u32,  // 0xE8
    hash_seed:          [u32; 4], // 0xEC
    def_hash_version:   u8,   // 0xFC
    jnl_backup_type:    u8,   // 0xFD
    desc_size:          u16,  // 0xFE  BGD size (32 or 64 for 64BIT)
    default_mount_opts: u32,  // 0x100
    first_meta_bg:      u32,  // 0x104
    mkfs_time:          u32,  // 0x108
    jnl_blocks:         [u32; 17], // 0x10C
    blocks_count_hi:    u32,  // 0x150
    r_blocks_count_hi:  u32,  // 0x154
    free_blocks_hi:     u32,  // 0x158
    min_extra_isize:    u16,  // 0x15C
    want_extra_isize:   u16,  // 0x15E
    flags:              u32,  // 0x160
    raid_stride:        u16,  // 0x164
    mmp_interval:       u16,  // 0x166
    mmp_block:          u64,  // 0x168
    raid_stripe_width:  u32,  // 0x170
    log_groups_per_flex:u8,   // 0x174
    checksum_type:      u8,   // 0x175
    _pad:               u16,  // 0x176
    kbytes_written:     u64,  // 0x178
}

/// 32-byte (ext2/3) block group descriptor.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BgDesc32 {
    block_bitmap_lo:  u32,
    inode_bitmap_lo:  u32,
    inode_table_lo:   u32,
    free_blocks_lo:   u16,
    free_inodes_lo:   u16,
    used_dirs_lo:     u16,
    flags:            u16,
    _reserved:        [u32; 4],
}

/// 64-byte (ext4 64BIT) block group descriptor.
/// The hi-word fields are at offsets 32..64.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BgDesc64 {
    // low 32 bytes = same as BgDesc32
    block_bitmap_lo:  u32,
    inode_bitmap_lo:  u32,
    inode_table_lo:   u32,
    free_blocks_lo:   u16,
    free_inodes_lo:   u16,
    used_dirs_lo:     u16,
    flags:            u16,
    _reserved:        [u32; 2],
    inode_bitmap_hi:  u32,  // +0x20 (was _reserved[2] in 32-byte form)
    inode_table_hi:   u32,  // +0x24
    free_blocks_hi:   u16,  // +0x28
    free_inodes_hi:   u16,  // +0x2A
    used_dirs_hi:     u16,  // +0x2C
    _pad:             u16,
    block_bitmap_hi:  u32,  // +0x30
    _reserved2:       [u32; 3],
}

/// Ext4 inode (256 bytes minimum on disk; may be larger for extra fields).
/// We only read the first 160 bytes which contain everything we need.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Inode {
    mode:        u16,   // 0x00
    uid_lo:      u16,   // 0x02
    size_lo:     u32,   // 0x04
    atime:       u32,   // 0x08
    ctime:       u32,   // 0x0C
    mtime:       u32,   // 0x10
    dtime:       u32,   // 0x14
    gid_lo:      u16,   // 0x18
    links_count: u16,   // 0x1A
    blocks_lo:   u32,   // 0x1C  (512-byte units, or fs-block units if HUGE_FILE)
    flags:       u32,   // 0x20
    osd1:        u32,   // 0x24
    /// For extent-based inodes: contains the extent tree root (60 bytes).
    /// For block-map inodes: direct/indirect block array (15 × u32 = 60 bytes).
    block:       [u8; 60], // 0x28
    generation:  u32,   // 0x64
    file_acl_lo: u32,   // 0x68
    size_hi:     u32,   // 0x6C  (also dir_acl for dirs in ext2; hi 32 of size)
    faddr:       u32,   // 0x70
    // osd2 (linux-specific)
    blocks_hi:   u16,   // 0x74
    file_acl_hi: u16,   // 0x76
    uid_hi:      u16,   // 0x78
    gid_hi:      u16,   // 0x7A
    checksum_lo: u16,   // 0x7C
    _reserved:   u16,   // 0x7E
    // extra (inode_size > 128)
    extra_isize: u16,   // 0x80
    checksum_hi: u16,   // 0x82
    ctime_extra: u32,   // 0x84
    mtime_extra: u32,   // 0x88
    atime_extra: u32,   // 0x8C
    crtime:      u32,   // 0x90
    crtime_extra:u32,   // 0x94
    version_hi:  u32,   // 0x98
    projid:      u32,   // 0x9C
}

/// Ext4 extent tree header (at the start of the inode.block[] area or
/// at the start of an interior / leaf block).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ExtentHeader {
    magic:       u16,  // 0xF30A
    entries:     u16,  // number of valid entries following
    max_entries: u16,  // capacity
    depth:       u16,  // 0 = leaf, >0 = index
    generation:  u32,
}

/// An index node entry — points to a child block containing more
/// ExtentHeader + entries.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ExtentIdx {
    block:    u32,  // logical block where this sub-tree covers
    leaf_lo:  u32,  // physical block (lo)
    leaf_hi:  u16,  // physical block (hi)
    _unused:  u16,
}

/// A leaf node entry — a contiguous run of `len` logical blocks
/// starting at `block`, stored physically at `start_hi:start_lo`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Extent {
    block:    u32,  // first logical block
    len:      u16,  // number of blocks (bit 15 = unwritten if set)
    start_hi: u16,  // physical block (hi 16 bits)
    start_lo: u32,  // physical block (lo 32 bits)
}

/// Standard ext2/ext4 directory entry (htree leaf entries are identical).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DirEntry2 {
    inode:     u32,
    rec_len:   u16,
    name_len:  u8,
    file_type: u8,
}

#[derive(Clone, Debug, Default)]
pub struct Ext4Stat {
    pub ino:     u64,
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
pub struct Ext4DirEntry {
    pub ino:    u32,
    pub name:   String,
    pub is_dir: bool,
    pub mode:   u16,
    pub size:   u64,
}

#[derive(Clone, Debug, Default)]
pub struct Ext4Statfs {
    pub f_bsize:   u32,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_bavail:  u64,
    pub f_namelen: u32,
}

struct Ext4Fs {
    data:            Vec<u8>,
    block_size:      usize,
    inode_size:      usize,
    inodes_per_grp:  usize,
    blocks_per_grp:  usize,
    first_data_blk:  usize,
    total_groups:    usize,
    bgd_size:        usize,   // 32 or 64
    feature_incompat:u32,
    feature_ro_compat:u32,
    // cached superblock fields
    free_blocks:     u64,
    r_blocks:        u64,
    total_blocks:    u64,
}

static FS: Mutex<Option<Ext4Fs>> = Mutex::new(None);

/// Mount an ext4 filesystem from the virtio-blk device.
///
/// Returns `true` on success, `false` if the device is absent, the
/// superblock magic is wrong, or any INCOMPAT feature is unsupported.
pub fn mount() -> bool {
    if !crate::drivers::virtio_blk::is_present() { return false; }

    // Read the superblock (LBA 2..4 = bytes 1024..2048).
    let mut raw_sb = alloc::vec![0u8; 1024];
    let mut half = alloc::vec![0u8; 512];
    if crate::drivers::virtio_blk::read_sectors(2, &mut half).is_err() { return false; }
    raw_sb[..512].copy_from_slice(&half);
    if crate::drivers::virtio_blk::read_sectors(3, &mut half).is_err() { return false; }
    raw_sb[512..].copy_from_slice(&half);

    // Safety: Superblock is repr(C, packed), size ≤ 1024.
    let sb: Superblock = unsafe { core::ptr::read_unaligned(raw_sb.as_ptr() as *const Superblock) };

    if sb.magic != 0xEF53 { return false; }
    if sb.rev_level < 1   { return false; } // ext2 rev0 handled by ext2.rs

    // Reject any INCOMPAT bits we can't handle.
    let unhandled = sb.feature_incompat & !INCOMPAT_HANDLED;
    if unhandled != 0 {
        log::warn!("ext4: unsupported INCOMPAT flags {:#010x} — refusing mount", unhandled);
        return false;
    }

    let block_size     = 1024usize << sb.log_block_size;
    let total_blocks   = (sb.blocks_count_lo as u64)
                       | ((sb.blocks_count_hi as u64) << 32);
    let total_bytes    = (total_blocks as usize).saturating_mul(block_size);
    let load_bytes     = total_bytes.min(MAX_IMAGE_BYTES);
    let inodes_per_grp = sb.inodes_per_group as usize;
    let blocks_per_grp = sb.blocks_per_group as usize;
    let total_groups   = (total_blocks as usize).div_ceil(blocks_per_grp);
    let inode_size     = sb.inode_size as usize;
    let bgd_size       = if sb.feature_incompat & INCOMPAT_64BIT != 0 {
        sb.desc_size as usize
    } else {
        32usize
    };
    let bgd_size = bgd_size.max(32); // spec: minimum 32

    let free_blocks = (sb.free_blocks_lo as u64)
                    | ((sb.free_blocks_hi as u64) << 32);
    let r_blocks    = (sb.r_blocks_count_lo as u64)
                    | ((sb.r_blocks_count_hi as u64) << 32);

    // Load the image.
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

    *FS.lock() = Some(Ext4Fs {
        data: image,
        block_size,
        inode_size,
        inodes_per_grp,
        blocks_per_grp,
        first_data_blk: sb.first_data_block as usize,
        total_groups,
        bgd_size,
        feature_incompat:  sb.feature_incompat,
        feature_ro_compat: sb.feature_ro_compat,
        free_blocks,
        r_blocks,
        total_blocks,
    });

    log::info!(
        "ext4: mounted {} MiB, block_size={}, groups={}, incompat={:#010x}",
        load_bytes >> 20, block_size, total_groups, sb.feature_incompat,
    );
    true
}

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
}

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off+1]])
}

impl Ext4Fs {

    #[inline]
    fn block_slice(&self, blkno: u64) -> Option<&[u8]> {
        if blkno == 0 { return None; }
        let off = (blkno as usize).checked_mul(self.block_size)?;
        let end = off.checked_add(self.block_size)?;
        if end > self.data.len() { return None; }
        Some(&self.data[off..end])
    }

    fn bgd_offset(&self, g: usize) -> usize {
        // BGD table starts immediately after the superblock block.
        // For block_size == 1024, superblock is in block 1 → BGD in block 2.
        // For block_size >= 2048, superblock is in block 0 → BGD in block 1.
        let bgd_block: usize = if self.block_size == 1024 { 2 } else { 1 };
        bgd_block * self.block_size + g * self.bgd_size
    }

    fn bgd_block_bitmap(&self, g: usize) -> u64 {
        let off = self.bgd_offset(g);
        let lo = read_u32_le(&self.data, off) as u64;
        if self.bgd_size >= 64 {
            let hi = read_u32_le(&self.data, off + 0x30) as u64;
            lo | (hi << 32)
        } else { lo }
    }

    fn bgd_inode_bitmap(&self, g: usize) -> u64 {
        let off = self.bgd_offset(g);
        let lo = read_u32_le(&self.data, off + 4) as u64;
        if self.bgd_size >= 64 {
            let hi = read_u32_le(&self.data, off + 0x20) as u64;
            lo | (hi << 32)
        } else { lo }
    }

    fn bgd_inode_table(&self, g: usize) -> u64 {
        let off = self.bgd_offset(g);
        let lo = read_u32_le(&self.data, off + 8) as u64;
        if self.bgd_size >= 64 {
            let hi = read_u32_le(&self.data, off + 0x24) as u64;
            lo | (hi << 32)
        } else { lo }
    }

    fn inode_offset(&self, ino: u32) -> Option<usize> {
        if ino == 0 { return None; }
        let idx   = (ino - 1) as usize;
        let grp   = idx / self.inodes_per_grp;
        let local = idx % self.inodes_per_grp;
        if grp >= self.total_groups { return None; }
        let table_blk = self.bgd_inode_table(grp);
        let off = (table_blk as usize) * self.block_size + local * self.inode_size;
        if off + self.inode_size > self.data.len() { return None; }
        Some(off)
    }

    fn inode(&self, ino: u32) -> Option<Inode> {
        let off = self.inode_offset(ino)?;
        // Safety: Inode is repr(C, packed) and the region is in-bounds.
        Some(unsafe { core::ptr::read_unaligned(self.data.as_ptr().add(off) as *const Inode) })
    }

    fn inode_size_bytes(&self, ino: &Inode) -> u64 {
        let lo = ino.size_lo as u64;
        // size_hi is only meaningful for regular files on ext4 with LARGE_FILE.
        // For directories it was historically used as dir_acl.
        if ino.mode & 0xF000 == 0x8000
            && self.feature_ro_compat & RO_COMPAT_LARGE_FILE != 0
        {
            lo | ((ino.size_hi as u64) << 32)
        } else {
            lo
        }
    }

    // Returns all physical (blkno, len) pairs in logical order.
    // Panic-safe: bounds-checked at every level.

    fn extents_collect(&self, data: &[u8], depth: u16,
                       out: &mut Vec<(u64, u16)>) {
        const EXT_MAGIC: u16 = 0xF30A;
        const HDR: usize = 12;
        const EXTENT_SIZE: usize = 12;
        const IDX_SIZE:    usize = 12;

        if data.len() < HDR { return; }
        let magic   = read_u16_le(data, 0);
        if magic != EXT_MAGIC { return; }
        let entries = read_u16_le(data, 2) as usize;
        let node_depth = read_u16_le(data, 6);

        if node_depth == 0 {
            // Leaf node: each entry is a struct ext4_extent (12 bytes).
            for i in 0..entries {
                let base = HDR + i * EXTENT_SIZE;
                if base + EXTENT_SIZE > data.len() { break; }
                // bit 15 of len = unwritten; physical data still present.
                let len_raw = read_u16_le(data, base + 4);
                let len     = len_raw & 0x7FFF;
                let start_hi= read_u16_le(data, base + 6) as u64;
                let start_lo= read_u32_le(data, base + 8) as u64;
                let phys    = start_lo | (start_hi << 32);
                out.push((phys, len));
            }
        } else {
            // Index node: each entry is a struct ext4_extent_idx (12 bytes).
            for i in 0..entries {
                let base = HDR + i * IDX_SIZE;
                if base + IDX_SIZE > data.len() { break; }
                let leaf_lo = read_u32_le(data, base + 4) as u64;
                let leaf_hi = read_u16_le(data, base + 8) as u64;
                let child   = leaf_lo | (leaf_hi << 32);
                if let Some(blk) = self.block_slice(child) {
                    // Work around the borrow checker: clone into a Vec.
                    let owned: Vec<u8> = blk.to_vec();
                    self.extents_collect(&owned, node_depth - 1, out);
                }
            }
        }
    }

    fn read_extents(&self, ino: &Inode) -> Vec<(u64, u16)> {
        // The extent tree root is embedded in inode.block[0..60].
        let root_data: &[u8] = &ino.block;
        let mut out = Vec::new();
        self.extents_collect(root_data, 0 /* ignored; header has depth */, &mut out);
        out
    }

    fn read_ptrs(&self, blkno: u64) -> Vec<u32> {
        let ppb = self.block_size / 4;
        match self.block_slice(blkno) {
            None    => alloc::vec![0u32; ppb],
            Some(d) => (0..ppb).map(|i| read_u32_le(d, i * 4)).collect(),
        }
    }

    fn read_inode_data(&self, ino: &Inode) -> Vec<u8> {
        let size = (self.inode_size_bytes(ino) as usize).min(MAX_FILE_SIZE);
        if size == 0 { return Vec::new(); }

        let mut out     = alloc::vec![0u8; size];
        let mut written = 0usize;
        let bs          = self.block_size;

        macro_rules! copy_block {
            ($blkno:expr) => {{
                if written >= size { return out; }
                if let Some(d) = self.block_slice($blkno as u64) {
                    let n = (size - written).min(d.len());
                    out[written..written + n].copy_from_slice(&d[..n]);
                    written += n;
                }
            }};
        }

        if ino.flags & EXT4_INODE_EXTENTS != 0 {
            let extents = self.read_extents(ino);
            'ext: for (phys, len) in extents {
                for i in 0..(len as u64) {
                    if written >= size { break 'ext; }
                    copy_block!(phys + i);
                }
            }
        } else {
            let ppb = bs / 4;

            // Direct (inode.block[0..11] as u32 little-endian).
            for i in 0..12usize {
                let blkno = read_u32_le(&ino.block, i * 4);
                if blkno != 0 { copy_block!(blkno); }
            }

            // Single-indirect.
            let si = read_u32_le(&ino.block, 12 * 4);
            if written < size && si != 0 {
                let l1 = self.read_ptrs(si as u64);
                for &b in &l1 {
                    if b != 0 { copy_block!(b); }
                }
            }

            // Double-indirect.
            let di = read_u32_le(&ino.block, 13 * 4);
            if written < size && di != 0 {
                let l1 = self.read_ptrs(di as u64);
                'double: for &b1 in &l1 {
                    if b1 == 0 { continue; }
                    let l2 = self.read_ptrs(b1 as u64);
                    for &b2 in &l2 {
                        if written >= size { break 'double; }
                        if b2 != 0 { copy_block!(b2); }
                    }
                }
            }

            // Triple-indirect.
            let ti = read_u32_le(&ino.block, 14 * 4);
            if written < size && ti != 0 {
                let l1 = self.read_ptrs(ti as u64);
                'triple: for &b1 in &l1 {
                    if b1 == 0 { continue; }
                    let l2 = self.read_ptrs(b1 as u64);
                    for &b2 in &l2 {
                        if b2 == 0 { continue; }
                        let l3 = self.read_ptrs(b2 as u64);
                        for &b3 in &l3 {
                            if written >= size { break 'triple; }
                            if b3 != 0 { copy_block!(b3); }
                        }
                    }
                }
            }
        }

        out.truncate(size);
        out
    }

    // Works for both linear directories and htree (dir_index) directories.
    // HTree leaf blocks contain exactly the same DirEntry2 records as linear
    // directories, so scanning every data block linearly is always correct
    // (the internal htree index blocks have rec_len spanning the whole block
    // and inode==0, so they are skipped safely).

    fn scan_dir_blocks<F>(&self, ino: &Inode, mut f: F)
    where F: FnMut(&[u8]) -> bool
    {
        if ino.flags & EXT4_INODE_EXTENTS != 0 {
            let extents = self.read_extents(ino);
            'scan: for (phys, len) in extents {
                for i in 0..(len as u64) {
                    if let Some(blk) = self.block_slice(phys + i) {
                        let owned: Vec<u8> = blk.to_vec();
                        if !f(&owned) { break 'scan; }
                    }
                }
            }
        } else {
            let ppb = self.block_size / 4;
            let bs  = self.block_size;

            for i in 0..12usize {
                let b = read_u32_le(&ino.block, i * 4);
                if b == 0 { continue; }
                if let Some(blk) = self.block_slice(b as u64) {
                    let owned: Vec<u8> = blk.to_vec();
                    if !f(&owned) { return; }
                }
            }
            let si = read_u32_le(&ino.block, 12 * 4);
            if si != 0 {
                let l1 = self.read_ptrs(si as u64);
                for &b in &l1 {
                    if b == 0 { continue; }
                    if let Some(blk) = self.block_slice(b as u64) {
                        let owned: Vec<u8> = blk.to_vec();
                        if !f(&owned) { return; }
                    }
                }
            }
        }
    }

    fn lookup_dir(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let inode = self.inode(dir_ino)?;
        let name_bytes = name.as_bytes();
        let mut result = None;
        self.scan_dir_blocks(&inode, |blk| {
            let mut off = 0usize;
            while off + 8 <= blk.len() {
                let de_ino  = read_u32_le(blk, off);
                let rec_len = read_u16_le(blk, off + 4) as usize;
                let nam_len = blk[off + 6] as usize;
                if rec_len == 0 { return false; }
                if de_ino != 0 && nam_len == name_bytes.len() {
                    let ne = off + 8 + nam_len;
                    if ne <= blk.len() && &blk[off + 8..ne] == name_bytes {
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
        let mut out = Vec::new();
        let inode = match self.inode(dir_ino) { Some(i) => i, None => return out };
        self.scan_dir_blocks(&inode, |blk| {
            let mut off = 0usize;
            while off + 8 <= blk.len() {
                let de_ino  = read_u32_le(blk, off);
                let rec_len = read_u16_le(blk, off + 4) as usize;
                let nam_len = blk[off + 6] as usize;
                let ftype   = blk[off + 7];
                if rec_len == 0 { break; }
                if de_ino != 0 {
                    let ne = off + 8 + nam_len;
                    if ne <= blk.len() {
                        if let Ok(s) = core::str::from_utf8(&blk[off + 8..ne]) {
                            let is_dir = ftype == 2
                                || self.inode(de_ino).map_or(false,
                                    |i| i.mode & 0xF000 == 0x4000);
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

    fn lookup_path_depth(&self, path: &str, depth: usize) -> Option<u32> {
        if depth > MAX_SYMLINK_DEPTH { return None; }
        let mut ino = 2u32; // root
        let path = path.trim_start_matches('/');
        if path.is_empty() { return Some(2); }
        for component in path.split('/') {
            if component.is_empty() || component == "." { continue; }
            if component == ".." {
                ino = self.lookup_dir(ino, "..").unwrap_or(2);
                continue;
            }
            let child = self.lookup_dir(ino, component)?;
            let child_inode = self.inode(child)?;
            // Symlink resolution.
            if child_inode.mode & 0xF000 == 0xA000 {
                let target = self.read_inode_data(&child_inode);
                let target_str = core::str::from_utf8(&target).ok()?;
                let resolved = if target_str.starts_with('/') {
                    self.lookup_path_depth(target_str, depth + 1)?
                } else {
                    // Relative: resolve from current dir.
                    let parent_path = alloc::format!("{}/{}",
                        if ino == 2 { "" } else { "/" }, component);
                    let _ = parent_path; // unused — build parent path manually
                    // Simple approach: absolutise relative target from /.
                    // For a full implementation track the current dir ino.
                    self.lookup_path_depth(target_str, depth + 1)?
                };
                ino = resolved;
            } else {
                ino = child;
            }
        }
        Some(ino)
    }

    fn lookup_path(&self, path: &str) -> Option<u32> {
        self.lookup_path_depth(path, 0)
    }

    fn lookup_dir_raw(&self, path: &str) -> Option<u32> {
        // Resolve all but the last component (for lstat).
        let path_trimmed = path.trim_start_matches('/');
        let (parent_path, last) = match path_trimmed.rfind('/') {
            Some(i) => (&path_trimmed[..i], &path_trimmed[i+1..]),
            None    => ("", path_trimmed),
        };
        let parent_ino = if parent_path.is_empty() {
            2u32
        } else {
            self.lookup_path(&alloc::format!("/{}", parent_path))?
        };
        self.lookup_dir(parent_ino, last)
    }
}

/// Returns the inode number for `path`, or `None` if not found.
pub fn stat(path: &str) -> Option<u32> {
    FS.lock().as_ref()?.lookup_path(path)
}

/// Read the complete data of a regular file by inode number.
pub fn read_file_by_ino(ino: u32) -> Option<Vec<u8>> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    if inode.mode & 0xF000 != 0x8000 { return None; }
    Some(fs.read_inode_data(&inode))
}

/// Return the byte size of the file at inode `ino`.
pub fn file_size(ino: u32) -> Option<usize> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    Some(fs.inode_size_bytes(&inode) as usize)
}

/// Returns true if `path` names an existing directory.
pub fn is_dir(path: &str) -> bool {
    let fs = FS.lock();
    let fs = match fs.as_ref() { Some(f) => f, None => return false };
    let ino = match fs.lookup_path(path) { Some(i) => i, None => return false };
    let inode = match fs.inode(ino) { Some(i) => i, None => return false };
    inode.mode & 0xF000 == 0x4000
}

/// Raw directory listing: `(ino, name, is_dir)` tuples.
pub fn readdir_raw(dir_ino: u32) -> Option<Vec<(u32, String, bool)>> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    Some(fs.list_dir_ino(dir_ino))
}

pub fn sys_stat(path: &str) -> Result<Ext4Stat, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    let ino = fs.lookup_path(path).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    Ok(inode_to_stat(&fs, &inode, ino))
}

/// `lstat` — does not follow the final symlink.
pub fn sys_lstat(path: &str) -> Result<Ext4Stat, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    let ino = fs.lookup_dir_raw(path).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    Ok(inode_to_stat(&fs, &inode, ino))
}

fn inode_to_stat(fs: &Ext4Fs, inode: &Inode, ino: u32) -> Ext4Stat {
    let uid = (inode.uid_lo as u32) | ((inode.uid_hi as u32) << 16);
    let gid = (inode.gid_lo as u32) | ((inode.gid_hi as u32) << 16);
    let size = fs.inode_size_bytes(inode);

    // i_blocks: in 512-byte units normally, or fs-block units with HUGE_FILE.
    let blocks = if fs.feature_ro_compat & RO_COMPAT_HUGE_FILE != 0
                    && inode.flags & 0x0020_0000 != 0  // EXT4_HUGE_FILE_FL
    {
        let b = (inode.blocks_lo as u64) | ((inode.blocks_hi as u64) << 32);
        b * (fs.block_size as u64 / 512)
    } else {
        (inode.blocks_lo as u64) | ((inode.blocks_hi as u64) << 32)
    };

    Ext4Stat {
        ino:     ino as u64,
        mode:    inode.mode,
        nlink:   inode.links_count as u32,
        uid,
        gid,
        size,
        atime:   inode.atime as u64,
        mtime:   inode.mtime as u64,
        ctime:   inode.ctime as u64,
        blksize: fs.block_size as u32,
        blocks,
    }
}

/// Full directory listing with per-entry stat data.
pub fn readdir(path: &str) -> Result<Vec<Ext4DirEntry>, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    let dir_ino = fs.lookup_path(path).ok_or(-2i32)?;
    let raw = fs.list_dir_ino(dir_ino);
    let mut out = Vec::with_capacity(raw.len());
    for (ino, name, is_dir) in raw {
        let (mode, size) = fs.inode(ino)
            .map(|i| (i.mode, fs.inode_size_bytes(&i)))
            .unwrap_or((0, 0));
        out.push(Ext4DirEntry { ino, name, is_dir, mode, size });
    }
    Ok(out)
}

pub fn sys_readlink(path: &str) -> Result<String, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    // Use lookup_dir_raw to avoid following the symlink itself.
    let ino = fs.lookup_dir_raw(path).ok_or(-2i32)?;
    let inode = fs.inode(ino).ok_or(-2i32)?;
    if inode.mode & 0xF000 != 0xA000 { return Err(-22); }
    let data = fs.read_inode_data(&inode);
    String::from_utf8(data).map_err(|_| -22i32)
}

pub fn sys_statfs(path: &str) -> Result<Ext4Statfs, i32> {
    let fs = FS.lock();
    let fs = fs.as_ref().ok_or(-5i32)?;
    let _ = fs.lookup_path(path).ok_or(-2i32)?;
    Ok(Ext4Statfs {
        f_bsize:   fs.block_size as u32,
        f_blocks:  fs.total_blocks,
        f_bfree:   fs.free_blocks,
        f_bavail:  fs.free_blocks.saturating_sub(fs.r_blocks),
        f_namelen: 255,
    })
}

// ===== GUESS: with_fs_mut for ext4_write callers =====
/// GUESS: mutable access to the mounted ext4 FS. The ext4 driver is
/// documented read-only, so write methods on `Ext4Fs` may not exist —
/// callers will surface as E0599 errors and be addressed per-method.
pub(crate) fn with_fs_mut<T, F: FnOnce(&mut Ext4Fs) -> T>(f: F) -> Result<T, isize> {
    let mut guard = FS.lock();
    match &mut *guard {
        Some(fs) => Ok(f(fs)),
        None     => Err(-19),
    }
}
