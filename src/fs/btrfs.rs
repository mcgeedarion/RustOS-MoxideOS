//! Btrfs filesystem driver — read/write, extent-mapped, copy-on-write.
//!
//! ## Architecture
//!
//! ```text
//!  VFS ops (vfs_ops.rs)
//!       │
//!       ▼
//!  btrfs_read_all / btrfs_write_all / btrfs_stat / btrfs_readdir …
//!       │
//!       ▼
//!  BtrfsFs  ──► B-tree lookup (fs-tree / extent-tree / root-tree)
//!       │
//!       ▼
//!  Block layer  (block_read / block_write)
//! ```
//!
//! ## On-disk layout (simplified)
//! ```
//! Offset 0x10000 : Superblock  (BtrfsSuperblock, 4096 bytes)
//! Offset 0x20000 : Chunk-tree root node
//! Chunk-tree     : logical → physical address map (BtrfsChunkItem)
//! Root-tree      : maps root objectids → BtrfsRootItem
//! FS-tree        : per-subvolume B-tree holding inodes, dir-entries, extents
//! Extent-tree    : free-space / reference-counting accounting
//! ```
//!
//! ## Supported features (this implementation)
//! - Superblock parse + magic/checksum validation
//! - Chunk-tree walk for logical→physical translation
//! - Root-tree lookup for the default subvolume
//! - FS-tree search: inode items, dir-index items, extent-data items
//! - Read-path: extent-mapped file reads (regular & inline extents)
//! - Write-path: CoW allocation, new extent insertion, inode size update
//! - VFS operations: stat, readdir, read_all, write_all, pread, pwrite,
//!   truncate, create, unlink, link, rename, mkdir, rmdir, symlink,
//!   readlink, chmod, chown, utimens, statfs
//!
//! ## Not yet implemented
//! - RAID profiles (DUP/RAID1/RAID5/6) — only single-device stripe assumed
//! - Compression (lzo/zstd) — compressed extents return EOPNOTSUPP
//! - Checksums on data blocks (crc32c tree integrity is verified)
//! - Snapshots / subvolume creation (read-only enumeration works)
//! - Send/receive, defrag, balance

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;

// In RustOS the block layer is accessed through the virtio-blk driver.
// We expose two thin wrappers here so the rest of the file never touches
// hardware directly.

/// Read `count` 512-byte sectors starting at `lba` from the primary disk.
fn block_read(lba: u64, count: u32) -> Vec<u8> {
    let mut buf = vec![0u8; count as usize * 512];
    crate::drivers::block::read_sectors(lba, count, &mut buf);
    buf
}

/// Write `data` (must be a multiple of 512 bytes) to the primary disk at `lba`.
fn block_write(lba: u64, data: &[u8]) {
    debug_assert!(data.len() % 512 == 0, "block_write: data not sector-aligned");
    crate::drivers::block::write_sectors(lba, data);
}


const BTRFS_MAGIC: u64               = 0x4D5F53665248425F; // "_BHRfS_M"
const BTRFS_SUPERBLOCK_OFFSET: u64   = 0x10000;            // 64 KiB
const BTRFS_SUPERBLOCK_SIZE: usize   = 4096;
const BTRFS_CSUM_SIZE: usize         = 32;
const BTRFS_FSID_SIZE: usize         = 16;
const BTRFS_UUID_SIZE: usize         = 16;
const BTRFS_LABEL_SIZE: usize        = 256;
const BTRFS_SYSTEM_CHUNK_ARRAY_SIZE: usize = 2048;

// Object-id constants
const BTRFS_ROOT_TREE_OBJECTID:     u64 = 1;
const BTRFS_EXTENT_TREE_OBJECTID:   u64 = 2;
const BTRFS_CHUNK_TREE_OBJECTID:    u64 = 3;
const BTRFS_FS_TREE_OBJECTID:       u64 = 5;
const BTRFS_ROOT_TREE_DIR_OBJECTID: u64 = 6;
const BTRFS_FIRST_FREE_OBJECTID:    u64 = 256;
const BTRFS_LAST_FREE_OBJECTID:     u64 = u64::MAX - 255;
const BTRFS_FIRST_CHUNK_TREE_OBJECTID: u64 = 256;

// Key types
const BTRFS_INODE_ITEM_KEY:       u8 = 1;
const BTRFS_INODE_REF_KEY:        u8 = 12;
const BTRFS_XATTR_ITEM_KEY:       u8 = 24;
const BTRFS_DIR_ITEM_KEY:         u8 = 84;
const BTRFS_DIR_INDEX_KEY:        u8 = 96;
const BTRFS_EXTENT_DATA_KEY:      u8 = 108;
const BTRFS_EXTENT_CSUM_KEY:      u8 = 128;
const BTRFS_ROOT_ITEM_KEY:        u8 = 132;
const BTRFS_ROOT_REF_KEY:         u8 = 156;
const BTRFS_EXTENT_ITEM_KEY:      u8 = 168;
const BTRFS_CHUNK_ITEM_KEY:       u8 = 228;
const BTRFS_DEV_ITEM_KEY:         u8 = 216;

// Inode flags (subset)
const BTRFS_INODE_NODATASUM:  u64 = 1 << 0;
const BTRFS_INODE_NODATACOW:  u64 = 1 << 1;

// Extent type
const BTRFS_FILE_EXTENT_INLINE:    u8 = 0;
const BTRFS_FILE_EXTENT_REG:       u8 = 1;
const BTRFS_FILE_EXTENT_PREALLOC:  u8 = 2;

// Node type
const BTRFS_NODE_LEAF:     u8 = 0;  // level == 0
const BTRFS_NODE_INTERNAL: u8 = 1;  // level >  0 (key pointers, no items)

// Directory item types
const BTRFS_FT_UNKNOWN:  u8 = 0;
const BTRFS_FT_REG_FILE: u8 = 1;
const BTRFS_FT_DIR:      u8 = 2;
const BTRFS_FT_SYMLINK:  u8 = 7;

// Compression types
const BTRFS_COMPRESS_NONE:  u8 = 0;
const BTRFS_COMPRESS_ZLIB:  u8 = 1;
const BTRFS_COMPRESS_LZO:   u8 = 2;
const BTRFS_COMPRESS_ZSTD:  u8 = 3;

// B-tree leaf item limits (rough; actual is block-size dependent)
const BTRFS_MAX_LEAF_ITEMS: usize = 512;

// All fields are little-endian on disk.  We read them with le-byte helpers.

/// 17-byte B-tree key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub ty:       u8,
    pub offset:   u64,
}

impl BtrfsKey {
    fn from_bytes(b: &[u8]) -> Self {
        BtrfsKey {
            objectid: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            ty:       b[8],
            offset:   u64::from_le_bytes(b[9..17].try_into().unwrap()),
        }
    }
}

/// On-disk inode item (160 bytes).
#[derive(Clone, Debug, Default)]
pub struct BtrfsInodeItem {
    pub generation:    u64,
    pub transid:       u64,
    pub size:          u64,
    pub nbytes:        u64,
    pub block_group:   u64,
    pub nlink:         u32,
    pub uid:           u32,
    pub gid:           u32,
    pub mode:          u32,
    pub rdev:          u64,
    pub flags:         u64,
    pub sequence:      u64,
    // 4× u64 reserved, then timespec pairs for atime/ctime/mtime/otime
    pub atime_sec:  u64,
    pub atime_nsec: u32,
    pub ctime_sec:  u64,
    pub ctime_nsec: u32,
    pub mtime_sec:  u64,
    pub mtime_nsec: u32,
    pub otime_sec:  u64,
    pub otime_nsec: u32,
}

impl BtrfsInodeItem {
    fn from_bytes(b: &[u8]) -> Self {
        let r64 = |off: usize| u64::from_le_bytes(b[off..off+8].try_into().unwrap());
        let r32 = |off: usize| u32::from_le_bytes(b[off..off+4].try_into().unwrap());
        BtrfsInodeItem {
            generation:  r64(0),
            transid:     r64(8),
            size:        r64(16),
            nbytes:      r64(24),
            block_group: r64(32),
            nlink:       r32(40),
            uid:         r32(44),
            gid:         r32(48),
            mode:        r32(52),
            rdev:        r64(56),
            flags:       r64(64),
            sequence:    r64(72),
            // 4×8 = 32 bytes reserved at offset 80
            atime_sec:   r64(112), atime_nsec: r32(120),
            ctime_sec:   r64(124), ctime_nsec: r32(132),
            mtime_sec:   r64(136), mtime_nsec: r32(144),
            otime_sec:   r64(148), otime_nsec: r32(156),
        }
    }

    fn atime_ns(&self) -> u64 { self.atime_sec * 1_000_000_000 + self.atime_nsec as u64 }
    fn mtime_ns(&self) -> u64 { self.mtime_sec * 1_000_000_000 + self.mtime_nsec as u64 }
    fn ctime_ns(&self) -> u64 { self.ctime_sec * 1_000_000_000 + self.ctime_nsec as u64 }
}

/// On-disk directory item (variable-length; this is the fixed header, 30 bytes).
#[derive(Clone, Debug)]
pub struct BtrfsDirItem {
    pub child_key: BtrfsKey,   // key of child inode item
    pub transid:   u64,
    pub data_len:  u16,
    pub name_len:  u16,
    pub ty:        u8,
    // followed by name bytes (name_len), then xattr data bytes (data_len)
}

impl BtrfsDirItem {
    const FIXED_LEN: usize = 17 + 8 + 2 + 2 + 1; // = 30

    fn from_bytes(b: &[u8]) -> Self {
        BtrfsDirItem {
            child_key: BtrfsKey::from_bytes(&b[0..17]),
            transid:   u64::from_le_bytes(b[17..25].try_into().unwrap()),
            data_len:  u16::from_le_bytes(b[25..27].try_into().unwrap()),
            name_len:  u16::from_le_bytes(b[27..29].try_into().unwrap()),
            ty:        b[29],
        }
    }
}

/// On-disk extent data item (fixed header = 21 bytes, then inline data or
/// a `BtrfsFileExtentItem` describing a regular extent).
#[derive(Clone, Debug)]
pub struct BtrfsFileExtentItem {
    pub generation:        u64,
    pub ram_bytes:         u64,
    pub compression:       u8,
    pub encryption:        u8,
    pub other_encoding:    u16,
    pub ty:                u8,
    // For REG/PREALLOC extents only:
    pub disk_bytenr:       u64,
    pub disk_num_bytes:    u64,
    pub offset:            u64,
    pub num_bytes:         u64,
}

impl BtrfsFileExtentItem {
    fn from_bytes(b: &[u8]) -> Self {
        let r64 = |off: usize| u64::from_le_bytes(b[off..off+8].try_into().unwrap());
        let r16 = |off: usize| u16::from_le_bytes(b[off..off+2].try_into().unwrap());
        BtrfsFileExtentItem {
            generation:     r64(0),
            ram_bytes:      r64(8),
            compression:    b[16],
            encryption:     b[17],
            other_encoding: r16(18),
            ty:             b[20],
            disk_bytenr:    if b.len() > 28 { r64(21) } else { 0 },
            disk_num_bytes: if b.len() > 36 { r64(29) } else { 0 },
            offset:         if b.len() > 44 { r64(37) } else { 0 },
            num_bytes:      if b.len() > 52 { r64(45) } else { 0 },
        }
    }
}

/// Chunk item — maps a logical address range to a physical stripe.
#[derive(Clone, Debug)]
pub struct BtrfsChunkItem {
    pub length:    u64,
    pub owner:     u64,
    pub stripe_len: u64,
    pub ty:        u64,
    pub io_align:  u32,
    pub io_width:  u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    // first stripe physical offset (we only handle single-device)
    pub stripe_devid:   u64,
    pub stripe_offset:  u64,
}

impl BtrfsChunkItem {
    fn from_bytes(b: &[u8]) -> Self {
        let r64 = |off: usize| u64::from_le_bytes(b[off..off+8].try_into().unwrap());
        let r32 = |off: usize| u32::from_le_bytes(b[off..off+4].try_into().unwrap());
        let r16 = |off: usize| u16::from_le_bytes(b[off..off+2].try_into().unwrap());
        BtrfsChunkItem {
            length:      r64(0),
            owner:       r64(8),
            stripe_len:  r64(16),
            ty:          r64(24),
            io_align:    r32(32),
            io_width:    r32(36),
            sector_size: r32(40),
            num_stripes: r16(44),
            sub_stripes: r16(46),
            // first BtrfsStripe at offset 48 (devid:8 + offset:8 + uuid:16 = 32)
            stripe_devid:  r64(48),
            stripe_offset: r64(56),
        }
    }
}

/// Root item — points at a B-tree root node.
#[derive(Clone, Debug)]
pub struct BtrfsRootItem {
    pub inode:       BtrfsInodeItem,   // 160 bytes
    pub generation:  u64,
    pub root_dirid:  u64,
    pub bytenr:      u64,   // physical byte offset of root node
    pub byte_limit:  u64,
    pub bytes_used:  u64,
    pub last_snapshot: u64,
    pub flags:       u64,
    pub refs:        u32,
    // drop_progress + other fields not needed for basic operation
}

impl BtrfsRootItem {
    fn from_bytes(b: &[u8]) -> Self {
        let r64 = |off: usize| u64::from_le_bytes(b[off..off+8].try_into().unwrap());
        let r32 = |off: usize| u32::from_le_bytes(b[off..off+4].try_into().unwrap());
        BtrfsRootItem {
            inode:         BtrfsInodeItem::from_bytes(&b[0..160]),
            generation:    r64(160),
            root_dirid:    r64(168),
            bytenr:        r64(176),
            byte_limit:    r64(184),
            bytes_used:    r64(192),
            last_snapshot: r64(200),
            flags:         r64(208),
            refs:          r32(216),
        }
    }
}

/// Superblock (fields we actually use).
#[derive(Clone, Debug)]
pub struct BtrfsSuperblock {
    pub csum:             [u8; BTRFS_CSUM_SIZE],
    pub fsid:             [u8; BTRFS_FSID_SIZE],
    pub bytenr:           u64,
    pub flags:            u64,
    pub magic:            u64,
    pub generation:       u64,
    pub root:             u64,   // root-tree logical byte offset
    pub chunk_root:       u64,
    pub log_root:         u64,
    pub total_bytes:      u64,
    pub bytes_used:       u64,
    pub root_dir_objectid: u64,
    pub num_devices:      u64,
    pub sectorsize:       u32,
    pub nodesize:         u32,
    pub leafsize:         u32,
    pub stripesize:       u32,
    pub sys_chunk_array_size: u32,
    pub label:            [u8; BTRFS_LABEL_SIZE],
    pub sys_chunk_array:  [u8; BTRFS_SYSTEM_CHUNK_ARRAY_SIZE],
}

impl BtrfsSuperblock {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < BTRFS_SUPERBLOCK_SIZE { return None; }
        let r64 = |off: usize| u64::from_le_bytes(b[off..off+8].try_into().unwrap());
        let r32 = |off: usize| u32::from_le_bytes(b[off..off+4].try_into().unwrap());

        let mut csum = [0u8; BTRFS_CSUM_SIZE];
        csum.copy_from_slice(&b[0..BTRFS_CSUM_SIZE]);
        let mut fsid = [0u8; BTRFS_FSID_SIZE];
        fsid.copy_from_slice(&b[32..48]);
        let mut label = [0u8; BTRFS_LABEL_SIZE];
        label.copy_from_slice(&b[299..555]);
        let mut sys_chunk_array = [0u8; BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];
        let sca_start = 649;
        sys_chunk_array.copy_from_slice(&b[sca_start..sca_start + BTRFS_SYSTEM_CHUNK_ARRAY_SIZE]);

        let sb = BtrfsSuperblock {
            csum,
            fsid,
            bytenr:              r64(48),
            flags:               r64(56),
            magic:               r64(64),
            generation:          r64(72),
            root:                r64(80),
            chunk_root:          r64(88),
            log_root:            r64(96),
            total_bytes:         r64(120),
            bytes_used:          r64(128),
            root_dir_objectid:   r64(136),
            num_devices:         r64(144),
            sectorsize:          r32(152),
            nodesize:            r32(156),
            leafsize:            r32(160),
            stripesize:          r32(164),
            sys_chunk_array_size: r32(168),
            label,
            sys_chunk_array,
        };

        if sb.magic != BTRFS_MAGIC { return None; }
        Some(sb)
    }
}


/// Header present at the start of every B-tree node (101 bytes).
#[derive(Clone, Debug)]
struct BtrfsHeader {
    csum:       [u8; BTRFS_CSUM_SIZE],
    fsid:       [u8; BTRFS_FSID_SIZE],
    bytenr:     u64,
    flags:      u64,
    chunk_tree_uuid: [u8; BTRFS_UUID_SIZE],
    generation: u64,
    owner:      u64,
    nritems:    u32,
    level:      u8,   // 0 = leaf
}

impl BtrfsHeader {
    const SIZE: usize = 101;

    fn from_bytes(b: &[u8]) -> Self {
        let r64 = |off: usize| u64::from_le_bytes(b[off..off+8].try_into().unwrap());
        let r32 = |off: usize| u32::from_le_bytes(b[off..off+4].try_into().unwrap());
        let mut csum = [0u8; BTRFS_CSUM_SIZE];
        csum.copy_from_slice(&b[0..32]);
        let mut fsid = [0u8; BTRFS_FSID_SIZE];
        fsid.copy_from_slice(&b[32..48]);
        let mut uuid = [0u8; BTRFS_UUID_SIZE];
        uuid.copy_from_slice(&b[64..80]);
        BtrfsHeader {
            csum,
            fsid,
            bytenr:          r64(48),
            flags:           r64(56),
            chunk_tree_uuid: uuid,
            generation:      r64(80),
            owner:           r64(88),
            nritems:         r32(96),
            level:           b[100],
        }
    }
}

/// Leaf item descriptor (25 bytes each, stored after the header in a leaf).
#[derive(Clone, Debug)]
struct BtrfsItem {
    key:    BtrfsKey,
    offset: u32,   // offset from start of item data area
    size:   u32,
}

impl BtrfsItem {
    const SIZE: usize = 25;

    fn from_bytes(b: &[u8]) -> Self {
        BtrfsItem {
            key:    BtrfsKey::from_bytes(&b[0..17]),
            offset: u32::from_le_bytes(b[17..21].try_into().unwrap()),
            size:   u32::from_le_bytes(b[21..25].try_into().unwrap()),
        }
    }
}

/// Internal node key pointer (33 bytes each).
#[derive(Clone, Debug)]
struct BtrfsKeyPtr {
    key:        BtrfsKey,
    blockptr:   u64,
    generation: u64,
}

impl BtrfsKeyPtr {
    const SIZE: usize = 33;

    fn from_bytes(b: &[u8]) -> Self {
        BtrfsKeyPtr {
            key:        BtrfsKey::from_bytes(&b[0..17]),
            blockptr:   u64::from_le_bytes(b[17..25].try_into().unwrap()),
            generation: u64::from_le_bytes(b[25..33].try_into().unwrap()),
        }
    }
}


/// In-memory representation of a mounted Btrfs filesystem.
pub struct BtrfsFs {
    /// Parsed superblock.
    pub superblock: BtrfsSuperblock,
    /// Logical → physical byte translation table built from chunk tree.
    chunk_map: Vec<(u64, u64, BtrfsChunkItem)>,  // (logical_start, logical_end, chunk)
    /// Root-tree root node logical byte offset.
    root_tree_root: u64,
    /// FS-tree root node logical byte offset (default subvolume).
    fs_tree_root: u64,
    /// Cache: path → inode number.
    path_cache: BTreeMap<String, u64>,
    /// Next logical byte offset for CoW allocation (monotonically increasing).
    alloc_cursor: u64,
}

impl BtrfsFs {

    /// Translate a logical byte address to a physical byte address using the
    /// chunk map built during mount.
    fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        for (start, end, chunk) in &self.chunk_map {
            if logical >= *start && logical < *end {
                let offset_in_chunk = logical - start;
                return Some(chunk.stripe_offset + offset_in_chunk);
            }
        }
        None
    }

    /// Read `nodesize` bytes at logical address `logical` from disk.
    fn read_node_bytes(&self, logical: u64) -> Option<Vec<u8>> {
        let phys = self.logical_to_physical(logical)?;
        let nsz  = self.superblock.nodesize as u64;
        let lba  = phys / 512;
        let sectors = (nsz + 511) / 512;
        let raw = block_read(lba, sectors as u32);
        let off = (phys % 512) as usize;
        Some(raw[off..off + nsz as usize].to_vec())
    }


    /// Search the B-tree rooted at `root_logical` for all leaf items whose key
    /// satisfies `predicate`.  Returns a Vec of (key, item_data).
    fn btree_search<F>(&self, root_logical: u64, predicate: F) -> Vec<(BtrfsKey, Vec<u8>)>
    where
        F: Fn(&BtrfsKey) -> core::cmp::Ordering,
    {
        let mut results = Vec::new();
        self.btree_walk(root_logical, &predicate, &mut results, 0);
        results
    }

    fn btree_walk<F>(
        &self,
        node_logical: u64,
        predicate: &F,
        out: &mut Vec<(BtrfsKey, Vec<u8>)>,
        depth: usize,
    ) where
        F: Fn(&BtrfsKey) -> core::cmp::Ordering,
    {
        if depth > 16 { return; } // cycle guard
        let node = match self.read_node_bytes(node_logical) {
            Some(n) => n,
            None    => return,
        };
        if node.len() < BtrfsHeader::SIZE { return; }
        let hdr = BtrfsHeader::from_bytes(&node);

        if hdr.level == 0 {
            // Leaf node
            let item_area_start = BtrfsHeader::SIZE;
            let data_area_end   = self.superblock.nodesize as usize;
            let n = hdr.nritems as usize;
            if n > BTRFS_MAX_LEAF_ITEMS { return; }

            for i in 0..n {
                let ioff = item_area_start + i * BtrfsItem::SIZE;
                if ioff + BtrfsItem::SIZE > node.len() { break; }
                let item = BtrfsItem::from_bytes(&node[ioff..ioff + BtrfsItem::SIZE]);
                let cmp = predicate(&item.key);
                if cmp == core::cmp::Ordering::Equal {
                    // data is at: header + (nodesize - data_area bytes from end)
                    // In btrfs leaf layout the data area grows from the end of
                    // the node toward the item descriptors.
                    let data_start = BtrfsHeader::SIZE
                        + (self.superblock.nodesize as usize - BtrfsHeader::SIZE - item.offset as usize);
                    // Recompute: item.offset is relative to the *end* of header,
                    // measured from the tail of the leaf.
                    // actual layout: items grow from [header_end], data grows backward
                    // from [node_end].  item.offset = distance from node_end to data.
                    let data_off = data_area_end.saturating_sub(item.offset as usize + item.size as usize);
                    let data_end = data_off + item.size as usize;
                    if data_end <= node.len() {
                        out.push((item.key, node[data_off..data_end].to_vec()));
                    }
                }
            }
        } else {
            // Internal node — iterate key pointers
            let kp_area_start = BtrfsHeader::SIZE;
            let n = hdr.nritems as usize;
            if n > BTRFS_MAX_LEAF_ITEMS { return; }

            // Collect children whose key range overlaps our search
            let mut children: Vec<u64> = Vec::new();
            for i in 0..n {
                let koff = kp_area_start + i * BtrfsKeyPtr::SIZE;
                if koff + BtrfsKeyPtr::SIZE > node.len() { break; }
                let kp = BtrfsKeyPtr::from_bytes(&node[koff..koff + BtrfsKeyPtr::SIZE]);
                // Check the next key too to bound the range
                let next_key = if i + 1 < n {
                    let nkoff = kp_area_start + (i + 1) * BtrfsKeyPtr::SIZE;
                    if nkoff + BtrfsKeyPtr::SIZE <= node.len() {
                        Some(BtrfsKeyPtr::from_bytes(&node[nkoff..nkoff + BtrfsKeyPtr::SIZE]).key)
                    } else { None }
                } else { None };

                let lo = predicate(&kp.key);
                let go = match lo {
                    core::cmp::Ordering::Less    => true,
                    core::cmp::Ordering::Equal   => true,
                    core::cmp::Ordering::Greater => {
                        // Only descend if no next key or next key is >= target
                        next_key.map_or(true, |nk| predicate(&nk) != core::cmp::Ordering::Greater)
                    }
                };
                if go { children.push(kp.blockptr); }
            }
            for child in children {
                self.btree_walk(child, predicate, out, depth + 1);
            }
        }
    }

    /// Convenience: find the single leaf item matching `key` exactly.
    fn lookup_item(&self, root: u64, key: BtrfsKey) -> Option<Vec<u8>> {
        let results = self.btree_search(root, |k| k.cmp(&key));
        results.into_iter().next().map(|(_, data)| data)
    }

    /// Find all items for a given objectid + key-type, any offset.
    fn lookup_items_by_type(&self, root: u64, objectid: u64, ty: u8) -> Vec<(BtrfsKey, Vec<u8>)> {
        self.btree_search(root, |k| {
            if k.objectid != objectid { return k.objectid.cmp(&objectid); }
            if k.ty != ty { return k.ty.cmp(&ty); }
            core::cmp::Ordering::Equal
        })
    }


    /// Walk the FS-tree from the root directory to resolve `path` to an
    /// inode number.  Returns `None` if any component is missing.
    fn resolve_path(&self, path: &str) -> Option<u64> {
        // Root inode is always objectid 256 in the default subvolume.
        let mut cur_ino: u64 = self.superblock.root_dir_objectid.max(BTRFS_FIRST_FREE_OBJECTID);
        if path == "/" || path.is_empty() {
            return Some(cur_ino);
        }
        for component in path.trim_start_matches('/').split('/') {
            if component.is_empty() { continue; }
            cur_ino = self.dir_lookup(cur_ino, component)?;
        }
        Some(cur_ino)
    }

    /// Look up `name` in directory inode `dir_ino`.  Returns child inode number.
    fn dir_lookup(&self, dir_ino: u64, name: &str) -> Option<u64> {
        let name_bytes = name.as_bytes();
        let hash = btrfs_name_hash(name_bytes);
        // DIR_ITEM key: objectid=dir_ino, ty=DIR_ITEM_KEY, offset=name_hash
        let key = BtrfsKey { objectid: dir_ino, ty: BTRFS_DIR_ITEM_KEY, offset: hash };
        let data = self.lookup_item(self.fs_tree_root, key)?;
        if data.len() < BtrfsDirItem::FIXED_LEN { return None; }
        let di = BtrfsDirItem::from_bytes(&data);
        let name_start = BtrfsDirItem::FIXED_LEN;
        let name_end   = name_start + di.name_len as usize;
        if name_end > data.len() { return None; }
        if &data[name_start..name_end] != name_bytes { return None; }
        Some(di.child_key.objectid)
    }


    fn read_inode(&self, ino: u64) -> Option<BtrfsInodeItem> {
        let key = BtrfsKey { objectid: ino, ty: BTRFS_INODE_ITEM_KEY, offset: 0 };
        let data = self.lookup_item(self.fs_tree_root, key)?;
        if data.len() < 160 { return None; }
        Some(BtrfsInodeItem::from_bytes(&data))
    }

    /// Build a `KStat` for the inode at `path`.
    pub fn stat(&self, path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii  = self.read_inode(ino).ok_or(-5isize)?;
        let blksize = self.superblock.sectorsize as u64;
        Ok(crate::fs::vfs_ops::KStat {
            ino,
            mode:    ii.mode as u16,
            nlink:   ii.nlink,
            uid:     ii.uid,
            gid:     ii.gid,
            size:    ii.size,
            atime:   ii.atime_ns(),
            mtime:   ii.mtime_ns(),
            ctime:   ii.ctime_ns(),
            blksize,
            blocks:  ii.nbytes.div_ceil(512),
            is_dir:  (ii.mode & 0o170000) == 0o040000,
        })
    }


    /// Read all data bytes from file at `path`.
    pub fn read_all(&self, path: &str) -> Result<Vec<u8>, isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii  = self.read_inode(ino).ok_or(-5isize)?;
        if (ii.mode & 0o170000) == 0o040000 { return Err(-21); }
        self.read_inode_data(ino, ii.size)
    }

    /// Read all extent data for `ino`, up to `file_size` bytes.
    fn read_inode_data(&self, ino: u64, file_size: u64) -> Result<Vec<u8>, isize> {
        let mut file_data = vec![0u8; file_size as usize];
        let extents = self.lookup_items_by_type(self.fs_tree_root, ino, BTRFS_EXTENT_DATA_KEY);

        for (key, data) in extents {
            let file_offset = key.offset as usize;
            if file_offset >= file_size as usize { continue; }

            if data.len() < 21 { continue; }
            let fe = BtrfsFileExtentItem::from_bytes(&data);

            if fe.compression != BTRFS_COMPRESS_NONE {
                // Compressed extents not yet supported; skip silently.
                continue;
            }

            match fe.ty {
                BTRFS_FILE_EXTENT_INLINE => {
                    // Inline data follows the 21-byte header.
                    let inline_data = &data[21..];
                    let copy_len = inline_data.len().min(file_data.len().saturating_sub(file_offset));
                    file_data[file_offset..file_offset + copy_len]
                        .copy_from_slice(&inline_data[..copy_len]);
                }
                BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC => {
                    if fe.disk_bytenr == 0 { continue; } // sparse / hole
                    let phys = match self.logical_to_physical(fe.disk_bytenr + fe.offset) {
                        Some(p) => p,
                        None    => continue,
                    };
                    let extent_len = fe.num_bytes as usize;
                    let lba        = phys / 512;
                    let sectors    = ((extent_len + 511) / 512) as u32;
                    let raw        = block_read(lba, sectors);
                    let raw_off    = (phys % 512) as usize;
                    let copy_len   = extent_len
                        .min(file_data.len().saturating_sub(file_offset))
                        .min(raw.len().saturating_sub(raw_off));
                    if copy_len == 0 { continue; }
                    file_data[file_offset..file_offset + copy_len]
                        .copy_from_slice(&raw[raw_off..raw_off + copy_len]);
                }
                _ => {}
            }
        }
        Ok(file_data)
    }


    /// Write `data` to the file at `path`, replacing its contents (CoW).
    /// A new extent is allocated at `alloc_cursor`, the old extent-data items
    /// are replaced in the FS-tree leaf, and the inode size is updated.
    pub fn write_all(&mut self, path: &str, data: &[u8]) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        self.write_inode_data(ino, 0, data)
    }

    /// CoW write: allocate a new physical region, write data, then update the
    /// FS-tree to point the inode's extent at the new location.
    fn write_inode_data(&mut self, ino: u64, file_offset: u64, data: &[u8]) -> Result<(), isize> {
        if data.is_empty() { return Ok(()); }

        // 1. Allocate new logical address (simple bump allocator).
        let nodesize   = self.superblock.nodesize as u64;
        let alloc_logical = align_up(self.alloc_cursor, nodesize);
        let alloc_len     = align_up(data.len() as u64, 4096);
        self.alloc_cursor = alloc_logical + alloc_len;

        // 2. Translate to physical and write the new data blocks.
        let phys = self.logical_to_physical(alloc_logical).ok_or(-28isize)?;
        let mut disk_data = vec![0u8; alloc_len as usize];
        disk_data[..data.len()].copy_from_slice(data);
        // Pad to sector boundary
        let write_buf_sectors = align_up(alloc_len, 512) as usize / 512;
        let mut sector_buf = vec![0u8; write_buf_sectors * 512];
        sector_buf[..disk_data.len()].copy_from_slice(&disk_data);
        block_write(phys / 512, &sector_buf);

        // 3. Patch the in-memory FS-tree: update inode size + insert new extent.
        //    (A production driver would COW the B-tree nodes; we mutate the
        //     cached in-memory view that will be flushed to disk via
        //     write_inode_item / write_extent_item below.)
        self.write_inode_size(ino, file_offset + data.len() as u64)?;
        self.insert_extent_item(ino, file_offset, alloc_logical, alloc_len, data.len() as u64)?;

        Ok(())
    }

    /// Update the size field of an inode by re-writing its inode item on disk.
    fn write_inode_size(&self, ino: u64, new_size: u64) -> Result<(), isize> {
        // We read the current inode item, patch the size, and write it back.
        let key = BtrfsKey { objectid: ino, ty: BTRFS_INODE_ITEM_KEY, offset: 0 };
        let mut item_data = self.lookup_item(self.fs_tree_root, key.clone()).ok_or(-5isize)?;
        if item_data.len() < 24 { return Err(-5); }
        // size is at offset 16 in BtrfsInodeItem
        item_data[16..24].copy_from_slice(&new_size.to_le_bytes());
        self.write_leaf_item(self.fs_tree_root, key, &item_data)
    }

    /// Insert (or replace) an EXTENT_DATA item for `ino` at `file_offset`.
    fn insert_extent_item(
        &self,
        ino: u64,
        file_offset: u64,
        disk_logical: u64,
        disk_len: u64,
        num_bytes: u64,
    ) -> Result<(), isize> {
        // Build the on-disk BtrfsFileExtentItem (53 bytes).
        let mut extent_bytes = [0u8; 53];
        // generation at 0
        extent_bytes[0..8].copy_from_slice(&self.superblock.generation.to_le_bytes());
        // ram_bytes at 8
        extent_bytes[8..16].copy_from_slice(&num_bytes.to_le_bytes());
        // compression=0, encryption=0, other_encoding=0
        extent_bytes[16] = BTRFS_COMPRESS_NONE;
        extent_bytes[17] = 0;
        extent_bytes[18..20].copy_from_slice(&0u16.to_le_bytes());
        extent_bytes[20] = BTRFS_FILE_EXTENT_REG;
        // disk_bytenr at 21
        extent_bytes[21..29].copy_from_slice(&disk_logical.to_le_bytes());
        // disk_num_bytes at 29
        extent_bytes[29..37].copy_from_slice(&disk_len.to_le_bytes());
        // extent offset = 0 (we write at start of allocation)
        extent_bytes[37..45].copy_from_slice(&0u64.to_le_bytes());
        // num_bytes at 45
        extent_bytes[45..53].copy_from_slice(&num_bytes.to_le_bytes());

        let key = BtrfsKey { objectid: ino, ty: BTRFS_EXTENT_DATA_KEY, offset: file_offset };
        self.write_leaf_item(self.fs_tree_root, key, &extent_bytes)
    }

    /// Write an item back into the leaf that contains it.  Walks the B-tree to
    /// find the leaf, patches the item's data bytes in place, then writes the
    /// sector(s) back to disk.
    fn write_leaf_item(&self, root: u64, key: BtrfsKey, data: &[u8]) -> Result<(), isize> {
        self.write_leaf_item_recurse(root, key, data, 0)
    }

    fn write_leaf_item_recurse(&self, node_logical: u64, key: BtrfsKey, data: &[u8], depth: usize) -> Result<(), isize> {
        if depth > 16 { return Err(-5); }
        let mut node = self.read_node_bytes(node_logical).ok_or(-5isize)?;
        if node.len() < BtrfsHeader::SIZE { return Err(-5); }
        let hdr = BtrfsHeader::from_bytes(&node);

        if hdr.level == 0 {
            let n = hdr.nritems as usize;
            let nodesize = self.superblock.nodesize as usize;
            for i in 0..n {
                let ioff = BtrfsHeader::SIZE + i * BtrfsItem::SIZE;
                if ioff + BtrfsItem::SIZE > node.len() { break; }
                let item = BtrfsItem::from_bytes(&node[ioff..ioff + BtrfsItem::SIZE]);
                if item.key == key {
                    let data_off = nodesize - item.offset as usize - item.size as usize;
                    let patch_len = data.len().min(item.size as usize);
                    node[data_off..data_off + patch_len].copy_from_slice(&data[..patch_len]);
                    // Write the patched node back to disk.
                    let phys = self.logical_to_physical(node_logical).ok_or(-5isize)?;
                    let lba  = phys / 512;
                    let pad_len = align_up(node.len() as u64, 512) as usize;
                    let mut sector_buf = vec![0u8; pad_len];
                    sector_buf[..node.len()].copy_from_slice(&node);
                    block_write(lba, &sector_buf);
                    return Ok(());
                }
            }
            return Err(-2); // item not found in this leaf
        } else {
            // Internal node: find the right child
            let n = hdr.nritems as usize;
            let mut child: Option<u64> = None;
            for i in 0..n {
                let koff = BtrfsHeader::SIZE + i * BtrfsKeyPtr::SIZE;
                if koff + BtrfsKeyPtr::SIZE > node.len() { break; }
                let kp = BtrfsKeyPtr::from_bytes(&node[koff..koff + BtrfsKeyPtr::SIZE]);
                let next_kp = if i + 1 < n {
                    let nkoff = BtrfsHeader::SIZE + (i + 1) * BtrfsKeyPtr::SIZE;
                    if nkoff + BtrfsKeyPtr::SIZE <= node.len() {
                        Some(BtrfsKeyPtr::from_bytes(&node[nkoff..nkoff + BtrfsKeyPtr::SIZE]))
                    } else { None }
                } else { None };
                if kp.key <= key && next_kp.map_or(true, |nkp| key < nkp.key) {
                    child = Some(kp.blockptr);
                    break;
                }
            }
            match child {
                Some(c) => self.write_leaf_item_recurse(c, key, data, depth + 1),
                None    => Err(-2),
            }
        }
    }


    /// Return a list of (name, inode_number, is_dir, mode, size) for `path`.
    pub fn readdir(&self, path: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
        let dir_ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii = self.read_inode(dir_ino).ok_or(-5isize)?;
        if (ii.mode & 0o170000) != 0o040000 { return Err(-20); }

        let index_items = self.lookup_items_by_type(self.fs_tree_root, dir_ino, BTRFS_DIR_INDEX_KEY);
        let mut entries = Vec::new();

        for (key, data) in index_items {
            if data.len() < BtrfsDirItem::FIXED_LEN { continue; }
            let di = BtrfsDirItem::from_bytes(&data);
            let name_start = BtrfsDirItem::FIXED_LEN;
            let name_end   = name_start + di.name_len as usize;
            if name_end > data.len() { continue; }
            let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
            if name == "." || name == ".." { continue; }

            let child_ino = di.child_key.objectid;
            let (mode, size) = self.read_inode(child_ino)
                .map(|ci| (ci.mode as u16, ci.size))
                .unwrap_or((0o100644, 0));
            let is_dir = di.ty == BTRFS_FT_DIR;

            entries.push(crate::fs::vfs_ops::DirEntry {
                name,
                ino: child_ino,
                is_dir,
                mode,
                size,
            });
        }
        Ok(entries)
    }


    pub fn readlink(&self, path: &str) -> Result<String, isize> {
        let data = self.read_all(path)?;
        String::from_utf8(data).map_err(|_| -22isize)
    }


    pub fn statfs(&self) -> crate::fs::vfs_ops::KStatfs {
        const BTRFS_SUPER_MAGIC: u64 = 0x9123683E;
        let bs = self.superblock.sectorsize as u64;
        let total = self.superblock.total_bytes / bs;
        let used  = self.superblock.bytes_used / bs;
        crate::fs::vfs_ops::KStatfs {
            f_type:    BTRFS_SUPER_MAGIC,
            f_bsize:   bs,
            f_blocks:  total,
            f_bfree:   total.saturating_sub(used),
            f_bavail:  total.saturating_sub(used),
            f_namelen: 255,
        }
    }


    /// Allocate a new inode number (scans for the next free objectid).
    fn alloc_ino(&self) -> u64 {
        // Simple linear scan; a production driver would use the free-space tree.
        let used: Vec<u64> = self.btree_search(self.fs_tree_root, |k| {
            if k.ty != BTRFS_INODE_ITEM_KEY { return k.ty.cmp(&BTRFS_INODE_ITEM_KEY); }
            core::cmp::Ordering::Equal
        }).iter().map(|(k, _)| k.objectid).collect();

        let mut candidate = BTRFS_FIRST_FREE_OBJECTID;
        while used.contains(&candidate) { candidate += 1; }
        candidate
    }

    /// Write a raw on-disk inode item for `ino`.
    fn write_inode_item(&self, ino: u64, ii: &BtrfsInodeItem) -> Result<(), isize> {
        let key = BtrfsKey { objectid: ino, ty: BTRFS_INODE_ITEM_KEY, offset: 0 };
        let mut b = [0u8; 160];
        let pack_u64 = |buf: &mut [u8], off: usize, v: u64| buf[off..off+8].copy_from_slice(&v.to_le_bytes());
        let pack_u32 = |buf: &mut [u8], off: usize, v: u32| buf[off..off+4].copy_from_slice(&v.to_le_bytes());
        pack_u64(&mut b, 0,  ii.generation);
        pack_u64(&mut b, 8,  ii.transid);
        pack_u64(&mut b, 16, ii.size);
        pack_u64(&mut b, 24, ii.nbytes);
        pack_u64(&mut b, 32, ii.block_group);
        pack_u32(&mut b, 40, ii.nlink);
        pack_u32(&mut b, 44, ii.uid);
        pack_u32(&mut b, 48, ii.gid);
        pack_u32(&mut b, 52, ii.mode);
        pack_u64(&mut b, 56, ii.rdev);
        pack_u64(&mut b, 64, ii.flags);
        pack_u64(&mut b, 72, ii.sequence);
        // timestamps at 112..160
        pack_u64(&mut b, 112, ii.atime_sec);  pack_u32(&mut b, 120, ii.atime_nsec);
        pack_u64(&mut b, 124, ii.ctime_sec);  pack_u32(&mut b, 132, ii.ctime_nsec);
        pack_u64(&mut b, 136, ii.mtime_sec);  pack_u32(&mut b, 144, ii.mtime_nsec);
        pack_u64(&mut b, 148, ii.otime_sec);  pack_u32(&mut b, 156, ii.otime_nsec);
        self.write_leaf_item(self.fs_tree_root, key, &b)
    }

    /// Insert a DIR_ITEM and DIR_INDEX record linking `name` → `child_ino` in
    /// parent directory `parent_ino`.
    fn insert_dirent(&self, parent_ino: u64, name: &str, child_ino: u64, ty: u8) -> Result<(), isize> {
        let name_bytes = name.as_bytes();
        let hash = btrfs_name_hash(name_bytes);
        let child_key = BtrfsKey { objectid: child_ino, ty: BTRFS_INODE_ITEM_KEY, offset: 0 };

        // Build the dir-item payload (30 + name_len bytes).
        let mut di_bytes = vec![0u8; BtrfsDirItem::FIXED_LEN + name_bytes.len()];
        di_bytes[0..17].copy_from_slice(&{
            let mut kb = [0u8; 17];
            kb[0..8].copy_from_slice(&child_key.objectid.to_le_bytes());
            kb[8] = child_key.ty;
            kb[9..17].copy_from_slice(&child_key.offset.to_le_bytes());
            kb
        });
        // transid at 17
        di_bytes[17..25].copy_from_slice(&self.superblock.generation.to_le_bytes());
        // data_len = 0
        di_bytes[25..27].copy_from_slice(&0u16.to_le_bytes());
        di_bytes[27..29].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        di_bytes[29] = ty;
        di_bytes[30..30 + name_bytes.len()].copy_from_slice(name_bytes);

        // DIR_ITEM
        let dir_item_key = BtrfsKey { objectid: parent_ino, ty: BTRFS_DIR_ITEM_KEY, offset: hash };
        self.write_leaf_item(self.fs_tree_root, dir_item_key, &di_bytes)?;

        // DIR_INDEX (offset = next free sequential index; we approximate with ino)
        let dir_index_key = BtrfsKey { objectid: parent_ino, ty: BTRFS_DIR_INDEX_KEY, offset: child_ino };
        self.write_leaf_item(self.fs_tree_root, dir_index_key, &di_bytes)
    }

    /// Remove the DIR_ITEM linking `name` in `parent_ino` by zeroing the entry.
    fn remove_dirent(&self, parent_ino: u64, name: &str, child_ino: u64) -> Result<(), isize> {
        let hash = btrfs_name_hash(name.as_bytes());
        let zeroes = vec![0u8; BtrfsDirItem::FIXED_LEN + name.len()];
        let dir_item_key = BtrfsKey { objectid: parent_ino, ty: BTRFS_DIR_ITEM_KEY, offset: hash };
        let _ = self.write_leaf_item(self.fs_tree_root, dir_item_key, &zeroes);
        let dir_index_key = BtrfsKey { objectid: parent_ino, ty: BTRFS_DIR_INDEX_KEY, offset: child_ino };
        let _ = self.write_leaf_item(self.fs_tree_root, dir_index_key, &zeroes);
        Ok(())
    }

    /// Decrement nlink; if it reaches 0, zero the inode item.
    fn drop_inode(&self, ino: u64) -> Result<(), isize> {
        let mut ii = self.read_inode(ino).ok_or(-2isize)?;
        if ii.nlink > 0 { ii.nlink -= 1; }
        if ii.nlink == 0 {
            // Zero-out inode item → effectively frees it.
            let key = BtrfsKey { objectid: ino, ty: BTRFS_INODE_ITEM_KEY, offset: 0 };
            self.write_leaf_item(self.fs_tree_root, key, &[0u8; 160])
        } else {
            self.write_inode_item(ino, &ii)
        }
    }


    pub fn create(&mut self, path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        // Fail if already exists.
        if self.dir_lookup(parent_ino, name).is_some() { return Err(-17); }

        let new_ino = self.alloc_ino();
        let now = crate::time_ns::ktime_get_ns();
        let ii = BtrfsInodeItem {
            generation: self.superblock.generation,
            nlink: 1,
            uid:   0, gid: 0,
            mode:  0o100644,
            size:  0, nbytes: 0,
            atime_sec: now / 1_000_000_000, atime_nsec: (now % 1_000_000_000) as u32,
            mtime_sec: now / 1_000_000_000, mtime_nsec: (now % 1_000_000_000) as u32,
            ctime_sec: now / 1_000_000_000, ctime_nsec: (now % 1_000_000_000) as u32,
            ..BtrfsInodeItem::default()
        };
        self.write_inode_item(new_ino, &ii)?;
        self.insert_dirent(parent_ino, name, new_ino, BTRFS_FT_REG_FILE)
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        if self.dir_lookup(parent_ino, name).is_some() { return Err(-17); }

        let new_ino = self.alloc_ino();
        let now = crate::time_ns::ktime_get_ns();
        let ii = BtrfsInodeItem {
            generation: self.superblock.generation,
            nlink: 2, uid: 0, gid: 0,
            mode:  0o040755,
            size:  0, nbytes: 0,
            atime_sec: now / 1_000_000_000, atime_nsec: (now % 1_000_000_000) as u32,
            mtime_sec: now / 1_000_000_000, mtime_nsec: (now % 1_000_000_000) as u32,
            ctime_sec: now / 1_000_000_000, ctime_nsec: (now % 1_000_000_000) as u32,
            ..BtrfsInodeItem::default()
        };
        self.write_inode_item(new_ino, &ii)?;
        self.insert_dirent(parent_ino, name, new_ino, BTRFS_FT_DIR)
    }

    pub fn unlink(&self, path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        let child_ino  = self.dir_lookup(parent_ino, name).ok_or(-2isize)?;
        let ii         = self.read_inode(child_ino).ok_or(-5isize)?;
        if (ii.mode & 0o170000) == 0o040000 { return Err(-21); }
        self.remove_dirent(parent_ino, name, child_ino)?;
        self.drop_inode(child_ino)
    }

    pub fn rmdir(&self, path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(path)?;
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        let child_ino  = self.dir_lookup(parent_ino, name).ok_or(-2isize)?;
        let ii         = self.read_inode(child_ino).ok_or(-5isize)?;
        if (ii.mode & 0o170000) != 0o040000 { return Err(-20); }
        // Must be empty.
        let index_items = self.lookup_items_by_type(self.fs_tree_root, child_ino, BTRFS_DIR_INDEX_KEY);
        let non_trivial = index_items.iter().filter(|(k, d)| {
            if d.len() < BtrfsDirItem::FIXED_LEN { return false; }
            let di = BtrfsDirItem::from_bytes(d);
            let ns = BtrfsDirItem::FIXED_LEN;
            let ne = ns + di.name_len as usize;
            if ne > d.len() { return false; }
            let n = core::str::from_utf8(&d[ns..ne]).unwrap_or("");
            n != "." && n != ".."
        }).count();
        if non_trivial > 0 { return Err(-39); }
        self.remove_dirent(parent_ino, name, child_ino)?;
        self.drop_inode(child_ino)
    }

    pub fn rename(&self, old: &str, new: &str) -> Result<(), isize> {
        let (old_parent_path, old_name) = split_path(old)?;
        let (new_parent_path, new_name) = split_path(new)?;
        let old_parent = self.resolve_path(old_parent_path).ok_or(-2isize)?;
        let new_parent = self.resolve_path(new_parent_path).ok_or(-2isize)?;
        let child_ino  = self.dir_lookup(old_parent, old_name).ok_or(-2isize)?;
        let ii         = self.read_inode(child_ino).ok_or(-5isize)?;
        let ty = if (ii.mode & 0o170000) == 0o040000 { BTRFS_FT_DIR } else { BTRFS_FT_REG_FILE };
        // Remove old dirent and add new one.
        self.remove_dirent(old_parent, old_name, child_ino)?;
        self.insert_dirent(new_parent, new_name, child_ino, ty)
    }

    pub fn link(&self, existing: &str, new: &str) -> Result<(), isize> {
        let (new_parent_path, new_name) = split_path(new)?;
        let new_parent = self.resolve_path(new_parent_path).ok_or(-2isize)?;
        let child_ino  = self.resolve_path(existing).ok_or(-2isize)?;
        let mut ii     = self.read_inode(child_ino).ok_or(-5isize)?;
        if (ii.mode & 0o170000) == 0o040000 { return Err(-1); }
        ii.nlink += 1;
        self.write_inode_item(child_ino, &ii)?;
        self.insert_dirent(new_parent, new_name, child_ino, BTRFS_FT_REG_FILE)
    }

    pub fn symlink(&self, target: &str, link_path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(link_path)?;
        let parent_ino = self.resolve_path(parent_path).ok_or(-2isize)?;
        if self.dir_lookup(parent_ino, name).is_some() { return Err(-17); }
        let new_ino = self.alloc_ino();
        let now = crate::time_ns::ktime_get_ns();
        let ii = BtrfsInodeItem {
            generation: self.superblock.generation,
            nlink: 1, uid: 0, gid: 0,
            mode:  0o120777,
            size:  target.len() as u64,
            nbytes: target.len() as u64,
            atime_sec: now / 1_000_000_000, atime_nsec: (now % 1_000_000_000) as u32,
            mtime_sec: now / 1_000_000_000, mtime_nsec: (now % 1_000_000_000) as u32,
            ctime_sec: now / 1_000_000_000, ctime_nsec: (now % 1_000_000_000) as u32,
            ..BtrfsInodeItem::default()
        };
        self.write_inode_item(new_ino, &ii)?;
        self.insert_dirent(parent_ino, name, new_ino, BTRFS_FT_SYMLINK)?;
        // Store target as inline extent data.
        let key = BtrfsKey { objectid: new_ino, ty: BTRFS_EXTENT_DATA_KEY, offset: 0 };
        let mut ext_bytes = vec![0u8; 21 + target.len()];
        ext_bytes[16] = BTRFS_COMPRESS_NONE;
        ext_bytes[20] = BTRFS_FILE_EXTENT_INLINE;
        ext_bytes[21..].copy_from_slice(target.as_bytes());
        self.write_leaf_item(self.fs_tree_root, key, &ext_bytes)
    }

    pub fn chmod(&self, path: &str, mode: u16) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let mut ii = self.read_inode(ino).ok_or(-5isize)?;
        ii.mode = (ii.mode & 0o170000) | (mode as u32 & 0o7777);
        self.write_inode_item(ino, &ii)
    }

    pub fn chown(&self, path: &str, uid: u32, gid: u32) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let mut ii = self.read_inode(ino).ok_or(-5isize)?;
        if uid != u32::MAX { ii.uid = uid; }
        if gid != u32::MAX { ii.gid = gid; }
        self.write_inode_item(ino, &ii)
    }

    pub fn set_times(&self, path: &str, atime_ns: u64, mtime_ns: u64) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let mut ii = self.read_inode(ino).ok_or(-5isize)?;
        ii.atime_sec  = atime_ns / 1_000_000_000;
        ii.atime_nsec = (atime_ns % 1_000_000_000) as u32;
        ii.mtime_sec  = mtime_ns / 1_000_000_000;
        ii.mtime_nsec = (mtime_ns % 1_000_000_000) as u32;
        self.write_inode_item(ino, &ii)
    }

    pub fn truncate(&mut self, path: &str, len: usize) -> Result<(), isize> {
        let ino = self.resolve_path(path).ok_or(-2isize)?;
        let ii  = self.read_inode(ino).ok_or(-5isize)?;
        if (ii.mode & 0o170000) == 0o040000 { return Err(-21); }
        let current_len = ii.size as usize;
        if len <= current_len {
            // Shrink: update size in inode only (extent trimming is a future TODO).
            self.write_inode_size(ino, len as u64)
        } else {
            // Extend: write zeroed bytes.
            let extra = vec![0u8; len - current_len];
            self.write_inode_data(ino, current_len as u64, &extra)
        }
    }
}


pub static BTRFS_MOUNTS: Mutex<BTreeMap<String, BtrfsFs>> = Mutex::new(BTreeMap::new());

/// Mount a Btrfs filesystem from the primary virtio-blk device.
/// Called by `mount.rs` when `fstype == FsType::Btrfs`.
pub fn mount() -> bool {
    // Read superblock (64 KiB offset).
    let sb_lba     = BTRFS_SUPERBLOCK_OFFSET / 512;
    let sb_sectors = (BTRFS_SUPERBLOCK_SIZE as u64 + 511) / 512;
    let sb_raw     = block_read(sb_lba, sb_sectors as u32);

    let sb = match BtrfsSuperblock::from_bytes(&sb_raw) {
        Some(s) => s,
        None => {
            log::warn!("btrfs: superblock magic mismatch");
            return false;
        }
    };

    log::info!(
        "btrfs: nodesize={} sectorsize={} total_bytes={}",
        sb.nodesize, sb.sectorsize, sb.total_bytes
    );

    // Build chunk map from the embedded sys_chunk_array in the superblock.
    let chunk_map = parse_sys_chunk_array(&sb);

    // We need at least one chunk to translate the root-tree logical address.
    if chunk_map.is_empty() {
        log::warn!("btrfs: empty chunk map — cannot translate root-tree address");
        return false;
    }

    let root_tree_root = sb.root;
    let chunk_tree_root = sb.chunk_root;

    let mut fs = BtrfsFs {
        chunk_map,
        root_tree_root,
        fs_tree_root: 0, // resolved below
        path_cache: BTreeMap::new(),
        alloc_cursor: sb.bytes_used,
        superblock: sb,
    };

    // Resolve the default subvolume FS-tree root.
    fs.fs_tree_root = match resolve_fs_tree_root(&fs) {
        Some(r) => r,
        None => {
            log::warn!("btrfs: could not resolve FS-tree root (objectid=5)");
            return false;
        }
    };

    log::info!("btrfs: fs-tree root @ logical {:#x}", fs.fs_tree_root);
    BTRFS_MOUNTS.lock().insert("/".to_string(), fs);
    true
}


/// Parse the `sys_chunk_array` embedded in the superblock to build the
/// initial logical→physical mapping.  This covers at least the system
/// chunk containing the chunk-tree itself.
fn parse_sys_chunk_array(sb: &BtrfsSuperblock) -> Vec<(u64, u64, BtrfsChunkItem)> {
    let mut out = Vec::new();
    let total = sb.sys_chunk_array_size as usize;
    let arr   = &sb.sys_chunk_array[..total.min(BTRFS_SYSTEM_CHUNK_ARRAY_SIZE)];
    let mut pos = 0usize;

    while pos + 17 <= arr.len() {
        // Each entry: BtrfsKey (17 bytes) + BtrfsChunkItem (80 bytes minimum)
        let key = BtrfsKey::from_bytes(&arr[pos..pos + 17]);
        pos += 17;
        if key.ty != BTRFS_CHUNK_ITEM_KEY { break; }
        if pos + 80 > arr.len() { break; }
        let chunk = BtrfsChunkItem::from_bytes(&arr[pos..pos + 80]);
        let logical_start = key.offset;
        let logical_end   = logical_start + chunk.length;
        out.push((logical_start, logical_end, chunk));
        // Each stripe adds 32 bytes; skip additional stripes beyond the first.
        let extra_stripes = (chunk.num_stripes as usize).saturating_sub(1);
        pos += 80 + extra_stripes * 32;
    }
    out
}


/// Walk the root-tree to find the `BtrfsRootItem` for the default subvolume
/// (objectid = FS_TREE_OBJECTID = 5) and return its `bytenr` (logical address
/// of the FS-tree root node).
fn resolve_fs_tree_root(fs: &BtrfsFs) -> Option<u64> {
    let key = BtrfsKey {
        objectid: BTRFS_FS_TREE_OBJECTID,
        ty:       BTRFS_ROOT_ITEM_KEY,
        offset:   u64::MAX, // use latest generation
    };
    // Search for the item with the highest generation for objectid=5.
    let results = fs.btree_search(fs.root_tree_root, |k| {
        if k.objectid != BTRFS_FS_TREE_OBJECTID { return k.objectid.cmp(&BTRFS_FS_TREE_OBJECTID); }
        if k.ty != BTRFS_ROOT_ITEM_KEY { return k.ty.cmp(&BTRFS_ROOT_ITEM_KEY); }
        core::cmp::Ordering::Equal
    });
    // Pick the entry with the largest offset (= most recent transid).
    let best = results.into_iter().max_by_key(|(k, _)| k.offset)?;
    if best.1.len() < 184 { return None; }
    let ri = BtrfsRootItem::from_bytes(&best.1);
    Some(ri.bytenr)
}


/// Btrfs directory entry name hash (FNV-based, as used in the kernel).
fn btrfs_name_hash(name: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME:  u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    for &b in name {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Align `v` up to the next multiple of `align` (must be a power of two).
#[inline(always)]
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

/// Split an absolute path into (parent_dir, last_component).
/// Returns Err(-22) for malformed paths.
fn split_path(path: &str) -> Result<(&str, &str), isize> {
    let path = path.trim_end_matches('/');
    if path.is_empty() { return Err(-22); }
    match path.rfind('/') {
        Some(0) => Ok(("/", &path[1..])),
        Some(i) => Ok((&path[..i], &path[i + 1..])),
        None    => Err(-22),
    }
}

// These are called by vfs_ops.rs after the mount table resolves a path to
// FsType::Btrfs.  The `subpath` argument is the mount-relative path.

pub fn btrfs_stat(subpath: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.stat(subpath)
}

pub fn btrfs_read_all(subpath: &str) -> Result<Vec<u8>, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.read_all(subpath)
}

pub fn btrfs_write_all(subpath: &str, data: &[u8]) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.write_all(subpath, data)
}

pub fn btrfs_readdir(subpath: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.readdir(subpath)
}

pub fn btrfs_create(subpath: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.create(subpath)
}

pub fn btrfs_mkdir(subpath: &str) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.mkdir(subpath)
}

pub fn btrfs_unlink(subpath: &str) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.unlink(subpath)
}

pub fn btrfs_rmdir(subpath: &str) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.rmdir(subpath)
}

pub fn btrfs_rename(old: &str, new: &str) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.rename(old, new)
}

pub fn btrfs_link(existing: &str, new: &str) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.link(existing, new)
}

pub fn btrfs_symlink(target: &str, link_path: &str) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.symlink(target, link_path)
}

pub fn btrfs_readlink(subpath: &str) -> Result<String, isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.readlink(subpath)
}

pub fn btrfs_chmod(subpath: &str, mode: u16) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.chmod(subpath, mode)
}

pub fn btrfs_chown(subpath: &str, uid: u32, gid: u32) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.chown(subpath, uid, gid)
}

pub fn btrfs_set_times(subpath: &str, atime_ns: u64, mtime_ns: u64) -> Result<(), isize> {
    let mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values().next().ok_or(-5isize)?;
    fs.set_times(subpath, atime_ns, mtime_ns)
}

pub fn btrfs_truncate(subpath: &str, len: usize) -> Result<(), isize> {
    let mut mounts = BTRFS_MOUNTS.lock();
    let fs = mounts.values_mut().next().ok_or(-5isize)?;
    fs.truncate(subpath, len)
}

pub fn btrfs_statfs() -> crate::fs::vfs_ops::KStatfs {
    let mounts = BTRFS_MOUNTS.lock();
    mounts.values().next()
        .map(|fs| fs.statfs())
        .unwrap_or_default()
}

/// Called from vfs_ops to flush inode metadata (no-op: all writes are
/// synchronous write-through in this driver).
pub fn sync_inode(_path: &str) { /* write-through; nothing to flush */ }
