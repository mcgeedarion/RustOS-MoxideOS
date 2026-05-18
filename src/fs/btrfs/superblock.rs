//! Btrfs filesystem driver — read/write, extent-mapped, copy-on-write.
//!
//! ## Architecture
//!
//! ```text
//!  VFS
//!   └─ btrfs::mount()         reads the superblock, builds chunk map, finds fs-tree root
//!       └─ BtrfsFs struct        owns all per-mount state
//!           ├─ logical_to_physical  translates logical byte offsets via chunk map
//!           ├─ btree_search         traverses B-tree nodes recursively
//!           ├─ read_inode_data      follows extent items to read file data
//!           └─ write_inode_data     CoW write: alloc pages, update extent/inode trees
//! ```

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

// Item-type constants
const BTRFS_INODE_ITEM_KEY:    u8 = 1;
const BTRFS_INODE_REF_KEY:     u8 = 12;
const BTRFS_DIR_ITEM_KEY:      u8 = 84;
const BTRFS_DIR_INDEX_KEY:     u8 = 96;
const BTRFS_EXTENT_DATA_KEY:   u8 = 108;
const BTRFS_CSUM_ITEM_KEY:     u8 = 120;
const BTRFS_ROOT_ITEM_KEY:     u8 = 132;
const BTRFS_CHUNK_ITEM_KEY:    u8 = 228;
const BTRFS_DEV_ITEM_KEY:      u8 = 216;
const BTRFS_DEV_EXTENT_KEY:    u8 = 204;

// Extent types
const BTRFS_FILE_EXTENT_INLINE:  u8 = 0;
const BTRFS_FILE_EXTENT_REG:     u8 = 1;
const BTRFS_FILE_EXTENT_PREALLOC:u8 = 2;

// Node flags
const BTRFS_NODE_LEAF:     u8 = 0;
const BTRFS_NODE_INTERNAL: u8 = 1;

const BTRFS_MAX_LEAF_ITEMS: usize = 128;

// Inode mode bits
const S_IFMT:   u32 = 0o170000;
const S_IFREG:  u32 = 0o100000;
const S_IFDIR:  u32 = 0o040000;
const S_IFLNK:  u32 = 0o120000;

// btrfs name hash (FNV-like used by kernel)
fn btrfs_name_hash(name: &[u8]) -> u64 {
    let mut h: u64 = 0xD2A98B26625EEE7B;
    for &b in name {
        h = h.wrapping_mul(0x1000193).wrapping_add(b as u64);
    }
    h
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub ty:       u8,
    pub offset:   u64,
}

impl BtrfsKey {
    pub fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        BtrfsKey { objectid, ty, offset }
    }
    fn from_bytes(b: &[u8]) -> Self {
        BtrfsKey {
            objectid: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            ty:       b[8],
            offset:   u64::from_le_bytes(b[9..17].try_into().unwrap()),
        }
    }
    fn lt_search(&self, other: &BtrfsKey) -> bool {
        (self.objectid, self.ty, self.offset) < (other.objectid, other.ty, other.offset)
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsInodeItem {
    pub generation: u64,
    pub transid:    u64,
    pub size:       u64,
    pub nbytes:     u64,
    pub block_group:u64,
    pub nlink:      u32,
    pub uid:        u32,
    pub gid:        u32,
    pub mode:       u32,
    pub rdev:       u64,
    pub flags:      u64,
    pub sequence:   u64,
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
        let r64 = |o: usize| u64::from_le_bytes(b[o..o+8].try_into().unwrap());
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
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
            atime_sec:   r64(152), atime_nsec: r32(160),
            ctime_sec:   r64(164), ctime_nsec: r32(172),
            mtime_sec:   r64(176), mtime_nsec: r32(184),
            otime_sec:   r64(188), otime_nsec: r32(196),
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 160];
        let w64 = |b: &mut Vec<u8>, o, v: u64| b[o..o+8].copy_from_slice(&v.to_le_bytes());
        let w32 = |b: &mut Vec<u8>, o, v: u32| b[o..o+4].copy_from_slice(&v.to_le_bytes());
        w64(&mut b, 0,  self.generation);
        w64(&mut b, 8,  self.transid);
        w64(&mut b, 16, self.size);
        w64(&mut b, 24, self.nbytes);
        w64(&mut b, 32, self.block_group);
        w32(&mut b, 40, self.nlink);
        w32(&mut b, 44, self.uid);
        w32(&mut b, 48, self.gid);
        w32(&mut b, 52, self.mode);
        w64(&mut b, 56, self.rdev);
        w64(&mut b, 64, self.flags);
        w64(&mut b, 72, self.sequence);
        b
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsDirItem {
    pub child_key:    BtrfsKey,
    pub transid:      u64,
    pub data_len:     u16,
    pub name_len:     u16,
    pub ty:           u8,
    pub name:         String,
}

impl BtrfsDirItem {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 30 { return None; }
        let child_key = BtrfsKey::from_bytes(&b[0..17]);
        let transid   = u64::from_le_bytes(b[17..25].try_into().ok()?);
        let data_len  = u16::from_le_bytes(b[25..27].try_into().ok()?);
        let name_len  = u16::from_le_bytes(b[27..29].try_into().ok()?);
        let ty        = b[29];
        let start     = 30;
        let end       = start + name_len as usize;
        if end > b.len() { return None; }
        let name = String::from_utf8_lossy(&b[start..end]).into_owned();
        Some(BtrfsDirItem { child_key, transid, data_len, name_len, ty, name })
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsFileExtentItem {
    pub generation:        u64,
    pub ram_bytes:         u64,
    pub compression:       u8,
    pub encryption:        u8,
    pub other_encoding:    u16,
    pub ty:                u8,
    // inline data (ty == INLINE)
    pub inline_data:       Vec<u8>,
    // regular/prealloc fields
    pub disk_bytenr:       u64,
    pub disk_num_bytes:    u64,
    pub extent_offset:     u64,
    pub num_bytes:         u64,
}

impl BtrfsFileExtentItem {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 13 { return None; }
        let generation     = u64::from_le_bytes(b[0..8].try_into().ok()?);
        let ram_bytes      = u64::from_le_bytes(b[8..16].try_into().ok()?);
        let compression    = b[16];
        let encryption     = b[17];
        let other_encoding = u16::from_le_bytes(b[18..20].try_into().ok()?);
        let ty             = b[20];
        let (inline_data, disk_bytenr, disk_num_bytes, extent_offset, num_bytes) =
            if ty == BTRFS_FILE_EXTENT_INLINE {
                (b[21..].to_vec(), 0, 0, 0, 0)
            } else if b.len() >= 53 {
                (
                    Vec::new(),
                    u64::from_le_bytes(b[21..29].try_into().ok()?),
                    u64::from_le_bytes(b[29..37].try_into().ok()?),
                    u64::from_le_bytes(b[37..45].try_into().ok()?),
                    u64::from_le_bytes(b[45..53].try_into().ok()?),
                )
            } else { return None; };
        Some(BtrfsFileExtentItem {
            generation, ram_bytes, compression, encryption, other_encoding, ty,
            inline_data, disk_bytenr, disk_num_bytes, extent_offset, num_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsChunkItem {
    pub length:       u64,
    pub owner:        u64,
    pub stripe_len:   u64,
    pub ty:           u64,
    pub io_align:     u32,
    pub io_width:     u32,
    pub sector_size:  u32,
    pub num_stripes:  u16,
    pub sub_stripes:  u16,
    // first stripe
    pub dev_id:       u64,
    pub offset:       u64,
    pub dev_uuid:     [u8; 16],
}

impl BtrfsChunkItem {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 80 { return None; }
        let r64 = |o: usize| u64::from_le_bytes(b[o..o+8].try_into().unwrap());
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        let mut dev_uuid = [0u8; 16];
        dev_uuid.copy_from_slice(&b[64..80]);
        Some(BtrfsChunkItem {
            length: r64(0), owner: r64(8), stripe_len: r64(16), ty: r64(24),
            io_align: r32(32), io_width: r32(36), sector_size: r32(40),
            num_stripes: r16(44), sub_stripes: r16(46),
            dev_id: r64(48), offset: r64(56), dev_uuid,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsRootItem {
    pub inode:          BtrfsInodeItem,
    pub generation:     u64,
    pub root_dirid:     u64,
    pub bytenr:         u64,
    pub byte_limit:     u64,
    pub bytes_used:     u64,
    pub last_snapshot:  u64,
    pub flags:          u64,
    pub refs:           u32,
    pub drop_progress:  BtrfsKey,
    pub drop_level:     u8,
    pub level:          u8,
}

impl BtrfsRootItem {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 256 { return None; }
        let r64 = |o: usize| u64::from_le_bytes(b[o..o+8].try_into().unwrap());
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let inode = BtrfsInodeItem::from_bytes(&b[0..160]);
        Some(BtrfsRootItem {
            inode,
            generation:    r64(160),
            root_dirid:    r64(168),
            bytenr:        r64(176),
            byte_limit:    r64(184),
            bytes_used:    r64(192),
            last_snapshot: r64(200),
            flags:         r64(208),
            refs:          r32(216),
            drop_progress: BtrfsKey::from_bytes(&b[220..237]),
            drop_level:    b[237],
            level:         b[238],
        })
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsSuperblock {
    pub csum:             [u8; 32],
    pub fsid:             [u8; 16],
    pub bytenr:           u64,
    pub flags:            u64,
    pub magic:            u64,
    pub generation:       u64,
    pub root:             u64,
    pub chunk_root:       u64,
    pub log_root:         u64,
    pub log_root_transid: u64,
    pub total_bytes:      u64,
    pub bytes_used:       u64,
    pub root_dir_objectid: u64,
    pub num_devices:      u64,
    pub sectorsize:       u32,
    pub nodesize:         u32,
    pub leafsize:         u32,
    pub stripesize:       u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation: u64,
    pub compat_flags:     u64,
    pub compat_ro_flags:  u64,
    pub incompat_flags:   u64,
    pub csum_type:        u16,
    pub root_level:       u8,
    pub chunk_root_level: u8,
    pub log_root_level:   u8,
    pub label:            [u8; 256],
    pub sys_chunk_array:  [u8; 2048],
}

impl BtrfsSuperblock {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < BTRFS_SUPERBLOCK_SIZE { return None; }
        let r64 = |o: usize| u64::from_le_bytes(b[o..o+8].try_into().unwrap());
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        let magic = r64(64);
        if magic != BTRFS_MAGIC { return None; }
        let mut csum = [0u8; 32]; csum.copy_from_slice(&b[0..32]);
        let mut fsid = [0u8; 16]; fsid.copy_from_slice(&b[32..48]);
        let mut label = [0u8; 256]; label.copy_from_slice(&b[299..555]);
        let mut sys_chunk_array = [0u8; 2048];
        sys_chunk_array.copy_from_slice(&b[2048..4096]);
        Some(BtrfsSuperblock {
            csum, fsid,
            bytenr:           r64(48),
            flags:            r64(56),
            magic,
            generation:       r64(72),
            root:             r64(80),
            chunk_root:       r64(88),
            log_root:         r64(96),
            log_root_transid: r64(104),
            total_bytes:      r64(112),
            bytes_used:       r64(120),
            root_dir_objectid: r64(128),
            num_devices:      r64(136),
            sectorsize:       r32(144),
            nodesize:         r32(148),
            leafsize:         r32(152),
            stripesize:       r32(156),
            sys_chunk_array_size: r32(160),
            chunk_root_generation: r64(168),
            compat_flags:     r64(176),
            compat_ro_flags:  r64(184),
            incompat_flags:   r64(192),
            csum_type:        r16(200),
            root_level:       b[202],
            chunk_root_level: b[203],
            log_root_level:   b[204],
            label, sys_chunk_array,
        })
    }
}

struct BtrfsHeader {
    csum:       [u8; 32],
    fsid:       [u8; 16],
    bytenr:     u64,
    flags:      u64,
    chunk_tree_uuid: [u8; 16],
    generation: u64,
    owner:      u64,
    nritems:    u32,
    level:      u8,
}

impl BtrfsHeader {
    fn from_bytes(b: &[u8]) -> Self {
        let r64 = |o: usize| u64::from_le_bytes(b[o..o+8].try_into().unwrap());
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let mut csum = [0u8; 32]; csum.copy_from_slice(&b[0..32]);
        let mut fsid = [0u8; 16]; fsid.copy_from_slice(&b[32..48]);
        let mut chunk_tree_uuid = [0u8; 16]; chunk_tree_uuid.copy_from_slice(&b[64..80]);
        BtrfsHeader {
            csum, fsid,
            bytenr:     r64(48),
            flags:      r64(56),
            chunk_tree_uuid,
            generation: r64(80),
            owner:      r64(88),
            nritems:    r32(96),
            level:      b[100],
        }
    }
}

const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_ITEM_SIZE:   usize = 25;
const BTRFS_KEY_PTR_SIZE:usize = 33;

struct BtrfsItem {
    key:    BtrfsKey,
    offset: u32,
    size:   u32,
}

impl BtrfsItem {
    fn from_bytes(b: &[u8]) -> Self {
        BtrfsItem {
            key:    BtrfsKey::from_bytes(&b[0..17]),
            offset: u32::from_le_bytes(b[17..21].try_into().unwrap()),
            size:   u32::from_le_bytes(b[21..25].try_into().unwrap()),
        }
    }
}

struct BtrfsKeyPtr {
    key:        BtrfsKey,
    block_ptr:  u64,
    generation: u64,
}

impl BtrfsKeyPtr {
    fn from_bytes(b: &[u8]) -> Self {
        BtrfsKeyPtr {
            key:        BtrfsKey::from_bytes(&b[0..17]),
            block_ptr:  u64::from_le_bytes(b[17..25].try_into().unwrap()),
            generation: u64::from_le_bytes(b[25..33].try_into().unwrap()),
        }
    }
}

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

pub static BTRFS_MOUNTS: Mutex<BTreeMap<String, BtrfsFs>> = Mutex::new(BTreeMap::new());
