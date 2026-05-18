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


const BTRFS_MAGIC: u64               = 0x4D5F53665248425F;
const BTRFS_SUPERBLOCK_OFFSET: u64   = 0x10000;
const BTRFS_SUPERBLOCK_SIZE: usize   = 4096;
const BTRFS_CSUM_SIZE: usize         = 32;
const BTRFS_FSID_SIZE: usize         = 16;
const BTRFS_UUID_SIZE: usize         = 16;
const BTRFS_LABEL_SIZE: usize        = 256;
const BTRFS_SYSTEM_CHUNK_ARRAY_SIZE: usize = 2048;

const BTRFS_ROOT_TREE_OBJECTID:     u64 = 1;
const BTRFS_EXTENT_TREE_OBJECTID:   u64 = 2;
const BTRFS_CHUNK_TREE_OBJECTID:    u64 = 3;
const BTRFS_FS_TREE_OBJECTID:       u64 = 5;
const BTRFS_ROOT_TREE_DIR_OBJECTID: u64 = 6;
const BTRFS_FIRST_FREE_OBJECTID:    u64 = 256;
const BTRFS_LAST_FREE_OBJECTID:     u64 = u64::MAX - 255;

const BTRFS_INODE_ITEM_KEY:   u8 = 1;
const BTRFS_DIR_ITEM_KEY:     u8 = 84;
const BTRFS_DIR_INDEX_KEY:    u8 = 96;
const BTRFS_EXTENT_DATA_KEY:  u8 = 108;
const BTRFS_ROOT_ITEM_KEY:    u8 = 132;
const BTRFS_CHUNK_ITEM_KEY:   u8 = 228;

const BTRFS_FT_UNKNOWN:  u8 = 0;
const BTRFS_FT_REG_FILE: u8 = 1;
const BTRFS_FT_DIR:      u8 = 2;
const BTRFS_FT_SYMLINK:  u8 = 7;

const BTRFS_FILE_EXTENT_INLINE:  u8 = 0;
const BTRFS_FILE_EXTENT_REG:     u8 = 1;
const BTRFS_FILE_EXTENT_PREALLOC:u8 = 2;

const BTRFS_NODE_LEAF:     u8 = 1;
const BTRFS_NODE_INTERNAL: u8 = 0;

const BTRFS_MAX_LEAF_ITEMS: usize = 256;

const BTRFS_COMPRESS_NONE:  u8 = 0;
const BTRFS_COMPRESS_ZLIB:  u8 = 1;
const BTRFS_COMPRESS_LZO:   u8 = 2;
const BTRFS_COMPRESS_ZSTD:  u8 = 3;

const S_IFMT:   u32 = 0xF000;
const S_IFREG:  u32 = 0x8000;
const S_IFDIR:  u32 = 0x4000;
const S_IFLNK:  u32 = 0xA000;


#[derive(Clone, Debug, Default)]
pub struct BtrfsChunkItem {
    pub length:          u64,
    pub owner:           u64,
    pub stripe_len:      u64,
    pub ty:              u64,
    pub io_align:        u32,
    pub io_width:        u32,
    pub sector_size:     u32,
    pub num_stripes:     u16,
    pub sub_stripes:     u16,
    /// Physical start of stripe 0.
    pub stripe_devid:    u64,
    pub stripe_offset:   u64,
}

#[derive(Clone, Debug, Default)]
pub struct BtrfsRootItem {
    pub inode:            super::inode::BtrfsInodeItem,
    pub expected_generation: u64,
    pub objid:            u64,
    pub bytenr:           u64,
    pub byte_limit:       u64,
    pub bytes_used:       u64,
    pub last_snapshot:    u64,
    pub flags:            u64,
    pub refs:             u32,
    pub level:            u8,
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

pub static BTRFS_MOUNTS: Mutex<BTreeMap<String, super::tree::BtrfsFs>> = Mutex::new(BTreeMap::new());
