extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;

fn block_read(lba: u64, count: u32) -> Vec<u8> {
    let mut buf = vec![0u8; count as usize * 512];
    crate::drivers::block::read_sectors(lba, count, &mut buf);
    buf
}

fn block_write(lba: u64, data: &[u8]) {
    debug_assert!(data.len() % 512 == 0);
    crate::drivers::block::write_sectors(lba, data);
}

pub const BTRFS_MAGIC: u64               = 0x4D5F53665248425F;
pub const BTRFS_SUPERBLOCK_OFFSET: u64   = 0x10000;
pub const BTRFS_SUPERBLOCK_SIZE: usize   = 4096;
pub const BTRFS_CSUM_SIZE: usize         = 32;
pub const BTRFS_FSID_SIZE: usize         = 16;
pub const BTRFS_UUID_SIZE: usize         = 16;
pub const BTRFS_LABEL_SIZE: usize        = 256;
pub const BTRFS_SYSTEM_CHUNK_ARRAY_SIZE: usize = 2048;

pub const BTRFS_ROOT_TREE_OBJECTID:     u64 = 1;
pub const BTRFS_EXTENT_TREE_OBJECTID:   u64 = 2;
pub const BTRFS_CHUNK_TREE_OBJECTID:    u64 = 3;
pub const BTRFS_FS_TREE_OBJECTID:       u64 = 5;
pub const BTRFS_ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const BTRFS_FIRST_FREE_OBJECTID:    u64 = 256;
pub const BTRFS_LAST_FREE_OBJECTID:     u64 = u64::MAX - 255;

pub const BTRFS_INODE_ITEM_KEY:    u8 = 1;
pub const BTRFS_INODE_REF_KEY:     u8 = 12;
pub const BTRFS_DIR_ITEM_KEY:      u8 = 84;
pub const BTRFS_DIR_INDEX_KEY:     u8 = 96;
pub const BTRFS_EXTENT_DATA_KEY:   u8 = 108;
pub const BTRFS_CHUNK_ITEM_KEY:    u8 = 228;
pub const BTRFS_ROOT_ITEM_KEY:     u8 = 132;
pub const BTRFS_ROOT_BACKREF_KEY:  u8 = 144;
pub const BTRFS_ROOT_REF_KEY:      u8 = 156;
pub const BTRFS_XATTR_ITEM_KEY:    u8 = 24;

pub const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
pub const BTRFS_FILE_EXTENT_REG:    u8 = 1;
pub const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

pub const BTRFS_FT_UNKNOWN:  u8 = 0;
pub const BTRFS_FT_REG_FILE: u8 = 1;
pub const BTRFS_FT_DIR:      u8 = 2;
pub const BTRFS_FT_SYMLINK:  u8 = 7;

pub const BTRFS_NODE_LEAF:     u8 = 1;
pub const BTRFS_NODE_INTERNAL: u8 = 0;
pub const BTRFS_MAX_LEAF_ITEMS: usize = 128;

pub const BTRFS_COMPRESS_NONE: u8 = 0;
pub const BTRFS_COMPRESS_ZLIB: u8 = 1;
pub const BTRFS_COMPRESS_LZO:  u8 = 2;
pub const BTRFS_COMPRESS_ZSTD: u8 = 3;

pub const S_IFMT:  u32 = 0xF000;
pub const S_IFREG: u32 = 0x8000;
pub const S_IFDIR: u32 = 0x4000;
pub const S_IFLNK: u32 = 0xA000;

#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    // followed by num_stripes BtrfsStripeItems
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsStripeItem {
    pub devid:  u64,
    pub offset: u64,
    pub dev_uuid: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsRootItem {
    pub inode:        [u8; 160],
    pub generation:   u64,
    pub root_dirid:   u64,
    pub bytenr:       u64,
    pub byte_limit:   u64,
    pub bytes_used:   u64,
    pub last_snapshot:u64,
    pub flags:        u64,
    pub refs:         u32,
    pub drop_progress:[u8; 17],
    pub drop_level:   u8,
    pub level:        u8,
    pub generation_v2:u64,
    pub uuid:         [u8; 16],
    pub parent_uuid:  [u8; 16],
    pub received_uuid:[u8; 16],
    pub ctransid:     u64,
    pub otransid:     u64,
    pub stransid:     u64,
    pub rtransid:     u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    pub root_dir_objectid:u64,
    pub num_devices:      u64,
    pub sectorsize:       u32,
    pub nodesize:         u32,
    pub leafsize:         u32,
    pub stripesize:       u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation:u64,
    pub compat_flags:     u64,
    pub compat_ro_flags:  u64,
    pub incompat_flags:   u64,
    pub csum_type:        u16,
    pub root_level:       u8,
    pub chunk_root_level: u8,
    pub log_root_level:   u8,
    pub dev_item:         [u8; 98],
    pub label:            [u8; 256],
    pub cache_generation: u64,
    pub uuid_tree_generation: u64,
    pub metadata_uuid:    [u8; 16],
    pub _reserved:        [u64; 28],
    pub sys_chunk_array:  [u8; 2048],
    pub super_roots:      [u8; 672],
    pub _unused:          [u8; 565],
}

pub use super::tree::BtrfsFs;

pub static BTRFS_MOUNTS: Mutex<BTreeMap<String, BtrfsFs>> =
    Mutex::new(BTreeMap::new());