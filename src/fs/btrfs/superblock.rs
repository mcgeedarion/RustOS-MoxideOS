extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use crate::block;

pub fn block_read(lba: u64, count: u32) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; count as usize * 512];
    let _ = crate::drivers::virtio_blk::read_lba(lba, count, &mut buf);
    buf
}
pub fn block_write(lba: u64, data: &[u8]) {
    let _ = crate::drivers::virtio_blk::write_lba(lba, data);
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
pub const BTRFS_FIRST_CHUNK_TREE_OBJECTID: u64 = 256;

pub const BTRFS_INODE_ITEM_KEY:       u8 = 1;
pub const BTRFS_INODE_REF_KEY:        u8 = 12;
pub const BTRFS_XATTR_ITEM_KEY:       u8 = 24;
pub const BTRFS_DIR_ITEM_KEY:         u8 = 84;
pub const BTRFS_DIR_INDEX_KEY:        u8 = 96;
pub const BTRFS_EXTENT_DATA_KEY:      u8 = 108;
pub const BTRFS_EXTENT_CSUM_KEY:      u8 = 128;
pub const BTRFS_ROOT_ITEM_KEY:        u8 = 132;
pub const BTRFS_ROOT_REF_KEY:         u8 = 156;
pub const BTRFS_EXTENT_ITEM_KEY:      u8 = 168;
pub const BTRFS_CHUNK_ITEM_KEY:       u8 = 228;
pub const BTRFS_DEV_ITEM_KEY:         u8 = 216;

pub const BTRFS_INODE_NODATASUM:  u64 = 1 << 0;
pub const BTRFS_INODE_NODATACOW:  u64 = 1 << 1;

pub const BTRFS_FILE_EXTENT_INLINE:    u8 = 0;
pub const BTRFS_FILE_EXTENT_REG:       u8 = 1;
pub const BTRFS_FILE_EXTENT_PREALLOC:  u8 = 2;

pub const BTRFS_NODE_LEAF:     u8 = 0;
pub const BTRFS_NODE_INTERNAL: u8 = 1;

pub const BTRFS_FT_UNKNOWN:  u8 = 0;
pub const BTRFS_FT_REG_FILE: u8 = 1;
pub const BTRFS_FT_DIR:      u8 = 2;
pub const BTRFS_FT_SYMLINK:  u8 = 7;

pub const BTRFS_COMPRESS_NONE:  u8 = 0;
pub const BTRFS_COMPRESS_ZLIB:  u8 = 1;
pub const BTRFS_COMPRESS_LZO:   u8 = 2;
pub const BTRFS_COMPRESS_ZSTD:  u8 = 3;

pub const BTRFS_MAX_LEAF_ITEMS: usize = 512;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct BtrfsChunkItem {
    pub length:        u64,
    pub owner:         u64,
    pub stripe_len:    u64,
    pub ty:            u64,
    pub io_align:      u32,
    pub io_width:      u32,
    pub sector_size:   u32,
    pub num_stripes:   u16,
    pub sub_stripes:   u16,
    pub stripe_devid:  u64,
    pub stripe_offset: u64,
}

impl BtrfsChunkItem {
    pub fn from_bytes(b: &[u8]) -> Self {
        BtrfsChunkItem {
            length:        u64::from_le_bytes(b[0..8].try_into().unwrap()),
            owner:         u64::from_le_bytes(b[8..16].try_into().unwrap()),
            stripe_len:    u64::from_le_bytes(b[16..24].try_into().unwrap()),
            ty:            u64::from_le_bytes(b[24..32].try_into().unwrap()),
            io_align:      u32::from_le_bytes(b[32..36].try_into().unwrap()),
            io_width:      u32::from_le_bytes(b[36..40].try_into().unwrap()),
            sector_size:   u32::from_le_bytes(b[40..44].try_into().unwrap()),
            num_stripes:   u16::from_le_bytes(b[44..46].try_into().unwrap()),
            sub_stripes:   u16::from_le_bytes(b[46..48].try_into().unwrap()),
            stripe_devid:  u64::from_le_bytes(b[48..56].try_into().unwrap()),
            stripe_offset: u64::from_le_bytes(b[56..64].try_into().unwrap()),
        }
    }
    pub fn physical_for(&self, logical_offset: u64) -> u64 {
        self.stripe_offset + (logical_offset % self.stripe_len)
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct BtrfsRootItem {
    pub inode:       [u8; 160],
    pub generation:  u64,
    pub root_dirid:  u64,
    pub bytenr:      u64,
    pub byte_limit:  u64,
    pub bytes_used:  u64,
    pub last_snapshot: u64,
    pub flags:       u64,
    pub refs:        u32,
}

impl BtrfsRootItem {
    pub fn from_bytes(b: &[u8]) -> Self {
        if b.len() < 184 { return Self::default(); }
        let mut inode = [0u8; 160];
        inode.copy_from_slice(&b[0..160]);
        BtrfsRootItem {
            inode,
            generation:    u64::from_le_bytes(b[160..168].try_into().unwrap()),
            root_dirid:    u64::from_le_bytes(b[168..176].try_into().unwrap()),
            bytenr:        u64::from_le_bytes(b[176..184].try_into().unwrap()),
            byte_limit:    0, bytes_used: 0, last_snapshot: 0, flags: 0, refs: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BtrfsSuperblock {
    pub csum:                 [u8; 32],
    pub fsid:                 [u8; 16],
    pub bytenr:               u64,
    pub flags:                u64,
    pub magic:                u64,
    pub generation:           u64,
    pub root:                 u64,
    pub chunk_root:           u64,
    pub log_root:             u64,
    pub log_root_transid:     u64,
    pub total_bytes:          u64,
    pub bytes_used:           u64,
    pub root_dir_objectid:    u64,
    pub num_devices:          u64,
    pub sectorsize:           u32,
    pub nodesize:             u32,
    pub leafsize:             u32,
    pub stripesize:           u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation: u64,
    pub compat_flags:         u64,
    pub compat_ro_flags:      u64,
    pub incompat_flags:       u64,
    pub csum_type:            u16,
    pub root_level:           u8,
    pub chunk_root_level:     u8,
    pub log_root_level:       u8,
    pub label:                [u8; 256],
    pub sys_chunk_array:      [u8; 2048],
}

impl BtrfsSuperblock {
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut csum  = [0u8; 32]; csum.copy_from_slice(&b[0..32]);
        let mut fsid  = [0u8; 16]; fsid.copy_from_slice(&b[32..48]);
        let mut label = [0u8; 256]; label.copy_from_slice(&b[299..555]);
        let mut sys_chunk_array = [0u8; 2048];
        sys_chunk_array.copy_from_slice(&b[2075..4123]);
        BtrfsSuperblock {
            csum, fsid,
            bytenr:               u64::from_le_bytes(b[48..56].try_into().unwrap()),
            flags:                u64::from_le_bytes(b[56..64].try_into().unwrap()),
            magic:                u64::from_le_bytes(b[64..72].try_into().unwrap()),
            generation:           u64::from_le_bytes(b[72..80].try_into().unwrap()),
            root:                 u64::from_le_bytes(b[80..88].try_into().unwrap()),
            chunk_root:           u64::from_le_bytes(b[88..96].try_into().unwrap()),
            log_root:             u64::from_le_bytes(b[96..104].try_into().unwrap()),
            log_root_transid:     u64::from_le_bytes(b[104..112].try_into().unwrap()),
            total_bytes:          u64::from_le_bytes(b[112..120].try_into().unwrap()),
            bytes_used:           u64::from_le_bytes(b[120..128].try_into().unwrap()),
            root_dir_objectid:    u64::from_le_bytes(b[128..136].try_into().unwrap()),
            num_devices:          u64::from_le_bytes(b[136..144].try_into().unwrap()),
            sectorsize:           u32::from_le_bytes(b[144..148].try_into().unwrap()),
            nodesize:             u32::from_le_bytes(b[148..152].try_into().unwrap()),
            leafsize:             u32::from_le_bytes(b[152..156].try_into().unwrap()),
            stripesize:           u32::from_le_bytes(b[156..160].try_into().unwrap()),
            sys_chunk_array_size: u32::from_le_bytes(b[160..164].try_into().unwrap()),
            chunk_root_generation: u64::from_le_bytes(b[164..172].try_into().unwrap()),
            compat_flags:         u64::from_le_bytes(b[172..180].try_into().unwrap()),
            compat_ro_flags:      u64::from_le_bytes(b[180..188].try_into().unwrap()),
            incompat_flags:       u64::from_le_bytes(b[188..196].try_into().unwrap()),
            csum_type:            u16::from_le_bytes(b[196..198].try_into().unwrap()),
            root_level:           b[198],
            chunk_root_level:     b[199],
            log_root_level:       b[200],
            label, sys_chunk_array,
        }
    }
    pub fn is_valid(&self) -> bool { self.magic == BTRFS_MAGIC }
}

pub static BTRFS_MOUNTS: Mutex<BTreeMap<String, super::tree::BtrfsFs>> =
    Mutex::new(BTreeMap::new());
