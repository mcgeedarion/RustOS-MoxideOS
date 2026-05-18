extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::tree::BtrfsKey;
use super::superblock::*;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct BtrfsFileExtentItem {
    pub generation:       u64,
    pub ram_bytes:        u64,
    pub compression:      u8,
    pub encryption:       u8,
    pub other_encoding:   u16,
    pub extent_type:      u8,
    // For REG/PREALLOC:
    pub disk_bytenr:      u64,
    pub disk_num_bytes:   u64,
    pub offset:           u64,
    pub num_bytes:        u64,
}

impl BtrfsFileExtentItem {
    pub fn from_bytes(b: &[u8]) -> Self {
        if b.len() < 21 {
            return BtrfsFileExtentItem {
                generation: 0, ram_bytes: 0, compression: 0,
                encryption: 0, other_encoding: 0,
                extent_type: super::superblock::BTRFS_FILE_EXTENT_INLINE,
                disk_bytenr: 0, disk_num_bytes: 0, offset: 0, num_bytes: 0,
            };
        }
        let extent_type = b[20];
        let (disk_bytenr, disk_num_bytes, offset, num_bytes) = if b.len() >= 53 {
            (
                u64::from_le_bytes(b[21..29].try_into().unwrap()),
                u64::from_le_bytes(b[29..37].try_into().unwrap()),
                u64::from_le_bytes(b[37..45].try_into().unwrap()),
                u64::from_le_bytes(b[45..53].try_into().unwrap()),
            )
        } else { (0, 0, 0, 0) };
        BtrfsFileExtentItem {
            generation:     u64::from_le_bytes(b[0..8].try_into().unwrap()),
            ram_bytes:      u64::from_le_bytes(b[8..16].try_into().unwrap()),
            compression:    b[16],
            encryption:     b[17],
            other_encoding: u16::from_le_bytes(b[18..20].try_into().unwrap()),
            extent_type,
            disk_bytenr, disk_num_bytes, offset, num_bytes,
        }
    }
}
