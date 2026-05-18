extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;
use super::tree::{BtrfsFs, BtrfsKey};
use super::superblock::*;

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct BtrfsInodeItem {
    pub generation:     u64,
    pub transid:        u64,
    pub size:           u64,
    pub nbytes:         u64,
    pub block_group:    u64,
    pub nlink:          u32,
    pub uid:            u32,
    pub gid:            u32,
    pub mode:           u32,
    pub rdev:           u64,
    pub flags:          u64,
    pub sequence:       u64,
    pub atime_sec:      u64,
    pub atime_nsec:     u32,
    pub ctime_sec:      u64,
    pub ctime_nsec:     u32,
    pub mtime_sec:      u64,
    pub mtime_nsec:     u32,
    pub otime_sec:      u64,
    pub otime_nsec:     u32,
}

impl BtrfsInodeItem {
    pub fn from_bytes(b: &[u8]) -> Self {
        if b.len() < 160 { return Self::default(); }
        BtrfsInodeItem {
            generation:  u64::from_le_bytes(b[0..8].try_into().unwrap()),
            transid:     u64::from_le_bytes(b[8..16].try_into().unwrap()),
            size:        u64::from_le_bytes(b[16..24].try_into().unwrap()),
            nbytes:      u64::from_le_bytes(b[24..32].try_into().unwrap()),
            block_group: u64::from_le_bytes(b[32..40].try_into().unwrap()),
            nlink:       u32::from_le_bytes(b[40..44].try_into().unwrap()),
            uid:         u32::from_le_bytes(b[44..48].try_into().unwrap()),
            gid:         u32::from_le_bytes(b[48..52].try_into().unwrap()),
            mode:        u32::from_le_bytes(b[52..56].try_into().unwrap()),
            rdev:        u64::from_le_bytes(b[56..64].try_into().unwrap()),
            flags:       u64::from_le_bytes(b[64..72].try_into().unwrap()),
            sequence:    u64::from_le_bytes(b[72..80].try_into().unwrap()),
            atime_sec:   u64::from_le_bytes(b[112..120].try_into().unwrap()),
            atime_nsec:  u32::from_le_bytes(b[120..124].try_into().unwrap()),
            ctime_sec:   u64::from_le_bytes(b[124..132].try_into().unwrap()),
            ctime_nsec:  u32::from_le_bytes(b[132..136].try_into().unwrap()),
            mtime_sec:   u64::from_le_bytes(b[136..144].try_into().unwrap()),
            mtime_nsec:  u32::from_le_bytes(b[144..148].try_into().unwrap()),
            otime_sec:   u64::from_le_bytes(b[148..156].try_into().unwrap()),
            otime_nsec:  u32::from_le_bytes(b[156..160].try_into().unwrap()),
        }
    }
}
