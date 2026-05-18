extern crate alloc;
use alloc::string::String;
use super::tree::BtrfsKey;

pub struct BtrfsDirItem {
    pub child_key: BtrfsKey,
    pub transid:   u64,
    pub data_len:  u16,
    pub name_len:  u16,
    pub ty:        u8,
}

impl BtrfsDirItem {
    const FIXED_LEN: usize = 30;

    pub fn from_bytes(b: &[u8]) -> Self {
        BtrfsDirItem {
            child_key: BtrfsKey::from_bytes(&b[0..17]),
            transid:   u64::from_le_bytes(b[17..25].try_into().unwrap()),
            data_len:  u16::from_le_bytes(b[25..27].try_into().unwrap()),
            name_len:  u16::from_le_bytes(b[27..29].try_into().unwrap()),
            ty:        b[29],
        }
    }

    pub fn total_len(&self) -> usize {
        Self::FIXED_LEN + self.name_len as usize + self.data_len as usize
    }

    pub fn name<'a>(&self, b: &'a [u8]) -> &'a [u8] {
        &b[Self::FIXED_LEN .. Self::FIXED_LEN + self.name_len as usize]
    }
}