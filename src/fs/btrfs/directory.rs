extern crate alloc;
use alloc::string::String;

#[derive(Clone, Debug)]
pub struct BtrfsDirItem {
    pub key: super::tree::BtrfsKey,
    pub transid: u64,
    pub data_len: u16,
    pub name_len: u16,
    pub ty: u8,
    pub name: String,
}
