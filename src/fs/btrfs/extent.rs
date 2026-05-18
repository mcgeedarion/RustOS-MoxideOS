#[derive(Clone, Debug)]
pub struct BtrfsFileExtentItem {
    pub generation:       u64,
    pub ram_bytes:        u64,
    pub compression:      u8,
    pub encryption:       u8,
    pub other_encoding:   u16,
    pub ty:               u8,
    // inline data
    pub inline_data:      alloc::vec::Vec<u8>,
    // regular/prealloc
    pub disk_bytenr:      u64,
    pub disk_num_bytes:   u64,
    pub offset:           u64,
    pub num_bytes:        u64,
}
