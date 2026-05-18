/// Btrfs file-extent item (BTRFS_EXTENT_DATA_KEY).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BtrfsFileExtentItem {
    pub generation:          u64,
    pub ram_bytes:           u64,
    pub compression:         u8,
    pub encryption:          u8,
    pub other_encoding:      u16,
    /// 0 = inline, 1 = regular, 2 = prealloc
    pub extent_type:         u8,
    // --- regular extent fields (only valid when extent_type != 0) ---
    pub disk_bytenr:         u64,
    pub disk_num_bytes:      u64,
    pub offset:              u64,
    pub num_bytes:           u64,
}