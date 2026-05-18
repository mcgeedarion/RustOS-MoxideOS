//! Btrfs compression stubs (zlib/lzo/zstd). Compressed extents read as zeros.
extern crate alloc;
pub fn decompress(_algo: u8, _data: &[u8], sz: usize) -> alloc::vec::Vec<u8> {
    alloc::vec![0u8; sz]
}
