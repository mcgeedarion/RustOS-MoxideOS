//! Btrfs inline compression stubs (zlib / lzo / zstd).
//! Compressed extents are not yet decompressed — they read as zeros.

extern crate alloc;

pub fn decompress(_algo: u8, _data: &[u8], uncompressed_size: usize) -> alloc::vec::Vec<u8> {
    alloc::vec![0u8; uncompressed_size]
}
