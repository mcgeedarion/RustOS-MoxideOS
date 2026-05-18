//! Btrfs inline compression stubs (zlib/lzo/zstd).
//! Decompression is not yet implemented; compressed extents read as zeros.

pub fn decompress(_algo: u8, _data: &[u8], _uncompressed_size: usize)
    -> alloc::vec::Vec<u8>
{
    alloc::vec![0u8; _uncompressed_size]
}
