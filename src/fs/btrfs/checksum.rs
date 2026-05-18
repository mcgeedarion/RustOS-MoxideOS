//! crc32c stub — checksums are zeroed on write, not verified on read.
pub fn crc32c(_data: &[u8]) -> u32 { 0 }
pub fn verify_header_csum(_raw: &[u8]) -> bool { true }
