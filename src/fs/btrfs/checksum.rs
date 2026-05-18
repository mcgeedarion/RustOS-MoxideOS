//! Btrfs checksum support (crc32c).
//! Checksum validation is skipped in this driver; all written checksums are zeroed.

pub fn crc32c(_data: &[u8]) -> u32 { 0 }
pub fn verify_header_csum(_raw: &[u8]) -> bool { true }