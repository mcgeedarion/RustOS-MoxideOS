//! Btrfs crc32c stub — checksums are not validated in this driver.
pub fn crc32c(_data: &[u8]) -> u32 { 0 }
pub fn verify_header_csum(_raw: &[u8]) -> bool { true }
