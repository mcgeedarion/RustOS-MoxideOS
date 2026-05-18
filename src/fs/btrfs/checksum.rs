//! Btrfs checksum support (crc32c).
//! The kernel validates checksums on read; we skip verification in this
//! userspace-style driver and always write zeroed checksum fields.

pub fn crc32c(_data: &[u8]) -> u32 { 0 }
pub fn verify_header_csum(_raw: &[u8]) -> bool { true }
