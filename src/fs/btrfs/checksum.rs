//! Btrfs checksum support (crc32c).

const BTRFS_CSUM_SIZE: usize = 32;

const CRC32C_TABLE: [u32; 256] = make_crc32c_table();

const fn make_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;

    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;

        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x82f6_3b78;
            } else {
                crc >>= 1;
            }

            bit += 1;
        }

        table[i] = crc;
        i += 1;
    }

    table
}

/// Compute CRC32C using the Castagnoli polynomial.
///
/// Btrfs uses CRC32C for the classic metadata checksum type. The returned
/// value is the finalized checksum value, ready to compare against the
/// little-endian checksum bytes stored in a Btrfs block header.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;

    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xff) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[index];
    }

    !crc
}

/// Verify a Btrfs metadata block header checksum.
///
/// The first 32 bytes of every Btrfs metadata block are reserved for the
/// checksum field. For CRC32C, Btrfs stores the 4-byte checksum in little-endian
/// order at the start of that field, then computes the checksum over the rest
/// of the raw block.
pub fn verify_header_csum(raw: &[u8]) -> bool {
    if raw.len() <= BTRFS_CSUM_SIZE {
        return false;
    }

    let expected = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let actual = crc32c(&raw[BTRFS_CSUM_SIZE..]);

    expected == actual
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn verify_header_csum_rejects_short_blocks() {
        assert!(!verify_header_csum(&[]));
        assert!(!verify_header_csum(&[0; BTRFS_CSUM_SIZE]));
    }

    #[test]
    fn verify_header_csum_accepts_matching_block() {
        let mut raw = [0u8; 128];

        for (index, byte) in raw[BTRFS_CSUM_SIZE..].iter_mut().enumerate() {
            *byte = index as u8;
        }

        let checksum = crc32c(&raw[BTRFS_CSUM_SIZE..]).to_le_bytes();
        raw[..4].copy_from_slice(&checksum);

        assert!(verify_header_csum(&raw));
    }

    #[test]
    fn verify_header_csum_rejects_mismatched_block() {
        let mut raw = [0u8; 128];
        let checksum = crc32c(&raw[BTRFS_CSUM_SIZE..]).to_le_bytes();

        raw[..4].copy_from_slice(&checksum);
        raw[BTRFS_CSUM_SIZE] ^= 0xff;

        assert!(!verify_header_csum(&raw));
    }
}
