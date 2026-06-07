//! Filesystem recognizer — probes a block device's first sectors and
//! identifies which filesystem type it contains.
//!
//! Used by `mount::init_mounts` and `sys_mount` (when fstype = "auto")
//! to automatically select the right driver without requiring the caller
//! to specify the filesystem type explicitly.
//!
//! ## Detection order
//! 1. exFAT   — OEM ID "EXFAT   " at offset 3
//! 2. NTFS    — OEM ID "NTFS    " at offset 3
//! 3. ext4    — magic 0xEF53 at offset 0x438 (also covers ext2/ext3)
//! 4. FAT32   — OEM ID check + FAT32 extended boot sig + "FAT32" string
//! 5. FAT16   — same region, "FAT16" string
//! 6. Btrfs   — magic "_BHRfS_M" at offset 0x10040
//! 7. ISO 9660— "CD001" at offset 0x8001 (sector 16 + 1)
//!
//! Returns `None` if the sector data does not match any known filesystem.

extern crate alloc;
use crate::fs::mount::FsType;

const EXT_MAGIC_OFF: usize = 0x438;
const EXT_MAGIC: [u8; 2] = [0x53, 0xEF];

const FAT_OEM_OFF: usize = 3;
const FAT32_FS_TYPE_OFF: usize = 82;
const FAT16_FS_TYPE_OFF: usize = 54;
const FAT32_SIGN: &[u8] = b"FAT32   ";
const FAT16_SIGN: &[u8] = b"FAT16   ";

const EXFAT_OEM_OFF: usize = 3;
const EXFAT_OEM: &[u8] = b"EXFAT   ";

const NTFS_OEM_OFF: usize = 3;
const NTFS_OEM: &[u8] = b"NTFS    ";

const BTRFS_MAGIC_OFF: usize = 0x10040;
const BTRFS_MAGIC: &[u8] = b"_BHRfS_M";

const ISO_MAGIC_OFF: usize = 0x8001; // sector 16, byte 1
const ISO_MAGIC: &[u8] = b"CD001";

/// Probe the first bytes of a block device image and return the detected
pub fn probe(data: &[u8]) -> Option<FsType> {
    if data.len() > EXFAT_OEM_OFF + 8 {
        if &data[EXFAT_OEM_OFF..EXFAT_OEM_OFF + 8] == EXFAT_OEM {
            return Some(FsType::ExFat);
        }
    }

    // NTFS
    if data.len() > NTFS_OEM_OFF + 8 {
        if &data[NTFS_OEM_OFF..NTFS_OEM_OFF + 8] == NTFS_OEM {
            return Some(FsType::Ntfs);
        }
    }

    // ext2 / ext3 / ext4 — all share the same superblock magic
    if data.len() > EXT_MAGIC_OFF + 2 {
        if data[EXT_MAGIC_OFF..EXT_MAGIC_OFF + 2] == EXT_MAGIC {
            let incompat_off = 0x460usize;
            let is_ext4 = data.len() > incompat_off + 4 && {
                let f = u32::from_le_bytes(
                    data[incompat_off..incompat_off + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                f & 0x0040 != 0 // EXT4_FEATURE_INCOMPAT_EXTENTS
            };
            return Some(if is_ext4 { FsType::Ext4 } else { FsType::Ext2 });
        }
    }

    // FAT32
    if data.len() > FAT32_FS_TYPE_OFF + 8 {
        if &data[FAT32_FS_TYPE_OFF..FAT32_FS_TYPE_OFF + 8] == FAT32_SIGN {
            return Some(FsType::Fat32);
        }
    }

    // FAT16 (also catches FAT12 volumes labelled FAT16)
    if data.len() > FAT16_FS_TYPE_OFF + 8 {
        if &data[FAT16_FS_TYPE_OFF..FAT16_FS_TYPE_OFF + 8] == FAT16_SIGN {
            return Some(FsType::Fat32); // route through Fat32 driver
        }
    }

    // Btrfs — magic lives past the first 64 KiB
    if data.len() > BTRFS_MAGIC_OFF + 8 {
        if &data[BTRFS_MAGIC_OFF..BTRFS_MAGIC_OFF + 8] == BTRFS_MAGIC {
            return Some(FsType::Btrfs);
        }
    }

    // ISO 9660
    if data.len() > ISO_MAGIC_OFF + 5 {
        if &data[ISO_MAGIC_OFF..ISO_MAGIC_OFF + 5] == ISO_MAGIC {
            return Some(FsType::Cdfs);
        }
    }

    None
}

/// Convenience: return a human-readable name for logging.
pub fn fs_type_name(fstype: &FsType) -> &'static str {
    match fstype {
        FsType::Ext2 => "ext2/ext3",
        FsType::Ext4 => "ext4",
        FsType::Fat32 => "fat32/fat16",
        FsType::ExFat => "exfat",
        FsType::Ntfs => "ntfs (ro)",
        FsType::Btrfs => "btrfs",
        FsType::Cdfs => "iso9660",
        FsType::Tmpfs => "tmpfs",
        FsType::Overlayfs => "overlayfs",
        FsType::Devfs => "devfs",
        FsType::Procfs => "procfs",
        FsType::Sysfs => "sysfs",
        FsType::Cgroupfs => "cgroupfs",
    }
}
