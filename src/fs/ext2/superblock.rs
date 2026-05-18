extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;

fn block_read(lba: u64, count: u32) -> Vec<u8> {
    let mut buf = vec![0u8; count as usize * 512];
    crate::drivers::block::read_sectors(lba, count, &mut buf);
    buf
}

fn block_write(lba: u64, data: &[u8]) {
    debug_assert!(data.len() % 512 == 0);
    crate::drivers::block::write_sectors(lba, data);
}

// Ext2 on-disk constants ────────────────────────────────────────────────────
const EXT2_SIGNATURE:      u16 = 0xEF53;
const EXT2_ROOT_INODE:     u32 = 2;
const EXT2_GOOD_OLD_INODE_SIZE: u16 = 128;

// File type bits (mode & 0xF000)
const S_IFMT:   u16 = 0xF000;
const S_IFSOCK: u16 = 0xC000;
const S_IFLNK:  u16 = 0xA000;
const S_IFREG:  u16 = 0x8000;
const S_IFBLK:  u16 = 0x6000;
const S_IFDIR:  u16 = 0x4000;
const S_IFCHR:  u16 = 0x2000;
const S_IFIFO:  u16 = 0x1000;

// Directory entry file-type byte
const EXT2_FT_UNKNOWN:  u8 = 0;
const EXT2_FT_REG_FILE: u8 = 1;
const EXT2_FT_DIR:      u8 = 2;
const EXT2_FT_CHRDEV:   u8 = 3;
const EXT2_FT_BLKDEV:   u8 = 4;
const EXT2_FT_FIFO:     u8 = 5;
const EXT2_FT_SOCK:     u8 = 6;
const EXT2_FT_SYMLINK:  u8 = 7;

// Inode flags
const EXT4_EXTENTS_FL: u32 = 0x80000;

// Ext4 extent header magic
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

/// Parsed superblock.
#[derive(Clone, Debug)]
pub struct Superblock {
    pub s_inodes_count:       u32,
    pub s_blocks_count:       u32,
    pub s_r_blocks_count:     u32,
    pub s_free_blocks_count:  u32,
    pub s_free_inodes_count:  u32,
    pub s_first_data_block:   u32,
    pub s_log_block_size:     u32,
    pub s_log_frag_size:      u32,
    pub s_blocks_per_group:   u32,
    pub s_frags_per_group:    u32,
    pub s_inodes_per_group:   u32,
    pub s_mtime:              u32,
    pub s_wtime:              u32,
    pub s_mnt_count:          u16,
    pub s_max_mnt_count:      u16,
    pub s_magic:              u16,
    pub s_state:              u16,
    pub s_errors:             u16,
    pub s_minor_rev_level:    u16,
    pub s_lastcheck:          u32,
    pub s_checkinterval:      u32,
    pub s_creator_os:         u32,
    pub s_rev_level:          u32,
    pub s_def_resuid:         u16,
    pub s_def_resgid:         u16,
    // Extended superblock (rev >= 1)
    pub s_first_ino:          u32,
    pub s_inode_size:         u16,
    pub s_block_group_nr:     u16,
    pub s_feature_compat:     u32,
    pub s_feature_incompat:   u32,
    pub s_feature_ro_compat:  u32,
    pub s_uuid:               [u8; 16],
    pub s_volume_name:        [u8; 16],
    pub block_size:           u32,   // computed: 1024 << s_log_block_size
}

#[derive(Clone, Debug)]
pub struct BgDesc {
    pub bg_block_bitmap:       u32,
    pub bg_inode_bitmap:       u32,
    pub bg_inode_table:        u32,
    pub bg_free_blocks_count:  u16,
    pub bg_free_inodes_count:  u16,
    pub bg_used_dirs_count:    u16,
    pub bg_pad:                u16,
}

#[derive(Clone, Debug, Default)]
pub struct Inode {
    pub i_mode:       u16,
    pub i_uid:        u16,
    pub i_size:       u32,
    pub i_atime:      u32,
    pub i_ctime:      u32,
    pub i_mtime:      u32,
    pub i_dtime:      u32,
    pub i_gid:        u16,
    pub i_links_count:u16,
    pub i_blocks:     u32,
    pub i_flags:      u32,
    pub i_block:      [u32; 15],
    pub i_file_acl:   u32,
    pub i_dir_acl:    u32,
    pub i_size_high:  u32,
    pub i_uid_high:   u16,
    pub i_gid_high:   u16,
    pub i_extra_isize:u16,
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub inode:     u32,
    pub rec_len:   u16,
    pub name_len:  u8,
    pub file_type: u8,
    pub name:      String,
}

/// Stat result returned to userspace.
#[derive(Clone, Debug, Default)]
pub struct Ext2Stat {
    pub ino:     u64,
    pub mode:    u16,
    pub nlink:   u32,
    pub uid:     u32,
    pub gid:     u32,
    pub size:    u64,
    pub blksize: u64,
    pub blocks:  u64,
    pub atime:   u64,
    pub mtime:   u64,
    pub ctime:   u64,
    pub rdev:    u32,
}

/// Statfs result.
#[derive(Clone, Debug, Default)]
pub struct Ext2Statfs {
    pub bsize:   u64,
    pub blocks:  u64,
    pub bfree:   u64,
    pub bavail:  u64,
    pub files:   u64,
    pub ffree:   u64,
    pub namelen: u64,
}

/// Live filesystem handle.
#[derive(Clone, Debug)]
pub struct Ext2Fs {
    /// Parsed superblock.
    pub sb: Superblock,
    /// LBA offset of the first byte of the partition on disk.
    pub part_lba: u64,
    /// inode → Inode cache.
    pub inode_cache: BTreeMap<u32, Inode>,
}

/// Global mounted ext2 filesystem (one partition for now).
pub static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);

// ── Low-level block/inode I/O ─────────────────────────────────────────────

#[inline]
fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off+4].try_into().unwrap_or([0;4]))
}
#[inline]
fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off+2].try_into().unwrap_or([0;2]))
}
