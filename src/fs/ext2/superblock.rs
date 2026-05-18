extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

pub const ENOENT:    i32 = -2;
pub const EIO:       i32 = -5;
pub const EEXIST:    i32 = -17;
pub const ENOTDIR:   i32 = -20;
pub const EISDIR:    i32 = -21;
pub const EINVAL:    i32 = -22;
pub const ENOSPC:    i32 = -28;
pub const EROFS:     i32 = -30;
pub const ENOTEMPTY: i32 = -39;
pub const ELOOP:     i32 = -40;

pub const MAX_IMAGE_BYTES:   usize = 512 * 1024 * 1024;
pub const MAX_FILE_SIZE:     usize = 512 * 1024 * 1024;
pub const MAX_SYMLINK_DEPTH: usize = 8;
pub const EXT2_MAGIC:        u16   = 0xEF53;
pub const EXT2_ROOT_INO:     u32   = 2;

const INCOMPAT_FILETYPE:   u32 = 0x0002;
const INCOMPAT_RECOVER:    u32 = 0x0004;
const INCOMPAT_DIR_INDEX:  u32 = 0x0010;
const INCOMPAT_META_BG:    u32 = 0x0010;
const INCOMPAT_HANDLED:    u32 =
    INCOMPAT_FILETYPE | INCOMPAT_RECOVER | INCOMPAT_DIR_INDEX;

const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_BTREE_DIR:  u32 = 0x0004;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Superblock {
    pub inodes_count:       u32,
    pub blocks_count:       u32,
    pub r_blocks_count:     u32,
    pub free_blocks_count:  u32,
    pub free_inodes_count:  u32,
    pub first_data_block:   u32,
    pub log_block_size:     u32,
    pub log_frag_size:      u32,
    pub blocks_per_group:   u32,
    pub frags_per_group:    u32,
    pub inodes_per_group:   u32,
    pub mtime:              u32,
    pub wtime:              u32,
    pub mnt_count:          u16,
    pub max_mnt_count:      u16,
    pub magic:              u16,
    pub state:              u16,
    pub errors:             u16,
    pub minor_rev_level:    u16,
    pub lastcheck:          u32,
    pub checkinterval:      u32,
    pub creator_os:         u32,
    pub rev_level:          u32,
    pub def_resuid:         u16,
    pub def_resgid:         u16,
    pub first_ino:          u32,
    pub inode_size:         u16,
    pub block_group_nr:     u16,
    pub feature_compat:     u32,
    pub feature_incompat:   u32,
    pub feature_ro_compat:  u32,
    pub uuid:               [u8; 16],
    pub volume_name:        [u8; 16],
    pub last_mounted:       [u8; 64],
    pub algo_bitmap:        u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BgDesc {
    pub block_bitmap:  u32,
    pub inode_bitmap:  u32,
    pub inode_table:   u32,
    pub free_blocks:   u16,
    pub free_inodes:   u16,
    pub used_dirs:     u16,
    pub _pad:          u16,
    pub _reserved:     [u32; 3],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Inode {
    pub mode:        u16,
    pub uid_lo:      u16,
    pub size_lo:     u32,
    pub atime:       u32,
    pub ctime:       u32,
    pub mtime:       u32,
    pub dtime:       u32,
    pub gid_lo:      u16,
    pub links_count: u16,
    pub blocks_lo:   u32,
    pub flags:       u32,
    pub osd1:        u32,
    pub block:       [u32; 15],
    pub generation:  u32,
    pub file_acl:    u32,
    pub size_hi:     u32,
    pub obso_faddr:  u32,
    pub osd2:        [u8; 12],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub inode:     u32,
    pub rec_len:   u16,
    pub name_len:  u8,
    pub file_type: u8,
}

#[derive(Clone, Debug, Default)]
pub struct Ext2Stat {
    pub ino:     u32,
    pub mode:    u16,
    pub nlink:   u32,
    pub uid:     u32,
    pub gid:     u32,
    pub size:    u64,
    pub atime:   u64,
    pub mtime:   u64,
    pub ctime:   u64,
    pub blksize: u32,
    pub blocks:  u64,
}

#[derive(Clone, Debug)]
pub struct Ext2DirEntry {
    pub ino:    u32,
    pub name:   String,
    pub is_dir: bool,
    pub mode:   u16,
    pub size:   u64,
}

#[derive(Clone, Debug, Default)]
pub struct Ext2Statfs {
    pub f_bsize:   u32,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_bavail:  u64,
    pub f_namelen: u32,
}

pub struct Ext2Fs {
    pub data:            Vec<u8>,
    pub block_size:      usize,
    pub inode_size:      usize,
    pub inodes_per_grp:  usize,
    pub blocks_per_grp:  usize,
    pub first_data_blk:  usize,
    pub total_groups:    usize,
    pub inodes_count:    u32,
    pub blocks_count:    u32,
    pub free_blocks:     u32,
    pub r_blocks:        u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub dirty_blocks:    Vec<u64>,
}

pub static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);

#[inline] pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
}
#[inline] pub fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off+4].copy_from_slice(&val.to_le_bytes());
}
#[inline] pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off+1]])
}
#[inline] pub fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off+2].copy_from_slice(&val.to_le_bytes());
}

impl Ext2Fs {
    #[inline]
    pub fn blk_off(&self, blkno: u32) -> Option<usize> {
        if blkno == 0 { return None; }
        let off = (blkno as usize).checked_mul(self.block_size)?;
        if off + self.block_size > self.data.len() { return None; }
        Some(off)
    }
    #[inline]
    pub fn block_slice(&self, blkno: u32) -> Option<&[u8]> {
        let off = self.blk_off(blkno)?;
        Some(&self.data[off..off + self.block_size])
    }
    #[inline]
    pub fn block_slice_mut(&mut self, blkno: u32) -> Option<&mut [u8]> {
        let off = self.blk_off(blkno)?;
        Some(&mut self.data[off..off + self.block_size])
    }
    pub fn inode(&self, ino: u32) -> Option<Inode> { None }
    pub fn inode_to_stat(&self, ino: u32, i: &Inode) -> Ext2Stat { Ext2Stat::default() }
    pub fn lookup_path(&self, path: &str) -> Option<u32> { None }
    pub fn lookup_lstat(&self, path: &str) -> Option<u32> { None }
    pub fn alloc_block(&mut self) -> Result<u32, i32> { Err(ENOSPC) }
    pub fn alloc_inode(&mut self) -> Result<u32, i32> { Err(ENOSPC) }
    pub fn free_block(&mut self, _blkno: u32) {}
    pub fn free_inode(&mut self, _ino: u32) {}
}
