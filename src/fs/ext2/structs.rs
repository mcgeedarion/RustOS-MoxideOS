//! ext2 on-disk structures and public stat/direntry types.
//! Source lines 1–257 of the original ext2.rs monolith.
extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use spin::Mutex;

const EXT2_SUPER_MAGIC: u16 = 0xEF53;
const EXT2_ROOT_INO:    u32 = 2;
const EXT2_S_IFMT:      u16 = 0xF000;
const EXT2_S_IFREG:     u16 = 0x8000;
const EXT2_S_IFDIR:     u16 = 0x4000;
const EXT2_S_IFLNK:     u16 = 0xA000;

fn block_read(lba: u64, count: u32) -> Vec<u8> {
    let mut buf = vec![0u8; count as usize * 512];
    crate::drivers::block::read_sectors(lba, count, &mut buf);
    buf
}

fn block_write(lba: u64, data: &[u8]) {
    debug_assert!(data.len() % 512 == 0, "block_write: not sector-aligned");
    crate::drivers::block::write_sectors(lba, data);
}

#[derive(Clone, Debug)]
struct Superblock {
    inodes_count:       u32,
    blocks_count:       u32,
    r_blocks_count:     u32,
    free_blocks_count:  u32,
    free_inodes_count:  u32,
    first_data_block:   u32,
    log_block_size:     u32,
    log_frag_size:      u32,
    blocks_per_group:   u32,
    frags_per_group:    u32,
    inodes_per_group:   u32,
    mtime:              u32,
    wtime:              u32,
    mnt_count:          u16,
    max_mnt_count:      u16,
    magic:              u16,
    state:              u16,
    errors:             u16,
    minor_rev_level:    u16,
    lastcheck:          u32,
    checkinterval:      u32,
    creator_os:         u32,
    rev_level:          u32,
    def_resuid:         u16,
    def_resgid:         u16,
    // EXT2_DYNAMIC_REV fields
    first_ino:          u32,
    inode_size:         u16,
    block_group_nr:     u16,
    feature_compat:     u32,
    feature_incompat:   u32,
    feature_ro_compat:  u32,
    uuid:               [u8; 16],
    volume_name:        [u8; 16],
    last_mounted:       [u8; 64],
    algo_bitmap:        u32,
}

impl Superblock {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 1024 { return None; }
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        let magic = r16(56);
        if magic != EXT2_SUPER_MAGIC { return None; }
        let mut uuid  = [0u8; 16]; uuid.copy_from_slice(&b[104..120]);
        let mut vname = [0u8; 16]; vname.copy_from_slice(&b[120..136]);
        let mut lmnt  = [0u8; 64]; lmnt.copy_from_slice(&b[136..200]);
        Some(Superblock {
            inodes_count:      r32(0),  blocks_count:       r32(4),
            r_blocks_count:    r32(8),  free_blocks_count:  r32(12),
            free_inodes_count: r32(16), first_data_block:   r32(20),
            log_block_size:    r32(24), log_frag_size:      r32(28),
            blocks_per_group:  r32(32), frags_per_group:    r32(36),
            inodes_per_group:  r32(40),
            mtime: r32(44), wtime: r32(48),
            mnt_count: r16(52), max_mnt_count: r16(54),
            magic, state: r16(58), errors: r16(60),
            minor_rev_level: r16(62), lastcheck: r32(64),
            checkinterval: r32(68), creator_os: r32(72),
            rev_level: r32(76), def_resuid: r16(80), def_resgid: r16(82),
            first_ino: r32(84), inode_size: r16(88), block_group_nr: r16(90),
            feature_compat: r32(92), feature_incompat: r32(96),
            feature_ro_compat: r32(100),
            uuid, volume_name: vname, last_mounted: lmnt,
            algo_bitmap: r32(200),
        })
    }
    fn block_size(&self) -> usize { 1024 << self.log_block_size }
    fn inode_size(&self) -> usize {
        if self.rev_level >= 1 { self.inode_size as usize } else { 128 }
    }
}

#[derive(Clone, Debug)]
struct BgDesc {
    block_bitmap:    u32,
    inode_bitmap:    u32,
    inode_table:     u32,
    free_blocks:     u16,
    free_inodes:     u16,
    used_dirs:       u16,
}

impl BgDesc {
    fn from_bytes(b: &[u8]) -> Self {
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        BgDesc {
            block_bitmap: r32(0), inode_bitmap: r32(4),
            inode_table:  r32(8), free_blocks:  r16(12),
            free_inodes:  r16(14), used_dirs:   r16(16),
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0..4].copy_from_slice(&self.block_bitmap.to_le_bytes());
        b[4..8].copy_from_slice(&self.inode_bitmap.to_le_bytes());
        b[8..12].copy_from_slice(&self.inode_table.to_le_bytes());
        b[12..14].copy_from_slice(&self.free_blocks.to_le_bytes());
        b[14..16].copy_from_slice(&self.free_inodes.to_le_bytes());
        b[16..18].copy_from_slice(&self.used_dirs.to_le_bytes());
        b
    }
}

#[derive(Clone, Debug)]
struct Inode {
    mode:       u16,
    uid:        u16,
    size:       u32,
    atime:      u32,
    ctime:      u32,
    mtime:      u32,
    dtime:      u32,
    gid:        u16,
    links_count:u16,
    blocks:     u32,
    flags:      u32,
    block:      [u32; 15],
    generation: u32,
    file_acl:   u32,
    dir_acl:    u32,  // size_high for large files
    faddr:      u32,
    uid_high:   u16,
    gid_high:   u16,
    inode_size: u16, // extra size beyond 128 bytes
}

impl Inode {
    fn from_bytes(b: &[u8]) -> Self {
        let r32 = |o: usize| u32::from_le_bytes(b[o..o+4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o+2].try_into().unwrap());
        let mut block = [0u32; 15];
        for i in 0..15 { block[i] = r32(40 + i*4); }
        Inode {
            mode: r16(0), uid: r16(2), size: r32(4),
            atime: r32(8), ctime: r32(12), mtime: r32(16), dtime: r32(20),
            gid: r16(24), links_count: r16(26), blocks: r32(28),
            flags: r32(32), block,
            generation: r32(100), file_acl: r32(104), dir_acl: r32(108),
            faddr: r32(112),
            uid_high: r16(116), gid_high: r16(118),
            inode_size: if b.len() > 128 { r16(128) } else { 0 },
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        b[0..2].copy_from_slice(&self.mode.to_le_bytes());
        b[2..4].copy_from_slice(&self.uid.to_le_bytes());
        b[4..8].copy_from_slice(&self.size.to_le_bytes());
        b[8..12].copy_from_slice(&self.atime.to_le_bytes());
        b[12..16].copy_from_slice(&self.ctime.to_le_bytes());
        b[16..20].copy_from_slice(&self.mtime.to_le_bytes());
        b[20..24].copy_from_slice(&self.dtime.to_le_bytes());
        b[24..26].copy_from_slice(&self.gid.to_le_bytes());
        b[26..28].copy_from_slice(&self.links_count.to_le_bytes());
        b[28..32].copy_from_slice(&self.blocks.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        for i in 0..15 { b[40+i*4..44+i*4].copy_from_slice(&self.block[i].to_le_bytes()); }
        b[100..104].copy_from_slice(&self.generation.to_le_bytes());
        b[104..108].copy_from_slice(&self.file_acl.to_le_bytes());
        b[108..112].copy_from_slice(&self.dir_acl.to_le_bytes());
        b[112..116].copy_from_slice(&self.faddr.to_le_bytes());
        b[116..118].copy_from_slice(&self.uid_high.to_le_bytes());
        b[118..120].copy_from_slice(&self.gid_high.to_le_bytes());
        b
    }
    fn file_size(&self) -> u64 {
        (self.size as u64) | ((self.dir_acl as u64) << 32)
    }
}

#[derive(Clone, Debug)]
struct DirEntry {
    inode:     u32,
    rec_len:   u16,
    name_len:  u8,
    file_type: u8,
    name:      String,
}

impl DirEntry {
    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 { return None; }
        let inode   = u32::from_le_bytes(b[0..4].try_into().ok()?);
        let rec_len = u16::from_le_bytes(b[4..6].try_into().ok()?);
        let name_len= b[6];
        let file_type = b[7];
        let end = 8 + name_len as usize;
        if end > b.len() { return None; }
        let name = String::from_utf8_lossy(&b[8..end]).into_owned();
        Some(DirEntry { inode, rec_len, name_len, file_type, name })
    }
}

#[derive(Clone, Debug)]
pub struct Ext2Stat {
    pub ino:    u32,
    pub mode:   u16,
    pub uid:    u32,
    pub gid:    u32,
    pub size:   u64,
    pub atime:  u32,
    pub mtime:  u32,
    pub ctime:  u32,
    pub nlink:  u16,
    pub blocks: u32,
}

#[derive(Clone, Debug)]
pub struct Ext2DirEntry {
    pub inode:     u32,
    pub name:      String,
    pub file_type: u8,
}

#[derive(Clone, Debug)]
pub struct Ext2Statfs {
    pub block_size:   u32,
    pub total_blocks: u32,
    pub free_blocks:  u32,
    pub total_inodes: u32,
    pub free_inodes:  u32,
}

pub struct Ext2Fs {
    pub(crate) sb:         Superblock,
    pub(crate) group_descs: Vec<BgDesc>,
    pub(crate) block_size:  usize,
    pub(crate) lba_offset:  u64,  // partition start in 512-byte sectors
}

pub(crate) static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);

impl Ext2Fs {
    fn block_to_lba(&self, block: u32) -> u64 {
        self.lba_offset + (block as u64 * self.block_size as u64 / 512)
    }
    fn read_block(&self, block: u32) -> Vec<u8> {
        block_read(self.block_to_lba(block), (self.block_size / 512) as u32)
    }
    fn write_block(&self, block: u32, data: &[u8]) {
        block_write(self.block_to_lba(block), data);
    }
    fn read_group_desc(&self, group: u32) -> Option<BgDesc> {
        self.group_descs.get(group as usize).cloned()
    }
}