//! Ext2 read-only filesystem driver.
//!
//! Revision 0 and revision 1 (dynamic inode sizes) are supported.
//! Block sizes of 1024, 2048, and 4096 bytes are supported.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

// Cap individual file reads to 256 MiB to prevent OOM from crafted images.
const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Superblock {
    inodes_count:         u32,
    blocks_count:         u32,
    r_blocks_count:       u32,
    free_blocks_count:    u32,
    free_inodes_count:    u32,
    first_data_block:     u32,
    log_block_size:       u32,
    log_frag_size:        i32,
    blocks_per_group:     u32,
    frags_per_group:      u32,
    inodes_per_group:     u32,
    mtime:                u32,
    wtime:                u32,
    mnt_count:            u16,
    max_mnt_count:        i16,
    magic:                u16,
    state:                u16,
    errors:               u16,
    minor_rev_level:      u16,
    lastcheck:            u32,
    checkinterval:        u32,
    creator_os:           u32,
    rev_level:            u32,
    def_resuid:           u16,
    def_resgid:           u16,
    first_ino:            u32,
    inode_size:           u16,
    block_group_nr:       u16,
    feature_compat:       u32,
    feature_incompat:     u32,
    feature_ro_compat:    u32,
    uuid:                 [u8; 16],
    volume_name:          [u8; 16],
    last_mounted:         [u8; 64],
    algo_bitmap:          u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GroupDesc {
    block_bitmap:  u32,
    inode_bitmap:  u32,
    inode_table:   u32,
    free_blocks:   u16,
    free_inodes:   u16,
    used_dirs:     u16,
    _pad:          u16,
    _reserved:     [u32; 3],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Inode {
    mode:          u16,
    uid:           u16,
    size_lo:       u32,
    atime:         u32,
    ctime:         u32,
    mtime:         u32,
    dtime:         u32,
    gid:           u16,
    links_count:   u16,
    blocks:        u32,
    flags:         u32,
    osd1:          u32,
    block:         [u32; 15],
    generation:    u32,
    file_acl:      u32,
    size_hi:       u32,
    faddr:         u32,
    osd2:          [u8; 12],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DirEntry2 {
    inode:     u32,
    rec_len:   u16,
    name_len:  u8,
    file_type: u8,
}

struct Ext2Fs {
    data:           Vec<u8>,
    block_size:     usize,
    inode_size:     usize,
    inodes_per_grp: usize,
    first_data_blk: usize,
}

static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);

pub fn mount() -> bool {
    if !crate::drivers::virtio_blk::is_present() { return false; }

    let mut sb_buf2 = alloc::vec![0u8; 512];
    let _ = crate::drivers::virtio_blk::read_sectors(2, &mut sb_buf2);
    let mut sb_buf3 = alloc::vec![0u8; 512];
    let _ = crate::drivers::virtio_blk::read_sectors(3, &mut sb_buf3);

    let mut raw_sb = alloc::vec![0u8; 1024];
    raw_sb[..512].copy_from_slice(&sb_buf2);
    raw_sb[512..].copy_from_slice(&sb_buf3);
    let sb = unsafe { *(raw_sb.as_ptr() as *const Superblock) };

    if sb.magic != 0xEF53 { return false; }

    let block_size = 1024usize << sb.log_block_size;
    let total_bytes = sb.blocks_count as usize * block_size;
    let load_bytes = total_bytes.min(256 * 1024 * 1024);

    let mut image = alloc::vec![0u8; load_bytes];
    let chunk = 128usize;
    let mut lba = 0u64;
    let mut off = 0usize;
    while off < load_bytes {
        let n = chunk.min((load_bytes - off) / 512);
        if n == 0 { break; }
        let slice = &mut image[off..off + n * 512];
        if crate::drivers::virtio_blk::read_sectors(lba, slice).is_err() { break; }
        off += n * 512;
        lba += n as u64;
    }

    let inode_size = if sb.rev_level >= 1 { sb.inode_size as usize } else { 128 };

    *FS.lock() = Some(Ext2Fs {
        data: image,
        block_size,
        inode_size,
        inodes_per_grp: sb.inodes_per_group as usize,
        first_data_blk: sb.first_data_block as usize,
    });
    true
}

impl Ext2Fs {
    fn group_desc(&self, g: usize) -> GroupDesc {
        let off = if self.block_size == 1024 { 2048 } else { self.block_size };
        let entry_off = off + g * 32;
        if entry_off + 32 > self.data.len() {
            return GroupDesc {
                block_bitmap: 0, inode_bitmap: 0, inode_table: 0,
                free_blocks: 0, free_inodes: 0, used_dirs: 0,
                _pad: 0, _reserved: [0; 3],
            };
        }
        unsafe { *((self.data.as_ptr().add(entry_off)) as *const GroupDesc) }
    }

    fn inode(&self, ino: u32) -> Option<Inode> {
        if ino == 0 { return None; }
        let idx   = (ino - 1) as usize;
        let grp   = idx / self.inodes_per_grp;
        let local = idx % self.inodes_per_grp;
        let gd    = self.group_desc(grp);
        let off   = gd.inode_table as usize * self.block_size + local * self.inode_size;
        if off + self.inode_size > self.data.len() { return None; }
        Some(unsafe { *(self.data.as_ptr().add(off) as *const Inode) })
    }

    fn block_data(&self, blkno: u32) -> Option<&[u8]> {
        if blkno == 0 { return None; }
        let off = blkno as usize * self.block_size;
        if off + self.block_size > self.data.len() { return None; }
        Some(&self.data[off..off + self.block_size])
    }

    /// Iterate over the direct + single-indirect data blocks of `ino`,
    /// calling `f` with each block slice. Stops early when `f` returns false.
    /// Zero-copy: slices point into self.data, no allocation.
    fn scan_inode_data_blocks<F>(&self, ino: &Inode, mut f: F)
    where F: FnMut(&[u8]) -> bool
    {
        // Direct blocks (0..11)
        for i in 0..12usize {
            if let Some(blk) = self.block_data(ino.block[i]) {
                if !f(blk) { return; }
            }
        }
        // Single-indirect block (block[12])
        if let Some(iblk) = self.block_data(ino.block[12]) {
            let ptrs = self.block_size / 4;
            for i in 0..ptrs {
                let blkno = u32::from_le_bytes([
                    iblk[i*4], iblk[i*4+1], iblk[i*4+2], iblk[i*4+3]
                ]);
                if let Some(blk) = self.block_data(blkno) {
                    if !f(blk) { return; }
                }
            }
        }
        // Double/triple indirect not needed for directory lookups —
        // directories in ext2 are practically never larger than
        // 12 + ptrs blocks (12 + 1024 = 1036 blocks = ~4 MiB at 4K blocks).
    }

    /// Read all data bytes for a regular file into an owned Vec.
    /// Used for file reads only; directory lookup uses scan_inode_data_blocks.
    fn read_inode_data(&self, ino: &Inode) -> Vec<u8> {
        let size = (ino.size_lo as usize).min(MAX_FILE_SIZE);
        let mut out = alloc::vec![0u8; size];
        let mut written = 0usize;
        for i in 0..12usize {
            if written >= size { break; }
            if let Some(d) = self.block_data(ino.block[i]) {
                let n = (size - written).min(d.len());
                out[written..written + n].copy_from_slice(&d[..n]);
                written += n;
            }
        }
        if written < size {
            if let Some(iblk) = self.block_data(ino.block[12]) {
                let ptrs = self.block_size / 4;
                for i in 0..ptrs {
                    if written >= size { break; }
                    let blk = u32::from_le_bytes([iblk[i*4], iblk[i*4+1], iblk[i*4+2], iblk[i*4+3]]);
                    if let Some(d) = self.block_data(blk) {
                        let n = (size - written).min(d.len());
                        out[written..written + n].copy_from_slice(&d[..n]);
                        written += n;
                    }
                }
            }
        }
        out.truncate(size);
        out
    }

    fn lookup_path(&self, path: &str) -> Option<u32> {
        let mut ino = 2u32;
        let path = path.trim_start_matches('/');
        if path.is_empty() { return Some(2); }
        for component in path.split('/') {
            if component.is_empty() { continue; }
            ino = self.lookup_dir(ino, component)?;
        }
        Some(ino)
    }

    /// Find `name` in directory inode `dir_ino`.
    /// Zero-copy: scans block slices from self.data directly via
    /// scan_inode_data_blocks; no Vec<u8> allocation.
    fn lookup_dir(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let inode = self.inode(dir_ino)?;
        let name_bytes = name.as_bytes();
        let mut result = None;
        self.scan_inode_data_blocks(&inode, |blk| {
            let mut off = 0usize;
            while off + 8 <= blk.len() {
                let de = unsafe { *(blk.as_ptr().add(off) as *const DirEntry2) };
                let rec = de.rec_len as usize;
                if rec == 0 { return false; } // malformed; stop
                if de.inode != 0 {
                    let name_end = off + 8 + de.name_len as usize;
                    if name_end <= blk.len() && &blk[off + 8..name_end] == name_bytes {
                        result = Some(de.inode);
                        return false; // found; stop scanning
                    }
                }
                off += rec;
            }
            true // continue to next block
        });
        result
    }

    /// Collect all entries in directory inode `dir_ino`.
    /// Uses read_inode_data (allocates once) since readdir needs all entries.
    fn list_dir_ino(&self, dir_ino: u32) -> Vec<(u32, String, bool)> {
        let mut out = Vec::new();
        let inode = match self.inode(dir_ino) { Some(i) => i, None => return out };
        let data  = self.read_inode_data(&inode);
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = unsafe { *(data.as_ptr().add(off) as *const DirEntry2) };
            let rec = de.rec_len as usize;
            if rec == 0 { break; }
            if de.inode != 0 {
                let name_end = off + 8 + de.name_len as usize;
                if name_end > data.len() { break; }
                let name_bytes = &data[off + 8..name_end];
                if let Ok(s) = core::str::from_utf8(name_bytes) {
                    let child_ino = de.inode;
                    let is_dir = de.file_type == 2
                        || self.inode(child_ino).map_or(false, |i| i.mode & 0xF000 == 0x4000);
                    out.push((child_ino, String::from(s), is_dir));
                }
            }
            off += rec;
        }
        out
    }
}

pub fn stat(path: &str) -> Option<u32> {
    FS.lock().as_ref()?.lookup_path(path)
}

pub fn read_file_by_ino(ino: u32) -> Option<Vec<u8>> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    if inode.mode & 0xF000 != 0x8000 { return None; }
    Some(fs.read_inode_data(&inode))
}

pub fn file_size(ino: u32) -> Option<usize> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    Some(inode.size_lo as usize)
}

pub fn is_dir(path: &str) -> bool {
    let fs = FS.lock();
    let fs = match fs.as_ref() { Some(f) => f, None => return false };
    let ino = match fs.lookup_path(path) { Some(i) => i, None => return false };
    let inode = match fs.inode(ino) { Some(i) => i, None => return false };
    inode.mode & 0xF000 == 0x4000
}

pub fn readdir(dir_ino: u32) -> Option<Vec<(u32, String, bool)>> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    Some(fs.list_dir_ino(dir_ino))
}
