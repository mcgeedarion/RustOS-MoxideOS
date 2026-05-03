//! Ext2 read-only filesystem driver.
//!
//! Revision 0 and revision 1 (dynamic inode sizes) are supported.
//! Block sizes of 1024, 2048, and 4096 bytes are supported.
//!
//! ## Design
//!   The driver loads the entire ext2 image from disk once at mount time
//!   into a kernel heap Vec<u8>.  All subsequent reads are pure memory
//!   operations; no further disk I/O is needed for reads.
//!
//!   Write support is intentionally omitted in this revision — the
//!   ramfs layer handles runtime-created files.  The ext2 image is
//!   the read-only root (binaries, shared libs, /etc).
//!
//! ## Inode layout
//!   Inodes are identified by their 32-bit number (1-based).
//!   The root directory is inode 2.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

// ── On-disk structures ─────────────────────────────────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Superblock {
    inodes_count:         u32,
    blocks_count:         u32,
    r_blocks_count:       u32,
    free_blocks_count:    u32,
    free_inodes_count:    u32,
    first_data_block:     u32,
    log_block_size:       u32,  // block_size = 1024 << log_block_size
    log_frag_size:        i32,
    blocks_per_group:     u32,
    frags_per_group:      u32,
    inodes_per_group:     u32,
    mtime:                u32,
    wtime:                u32,
    mnt_count:            u16,
    max_mnt_count:        i16,
    magic:                u16,  // 0xEF53
    state:                u16,
    errors:               u16,
    minor_rev_level:      u16,
    lastcheck:            u32,
    checkinterval:        u32,
    creator_os:           u32,
    rev_level:            u32,  // 0 = original, 1 = dynamic
    def_resuid:           u16,
    def_resgid:           u16,
    // Rev1 only:
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
    blocks:        u32,  // in 512-byte units
    flags:         u32,
    osd1:          u32,
    block:         [u32; 15], // 12 direct + 1 indirect + 1 dbl + 1 triple
    generation:    u32,
    file_acl:      u32,
    size_hi:       u32, // dir_acl in rev0; size_hi for large files in rev1
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

// ── Driver state ────────────────────────────────────────────────────────────

struct Ext2Fs {
    data:           Vec<u8>,
    block_size:     usize,
    inode_size:     usize,
    inodes_per_grp: usize,
    first_data_blk: usize,
}

static FS: Mutex<Option<Ext2Fs>> = Mutex::new(None);

// ── mount ───────────────────────────────────────────────────────────────────

/// Load the entire ext2 image from virtio_blk into memory.
/// Called by virtio_blk::init() after the device is ready, or from
/// kernel_main if the driver detects a disk.
pub fn mount() -> bool {
    if !crate::drivers::virtio_blk::is_present() { return false; }

    // Read the superblock (sector 2, offset 1024 in the image).
    let mut sb_buf = alloc::vec![0u8; 1024];
    if crate::drivers::virtio_blk::read_sectors(0, &mut sb_buf).is_err() { return false; }
    // Superblock is at byte offset 1024; we need a second read if sector_size=512.
    let mut sb_buf2 = alloc::vec![0u8; 512];
    let _ = crate::drivers::virtio_blk::read_sectors(2, &mut sb_buf2);
    let mut sb_buf3 = alloc::vec![0u8; 512];
    let _ = crate::drivers::virtio_blk::read_sectors(3, &mut sb_buf3);

    // Assemble superblock bytes [1024..2048].
    let mut raw_sb = alloc::vec![0u8; 1024];
    raw_sb[..512].copy_from_slice(&sb_buf2);
    raw_sb[512..].copy_from_slice(&sb_buf3);
    let sb = unsafe { *(raw_sb.as_ptr() as *const Superblock) };

    if sb.magic != 0xEF53 { return false; }

    let block_size = 1024usize << sb.log_block_size;
    let total_bytes = sb.blocks_count as usize * block_size;
    // Cap at 256 MiB to avoid OOM on large images.
    let load_bytes = total_bytes.min(256 * 1024 * 1024);
    let sectors    = (load_bytes + 511) / 512;

    let mut image = alloc::vec![0u8; load_bytes];
    let chunk = 128usize; // read 64 KiB at a time (128 sectors)
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

// ── low-level helpers ────────────────────────────────────────────────────────

impl Ext2Fs {
    fn sb(&self) -> &Superblock {
        unsafe { &*(self.data.as_ptr().add(1024) as *const Superblock) }
    }

    fn group_desc(&self, g: usize) -> GroupDesc {
        let off = if self.block_size == 1024 { 2048 } else { self.block_size };
        unsafe { *((self.data.as_ptr().add(off + g * 32)) as *const GroupDesc) }
    }

    fn inode(&self, ino: u32) -> Option<Inode> {
        if ino == 0 { return None; }
        let idx  = (ino - 1) as usize;
        let grp  = idx / self.inodes_per_grp;
        let local= idx % self.inodes_per_grp;
        let gd   = self.group_desc(grp);
        let off  = gd.inode_table as usize * self.block_size + local * self.inode_size;
        if off + self.inode_size > self.data.len() { return None; }
        Some(unsafe { *(self.data.as_ptr().add(off) as *const Inode) })
    }

    fn block_data(&self, blkno: u32) -> Option<&[u8]> {
        if blkno == 0 { return None; }
        let off = blkno as usize * self.block_size;
        if off + self.block_size > self.data.len() { return None; }
        Some(&self.data[off..off + self.block_size])
    }

    /// Read all bytes of a regular file.
    fn read_inode_data(&self, ino: &Inode) -> Vec<u8> {
        let size = ino.size_lo as usize;
        let mut out = alloc::vec![0u8; size];
        let mut written = 0usize;

        // Direct blocks (0-11).
        for i in 0..12usize {
            if written >= size { break; }
            let blk = ino.block[i];
            if let Some(d) = self.block_data(blk) {
                let n = (size - written).min(d.len());
                out[written..written + n].copy_from_slice(&d[..n]);
                written += n;
            }
        }

        // Singly indirect block (block[12]).
        if written < size {
            let ind = ino.block[12];
            if let Some(iblk) = self.block_data(ind) {
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
        // (Doubly/triply indirect blocks omitted — sufficient for binaries ≤ a few MiB)
        out.truncate(size);
        out
    }

    /// Resolve an absolute path to an inode number. Returns None if not found.
    fn lookup_path(&self, path: &str) -> Option<u32> {
        let mut ino = 2u32; // root
        let path = path.trim_start_matches('/');
        if path.is_empty() { return Some(2); }
        for component in path.split('/') {
            if component.is_empty() { continue; }
            ino = self.lookup_dir(ino, component)?;
        }
        Some(ino)
    }

    /// Find a directory entry named `name` inside directory inode `dir_ino`.
    fn lookup_dir(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let inode = self.inode(dir_ino)?;
        let data  = self.read_inode_data(&inode);
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let de = unsafe { *(data.as_ptr().add(off) as *const DirEntry2) };
            let rec = de.rec_len as usize;
            if rec == 0 { break; }
            if de.inode != 0 {
                let name_bytes = &data[off + 8..off + 8 + de.name_len as usize];
                if name_bytes == name.as_bytes() { return Some(de.inode); }
            }
            off += rec;
        }
        None
    }
}

// ── Public API (called by vfs.rs) ─────────────────────────────────────────

/// Return the inode number for `path`, or None if it doesn't exist.
pub fn stat(path: &str) -> Option<u32> {
    FS.lock().as_ref()?.lookup_path(path)
}

/// Read a file by inode number. Returns None if ino is not a regular file.
pub fn read_file_by_ino(ino: u32) -> Option<Vec<u8>> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    // mode bits: 0o100000 = regular file
    if inode.mode & 0xF000 != 0x8000 { return None; }
    Some(fs.read_inode_data(&inode))
}

/// Return the byte size of the file at inode `ino`.
pub fn file_size(ino: u32) -> Option<usize> {
    let fs = FS.lock();
    let fs = fs.as_ref()?;
    let inode = fs.inode(ino)?;
    Some(inode.size_lo as usize)
}

/// Return true if `path` exists and is a directory.
pub fn is_dir(path: &str) -> bool {
    let fs = FS.lock();
    let fs = match fs.as_ref() { Some(f) => f, None => return false };
    let ino = match fs.lookup_path(path) { Some(i) => i, None => return false };
    let inode = match fs.inode(ino) { Some(i) => i, None => return false };
    inode.mode & 0xF000 == 0x4000
}
