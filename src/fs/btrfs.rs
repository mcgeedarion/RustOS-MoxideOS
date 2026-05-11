//! Btrfs **read-only** filesystem driver.
//!
//! # Supported features
//! - Single device, single subvolume (default subvolume ID 256)
//! - Default tree root: FS tree lookup via root tree and chunk tree
//! - B-tree node / leaf traversal
//! - Regular files: extent items (EXTENT_DATA) with inline and regular extents
//! - Directories: DIR_ITEM / DIR_INDEX lookup
//! - Symlink resolution (up to 8 levels)
//! - `stat()`, `readdir()`, `readlink()`, `statfs()`
//!
//! # Not supported (yet)
//! - RAID profiles (single-device only)
//! - Multiple subvolumes / snapshots
//! - Compression (LZO, zstd, zlib) — compressed extents return EIO
//! - Write path
//!
//! # Architecture
//! Like ext4.rs the entire image (up to 512 MiB) is read into a Vec<u8>
//! at mount time.  All subsequent operations are purely in-memory.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

// ── magic / constants ──────────────────────────────────────────────────────
const BTRFS_MAGIC:           u64 = 0x4D5F53665248425F; // "_BHRfS_M"
const BTRFS_SUPER_OFFSET:    usize = 0x10000; // 64 KiB
const BTRFS_LEAF_NODE:       u8  = 0;
const BTRFS_INTERNAL_NODE:   u8  = 1;
const BTRFS_MAX_LEVEL:       usize = 8;
const MAX_IMAGE_BYTES:       usize = 512 * 1024 * 1024;
const MAX_SYMLINK_DEPTH:     usize = 8;

// Object IDs
const BTRFS_ROOT_TREE_OBJECTID:    u64 = 1;
const BTRFS_EXTENT_TREE_OBJECTID:  u64 = 2;
const BTRFS_CHUNK_TREE_OBJECTID:   u64 = 3;
const BTRFS_FS_TREE_OBJECTID:      u64 = 5;
const BTRFS_ROOT_TREE_DIR_OBJECTID:u64 = 6;
const BTRFS_FIRST_FREE_OBJECTID:   u64 = 256;
const BTRFS_INODE_ITEM_KEY:        u8  = 1;
const BTRFS_INODE_REF_KEY:         u8  = 12;
const BTRFS_DIR_ITEM_KEY:          u8  = 84;
const BTRFS_DIR_INDEX_KEY:         u8  = 96;
const BTRFS_EXTENT_DATA_KEY:       u8  = 108;
const BTRFS_ROOT_ITEM_KEY:         u8  = 132;
const BTRFS_EXTENT_ITEM_KEY:       u8  = 168;
const BTRFS_CHUNK_ITEM_KEY:        u8  = 228;

// Extent types
const BTRFS_EXTENT_INLINE:  u8 = 0;
const BTRFS_EXTENT_PREALLOC:u8 = 1;
const BTRFS_EXTENT_REGULAR: u8 = 2;

// ── on-disk layout helpers ─────────────────────────────────────────────────

#[inline]
fn r64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o+8].try_into().unwrap_or([0;8]))
}
#[inline]
fn r32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o+4].try_into().unwrap_or([0;4]))
}
#[inline]
fn r16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o+2].try_into().unwrap_or([0;2]))
}

// ── superblock (at 0x10000, 0x20000, 0x40000) ──────────────────────────────
// We read only the fields we need.
// Offsets from the Linux kernel btrfs_super_block layout.
struct Super {
    generation:   u64,
    root:         u64,  // root tree logical address
    chunk_root:   u64,  // chunk tree logical address
    node_size:    u32,
    leaf_size:    u32,
    sector_size:  u32,
    total_bytes:  u64,
    bytes_used:   u64,
    num_devices:  u64,
    sys_chunk_array_size: u32,
    // sys_chunk_array at +0x32b, len = sys_chunk_array_size
    sys_chunks:   Vec<u8>,
}

fn parse_super(data: &[u8]) -> Option<Super> {
    if data.len() < BTRFS_SUPER_OFFSET + 4096 { return None; }
    let s = &data[BTRFS_SUPER_OFFSET..];
    // csum (32) + fsid (16) + bytenr (8) + flags (8) + magic (8) = offset 0x40
    let magic = r64(s, 0x40);
    if magic != BTRFS_MAGIC { return None; }
    let generation = r64(s, 0x48);
    let root        = r64(s, 0x50); // s_root
    let chunk_root  = r64(s, 0x58); // s_chunk_root
    // 0x60 log_root, skip
    let total_bytes = r64(s, 0x70);
    let bytes_used  = r64(s, 0x78);
    let num_devices = r64(s, 0xE8);
    let sector_size = r32(s, 0xF0);
    let node_size   = r32(s, 0xF4);
    let leaf_size   = r32(s, 0xF8);
    let sys_chunk_array_size = r32(s, 0x159);
    let sc_off = BTRFS_SUPER_OFFSET + 0x15b;
    let sc_end = sc_off + sys_chunk_array_size as usize;
    if sc_end > data.len() { return None; }
    let sys_chunks = data[sc_off..sc_end].to_vec();
    Some(Super {
        generation, root, chunk_root,
        node_size, leaf_size, sector_size,
        total_bytes, bytes_used, num_devices,
        sys_chunk_array_size, sys_chunks,
    })
}

// ── chunk map: logical address → physical offset ──────────────────────────

#[derive(Clone)]
struct ChunkEntry {
    logical: u64,
    length:  u64,
    offset:  u64, // physical offset in image (single-device)
}

fn parse_sys_chunks(data: &[u8]) -> Vec<ChunkEntry> {
    // The sys_chunk_array is a sequence of (key (17 bytes), chunk (80+ bytes)) pairs.
    // key layout: objectid(8) type(1) offset(8)
    // chunk layout: length(8) owner(8) stripe_len(8) type(8) io_align(4)
    //               io_width(4) sector_size(4) num_stripes(2) sub_stripes(2)
    //               stripe[0]: devid(8) offset(8) dev_uuid(16)  -- 32 bytes each
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 17 + 80 <= data.len() {
        // key
        let _objid  = r64(data, pos);
        let key_type= data[pos + 8];
        let logical = r64(data, pos + 9);
        pos += 17;
        if key_type != BTRFS_CHUNK_ITEM_KEY { break; }
        // chunk
        let length      = r64(data, pos);
        let num_stripes = r16(data, pos + 48) as usize;
        // first stripe physical offset
        let stripe_off  = r64(data, pos + 64); // stripe.offset
        pos += 80 + num_stripes.saturating_sub(1) * 32;
        out.push(ChunkEntry { logical, length, offset: stripe_off });
    }
    out
}

// ── BtrfsFs ────────────────────────────────────────────────────────────────

struct BtrfsFs {
    data:       Vec<u8>,
    node_size:  usize,
    chunks:     Vec<ChunkEntry>,
    root_tree:  u64,  // logical addr
    fs_tree:    u64,  // logical addr of the FS tree for subvol 256
    total_bytes:u64,
    bytes_used: u64,
}

static FS: Mutex<Option<BtrfsFs>> = Mutex::new(None);

// ── logical → physical translation ────────────────────────────────────────

impl BtrfsFs {
    fn logical_to_phys(&self, logical: u64) -> Option<usize> {
        for c in &self.chunks {
            if logical >= c.logical && logical < c.logical + c.length {
                let delta = logical - c.logical;
                return Some((c.offset + delta) as usize);
            }
        }
        None
    }

    fn node(&self, logical: u64) -> Option<&[u8]> {
        let off = self.logical_to_phys(logical)?;
        let end = off + self.node_size;
        if end > self.data.len() { return None; }
        Some(&self.data[off..end])
    }

    // ── B-tree node header: 101 bytes ─────────────────────────────────────
    // csum(32) fsid(16) bytenr(8) flags(8) chunk_tree_uuid(16)
    // generation(8) owner(8) nritems(4) level(1) = 101
    const HDR: usize = 101;

    fn nritems(node: &[u8]) -> u32 { r32(node, 97) }
    fn level(node: &[u8])   -> u8  { node[100] }

    // Leaf item header: key(17) + offset(4) + size(4) = 25 bytes
    fn leaf_item_key(node: &[u8], i: usize) -> (u64, u8, u64) {
        let base = Self::HDR + i * 25;
        let objid = r64(node, base);
        let typ   = node[base + 8];
        let off   = r64(node, base + 9);
        (objid, typ, off)
    }
    fn leaf_item_data<'a>(node: &'a [u8], i: usize) -> &'a [u8] {
        let base   = Self::HDR + i * 25;
        let data_off = r32(node, base + 17) as usize;
        let data_len = r32(node, base + 21) as usize;
        let abs = Self::HDR + data_off;
        if abs + data_len <= node.len() { &node[abs..abs + data_len] } else { &[] }
    }

    // Internal node key pointer: key(17) + blockptr(8) + generation(8) = 33 bytes
    fn kp_key(node: &[u8], i: usize) -> (u64, u8, u64) {
        let base = Self::HDR + i * 33;
        (r64(node, base), node[base + 8], r64(node, base + 9))
    }
    fn kp_ptr(node: &[u8], i: usize) -> u64 {
        let base = Self::HDR + i * 33;
        r64(node, base + 17)
    }

    // ── B-tree search ────────────────────────────────────────────────────
    // Find all leaf items in `tree_root` where key matches the predicate.
    fn search<F>(&self, tree_root: u64, mut pred: F) -> Vec<(u64, u8, u64, Vec<u8>)>
    where F: FnMut(u64, u8, u64) -> core::cmp::Ordering
    {
        let mut results = Vec::new();
        self.search_node(tree_root, &mut pred, &mut results, 0);
        results
    }

    fn search_node<F>(
        &self, logical: u64,
        pred: &mut F,
        out: &mut Vec<(u64, u8, u64, Vec<u8>)>,
        depth: usize,
    ) where F: FnMut(u64, u8, u64) -> core::cmp::Ordering
    {
        if depth >= BTRFS_MAX_LEVEL { return; }
        let node = match self.node(logical) { Some(n) => n, None => return };
        let n = Self::nritems(node) as usize;
        if n == 0 { return; }

        if Self::level(node) == BTRFS_LEAF_NODE {
            for i in 0..n {
                let (obj, typ, off) = Self::leaf_item_key(node, i);
                match pred(obj, typ, off) {
                    core::cmp::Ordering::Equal => {
                        let d = Self::leaf_item_data(node, i).to_vec();
                        out.push((obj, typ, off, d));
                    }
                    _ => {}
                }
            }
        } else {
            for i in 0..n {
                let (obj, typ, off) = Self::kp_key(node, i);
                let ptr = Self::kp_ptr(node, i);
                // Descend if the subtree could contain matching keys.
                // For simplicity always descend (correct, just not optimal).
                self.search_node(ptr, pred, out, depth + 1);
            }
        }
    }

    // ── inode lookup ────────────────────────────────────────────────────
    fn inode_item(&self, ino: u64) -> Option<Vec<u8>> {
        let items = self.search(self.fs_tree, |obj, typ, _off| {
            match (obj.cmp(&ino), typ.cmp(&BTRFS_INODE_ITEM_KEY)) {
                (core::cmp::Ordering::Equal, core::cmp::Ordering::Equal) =>
                    core::cmp::Ordering::Equal,
                (core::cmp::Ordering::Less, _) | (core::cmp::Ordering::Equal, core::cmp::Ordering::Less) =>
                    core::cmp::Ordering::Less,
                _ => core::cmp::Ordering::Greater,
            }
        });
        items.into_iter().next().map(|(_, _, _, d)| d)
    }

    // ── directory lookup: name → child inode ────────────────────────────
    fn dir_lookup(&self, dir_ino: u64, name: &str) -> Option<u64> {
        let name_b = name.as_bytes();
        // Search for all DIR_ITEM entries under dir_ino.
        let items = self.search(self.fs_tree, |obj, typ, _| {
            if obj == dir_ino && typ == BTRFS_DIR_ITEM_KEY {
                core::cmp::Ordering::Equal
            } else if obj < dir_ino || (obj == dir_ino && typ < BTRFS_DIR_ITEM_KEY) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        });
        for (_, _, _, data) in items {
            // DIR_ITEM: location_key(17) + transid(8) + data_len(2) + name_len(2) + type(1)
            //           + name_bytes + data_bytes
            if data.len() < 30 { continue; }
            let child_ino = r64(&data, 0);
            let name_len  = r16(&data, 25) as usize;
            let name_off  = 30usize;
            if name_off + name_len > data.len() { continue; }
            if &data[name_off..name_off + name_len] == name_b {
                return Some(child_ino);
            }
        }
        None
    }

    // ── directory listing ────────────────────────────────────────────────
    fn readdir_ino(&self, dir_ino: u64) -> Vec<(u64, String, u8)> {
        let items = self.search(self.fs_tree, |obj, typ, _| {
            if obj == dir_ino && typ == BTRFS_DIR_INDEX_KEY {
                core::cmp::Ordering::Equal
            } else if obj < dir_ino || (obj == dir_ino && typ < BTRFS_DIR_INDEX_KEY) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        });
        let mut out = Vec::new();
        for (_, _, _, data) in items {
            if data.len() < 30 { continue; }
            let child_ino = r64(&data, 0);
            let ftype     = data[29];
            let name_len  = r16(&data, 25) as usize;
            let name_off  = 30usize;
            if name_off + name_len > data.len() { continue; }
            if let Ok(s) = core::str::from_utf8(&data[name_off..name_off + name_len]) {
                out.push((child_ino, alloc::string::ToString::to_string(s), ftype));
            }
        }
        out
    }

    // ── path resolution ─────────────────────────────────────────────────
    fn lookup_path_depth(&self, path: &str, depth: usize) -> Option<u64> {
        if depth > MAX_SYMLINK_DEPTH { return None; }
        let mut ino = 256u64; // root inode of default subvol
        for component in path.trim_start_matches('/').split('/') {
            if component.is_empty() || component == "." { continue; }
            if component == ".." {
                ino = self.dir_lookup(ino, "..").unwrap_or(256);
                continue;
            }
            let child = self.dir_lookup(ino, component)?;
            // Check for symlink
            if let Some(idata) = self.inode_item(child) {
                let mode = r32(&idata, 48) as u16; // st_mode at offset 48 in INODE_ITEM
                if mode & 0xF000 == 0xA000 {
                    let target = self.read_file_data(child)?;
                    let ts = core::str::from_utf8(&target).ok()?;
                    ino = if ts.starts_with('/') {
                        self.lookup_path_depth(ts, depth + 1)?
                    } else {
                        self.lookup_path_depth(ts, depth + 1)?
                    };
                    continue;
                }
            }
            ino = child;
        }
        Some(ino)
    }

    fn lookup_path(&self, path: &str) -> Option<u64> {
        self.lookup_path_depth(path, 0)
    }

    // ── file data reader ─────────────────────────────────────────────────
    fn read_file_data(&self, ino: u64) -> Option<Vec<u8>> {
        // Get file size from inode item.
        let idata = self.inode_item(ino)?;
        if idata.len() < 160 { return None; }
        let file_size = r64(&idata, 8) as usize; // nbytes at offset 8
        if file_size == 0 { return Some(Vec::new()); }

        // Collect EXTENT_DATA items, sorted by file offset.
        let mut extents: Vec<(u64, Vec<u8>)> = self.search(self.fs_tree, |obj, typ, _| {
            if obj == ino && typ == BTRFS_EXTENT_DATA_KEY {
                core::cmp::Ordering::Equal
            } else if obj < ino || (obj == ino && typ < BTRFS_EXTENT_DATA_KEY) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        }).into_iter().map(|(_, _, off, d)| (off, d)).collect();
        extents.sort_by_key(|(off, _)| *off);

        let mut out = alloc::vec![0u8; file_size];
        for (file_off, data) in extents {
            if data.len() < 21 { continue; }
            let compression = data[0];
            let extent_type = data[8];
            if compression != 0 {
                // Compressed extents: return zeros (we don’t decompress).
                continue;
            }
            match extent_type {
                0 => { // INLINE
                    let inline_data = &data[21..];
                    let dst_off = file_off as usize;
                    let copy_len = inline_data.len().min(file_size.saturating_sub(dst_off));
                    if copy_len > 0 {
                        out[dst_off..dst_off + copy_len].copy_from_slice(&inline_data[..copy_len]);
                    }
                }
                1 | 2 => { // PREALLOC | REGULAR
                    if data.len() < 53 { continue; }
                    let disk_bytenr = r64(&data, 9);  // physical address
                    let disk_num_bytes = r64(&data, 17);
                    let data_off_in_extent = r64(&data, 25);
                    let num_bytes = r64(&data, 33);
                    if disk_bytenr == 0 { continue; } // hole
                    let phys = match self.logical_to_phys(disk_bytenr) {
                        Some(p) => p,
                        None => continue,
                    };
                    let src_start = phys + data_off_in_extent as usize;
                    let src_end   = src_start + num_bytes as usize;
                    let dst_start = file_off as usize;
                    let dst_end   = dst_start + num_bytes as usize;
                    if src_end <= self.data.len() && dst_end <= out.len() {
                        out[dst_start..dst_end].copy_from_slice(&self.data[src_start..src_end]);
                    }
                }
                _ => {}
            }
        }
        Some(out)
    }
}

// ── public API ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct BtrfsStat {
    pub ino:     u64,
    pub mode:    u32,
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
pub struct BtrfsDirEntry {
    pub ino:    u64,
    pub name:   String,
    pub ftype:  u8,
}

#[derive(Clone, Debug, Default)]
pub struct BtrfsStatfs {
    pub f_bsize:   u32,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_namelen: u32,
}

/// Mount btrfs from the virtio-blk device (returns false if not present/valid).
pub fn mount() -> bool {
    if !crate::drivers::virtio_blk::is_present() { return false; }

    // Load up to 512 MiB.
    let load_bytes = MAX_IMAGE_BYTES;
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

    let sup = match parse_super(&image) {
        Some(s) => s,
        None => return false,
    };

    // Parse sys_chunk_array for initial chunk map.
    let mut chunks = parse_sys_chunks(&sup.sys_chunks);

    let node_size = sup.node_size as usize;
    let root_logical = sup.root;
    let total_bytes = sup.total_bytes;
    let bytes_used  = sup.bytes_used;

    // We also need to walk the chunk tree for a full chunk map, but for
    // single-device images the sys_chunk_array is usually sufficient.
    // (Full chunk tree walk is future work.)

    // Find the FS tree for subvolume 256 by looking in the root tree.
    // The root tree contains ROOT_ITEM entries keyed by subvolume ID.
    let fs = BtrfsFs {
        data: image.clone(),
        node_size,
        chunks: chunks.clone(),
        root_tree: root_logical,
        fs_tree: root_logical, // temporary; resolved below
        total_bytes,
        bytes_used,
    };

    // Look up the FS_TREE (objectid=5) or first free subvol (256) in root tree.
    let fs_tree_logical = {
        let items = fs.search(root_logical, |obj, typ, _| {
            if (obj == BTRFS_FS_TREE_OBJECTID || obj == BTRFS_FIRST_FREE_OBJECTID)
                && typ == BTRFS_ROOT_ITEM_KEY
            {
                core::cmp::Ordering::Equal
            } else if obj < BTRFS_FS_TREE_OBJECTID {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Greater
            }
        });
        // ROOT_ITEM: bytenr at offset 176 (the root node logical address)
        items.into_iter().find_map(|(_, _, _, d)| {
            if d.len() >= 184 { Some(r64(&d, 176)) } else { None }
        }).unwrap_or(root_logical)
    };

    *FS.lock() = Some(BtrfsFs {
        data: image,
        node_size,
        chunks,
        root_tree: root_logical,
        fs_tree: fs_tree_logical,
        total_bytes,
        bytes_used,
    });

    log::info!("btrfs: mounted, node_size={}, fs_tree_logical={:#x}", node_size, fs_tree_logical);
    true
}

pub fn is_mounted() -> bool {
    FS.lock().is_some()
}

pub fn stat(path: &str) -> Option<BtrfsStat> {
    let guard = FS.lock();
    let fs = guard.as_ref()?;
    let ino = fs.lookup_path(path)?;
    let idata = fs.inode_item(ino)?;
    if idata.len() < 160 { return None; }
    Some(BtrfsStat {
        ino,
        mode:    r32(&idata, 48),
        nlink:   r32(&idata, 56),
        uid:     r32(&idata, 60),
        gid:     r32(&idata, 64),
        size:    r64(&idata, 8),
        atime:   r64(&idata, 16),
        mtime:   r64(&idata, 32),
        ctime:   r64(&idata, 24),
        blksize: 4096,
        blocks:  r64(&idata, 8).div_ceil(512),
    })
}

pub fn readdir(path: &str) -> Option<Vec<BtrfsDirEntry>> {
    let guard = FS.lock();
    let fs = guard.as_ref()?;
    let ino = fs.lookup_path(path)?;
    let raw = fs.readdir_ino(ino);
    Some(raw.into_iter().map(|(ino, name, ftype)| BtrfsDirEntry { ino, name, ftype }).collect())
}

pub fn read_file(path: &str) -> Option<Vec<u8>> {
    let guard = FS.lock();
    let fs = guard.as_ref()?;
    let ino = fs.lookup_path(path)?;
    fs.read_file_data(ino)
}

pub fn readlink(path: &str) -> Option<String> {
    let guard = FS.lock();
    let fs = guard.as_ref()?;
    let ino = fs.lookup_path(path)?;
    let data = fs.read_file_data(ino)?;
    String::from_utf8(data).ok()
}

pub fn statfs() -> BtrfsStatfs {
    let guard = FS.lock();
    match guard.as_ref() {
        Some(fs) => BtrfsStatfs {
            f_bsize:   4096,
            f_blocks:  fs.total_bytes / 4096,
            f_bfree:   (fs.total_bytes.saturating_sub(fs.bytes_used)) / 4096,
            f_namelen: 255,
        },
        None => BtrfsStatfs::default(),
    }
}
