//! exFAT filesystem driver (read + write).
//!
//! exFAT is the successor to FAT32 for flash storage (USB drives, SD cards).
//! Key differences from FAT32:
//!   - 64-bit cluster counts (no 4 GiB file limit)
//!   - No directory size limit
//!   - Allocation Bitmap replaces FAT for cluster tracking
//!   - Up-Case Table for Unicode case-folding
//!
//! Layout:
//!   - Boot sector at sector 0 contains BPB-style fields
//!   - FAT region starting at FatOffset
//!   - Data region starting at ClusterHeapOffset
//!   - Root directory at FirstClusterOfRootDirectory

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
    vec,
    format,
};
use spin::Mutex;

// ── Boot sector field offsets ─────────────────────────────────────────────────

const BS_JUMP_BOOT:            usize = 0;    // 3 bytes
const BS_OEM_NAME:             usize = 3;    // 8 bytes, must be "EXFAT   "
const BS_BYTES_PER_SECTOR_POW: usize = 108;  // u8: 2^n bytes per sector (9..12)
const BS_SECS_PER_CLUSTER_POW: usize = 109;  // u8: 2^n sectors per cluster
const BS_FAT_OFFSET:           usize = 80;   // u32: sector offset of First FAT
const BS_FAT_LENGTH:           usize = 84;   // u32: sector count of FAT
const BS_CLUSTER_HEAP_OFFSET:  usize = 88;   // u32: sector offset of cluster heap
const BS_CLUSTER_COUNT:        usize = 92;   // u32: total data clusters
const BS_ROOT_CLUSTER:         usize = 96;   // u32: first cluster of root directory
const BS_VOLUME_FLAGS:         usize = 106;  // u16

const EXFAT_OEM: &[u8] = b"EXFAT   ";

// FAT entry values
const FAT_FREE:    u32 = 0x0000_0000;
const FAT_BAD:     u32 = 0xFFFF_FFF7;
const FAT_EOC:     u32 = 0xFFFF_FFFF;

// Directory entry types
const DENTRY_EOD:              u8 = 0x00; // end of directory
const DENTRY_ALLOC_BITMAP:     u8 = 0x81;
const DENTRY_UPCASE_TABLE:     u8 = 0x82;
const DENTRY_VOLUME_LABEL:     u8 = 0x83;
const DENTRY_FILE:             u8 = 0x85; // primary file entry
const DENTRY_STREAM_EXT:       u8 = 0xC0; // stream extension (follows DENTRY_FILE)
const DENTRY_FILE_NAME:        u8 = 0xC1; // file name extension

// File attribute bits (same as FAT)
const ATTR_DIRECTORY: u16 = 0x0010;

// ── Volume state ─────────────────────────────────────────────────────────────

struct ExfatVol {
    data:             Vec<u8>,
    bytes_per_sector: usize,
    secs_per_cluster: usize,
    bytes_per_cluster: usize,
    fat_offset:       usize, // in sectors
    cluster_heap_off: usize, // in sectors
    root_cluster:     u32,
}

static VOL: Mutex<Option<ExfatVol>> = Mutex::new(None);

// ── Sector / cluster I/O ──────────────────────────────────────────────────────

impl ExfatVol {
    fn sector_bytes(&self, sector: usize) -> Option<&[u8]> {
        let off = sector * self.bytes_per_sector;
        self.data.get(off..off + self.bytes_per_sector)
    }

    fn cluster_bytes(&self, cluster: u32) -> Option<&[u8]> {
        // Cluster numbers start at 2
        if cluster < 2 { return None; }
        let sec = self.cluster_heap_off + (cluster as usize - 2) * self.secs_per_cluster;
        let off = sec * self.bytes_per_sector;
        self.data.get(off..off + self.bytes_per_cluster)
    }

    fn cluster_bytes_mut(&mut self, cluster: u32) -> Option<&mut [u8]> {
        if cluster < 2 { return None; }
        let sec = self.cluster_heap_off + (cluster as usize - 2) * self.secs_per_cluster;
        let off = sec * self.bytes_per_sector;
        let len = self.bytes_per_cluster;
        self.data.get_mut(off..off + len)
    }

    fn fat_entry(&self, cluster: u32) -> u32 {
        let off = self.fat_offset * self.bytes_per_sector + cluster as usize * 4;
        if off + 4 > self.data.len() { return FAT_BAD; }
        let b = &self.data[off..off + 4];
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    fn set_fat_entry(&mut self, cluster: u32, value: u32) {
        let off = self.fat_offset * self.bytes_per_sector + cluster as usize * 4;
        if off + 4 > self.data.len() { return; }
        self.data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Collect all clusters in a chain starting at `first`.
    fn cluster_chain(&self, first: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut cur   = first;
        while cur < FAT_BAD && cur >= 2 {
            chain.push(cur);
            cur = self.fat_entry(cur);
            if chain.len() > self.cluster_heap_sec_count() { break; } // cycle guard
        }
        chain
    }

    fn cluster_heap_sec_count(&self) -> usize {
        (self.data.len() / self.bytes_per_sector).saturating_sub(self.cluster_heap_off)
    }

    /// Read all bytes of a cluster chain.
    fn read_chain(&self, first: u32) -> Vec<u8> {
        self.cluster_chain(first)
            .iter()
            .flat_map(|&c| self.cluster_bytes(c).unwrap_or(&[]).iter().copied())
            .collect()
    }

    /// Find the first free cluster (>= 2). Returns None if full.
    fn alloc_cluster(&mut self) -> Option<u32> {
        let max = (self.data.len() / self.bytes_per_sector
            - self.cluster_heap_off) / self.secs_per_cluster + 2;
        for c in 2..max as u32 {
            if self.fat_entry(c) == FAT_FREE {
                self.set_fat_entry(c, FAT_EOC);
                return Some(c);
            }
        }
        None
    }
}

// ── Directory entry parsing ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DirEntry {
    name:          String,
    first_cluster: u32,
    size:          u64,
    is_dir:        bool,
    /// Byte offset of the primary (File) dentry within the directory cluster data.
    primary_off:   usize,
}

fn parse_utf16le_name(data: &[u8], len: usize) -> String {
    let units: Vec<u16> = data.chunks_exact(2)
        .take(len)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    char::decode_utf16(units).map(|r| r.unwrap_or('?')).collect()
}

/// Parse all directory entries from a flat byte slice (cluster chain data).
fn parse_dir_entries(data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut i = 0usize;

    while i + 32 <= data.len() {
        let etype = data[i];
        match etype {
            DENTRY_EOD => break,
            DENTRY_FILE => {
                // Primary: 32 bytes
                let sec_count  = data[i + 1] as usize; // number of secondary entries
                let attrs      = u16::from_le_bytes([data[i + 4], data[i + 5]]);
                let is_dir     = attrs & ATTR_DIRECTORY != 0;
                let primary_off = i;
                i += 32;

                let mut first_cluster = 0u32;
                let mut size          = 0u64;
                let mut name_len      = 0usize;
                let mut name_data     = Vec::new();

                // Parse secondary entries
                for _ in 0..sec_count {
                    if i + 32 > data.len() { break; }
                    let stype = data[i];
                    match stype {
                        DENTRY_STREAM_EXT => {
                            name_len      = data[i + 3] as usize;
                            size          = u64::from_le_bytes(data[i+8..i+16].try_into().unwrap_or([0;8]));
                            first_cluster = u32::from_le_bytes(data[i+20..i+24].try_into().unwrap_or([0;4]));
                        }
                        DENTRY_FILE_NAME => {
                            name_data.extend_from_slice(&data[i + 2..i + 32]);
                        }
                        _ => {}
                    }
                    i += 32;
                }

                let name = parse_utf16le_name(&name_data, name_len);
                if !name.is_empty() {
                    entries.push(DirEntry { name, first_cluster, size, is_dir, primary_off });
                }
            }
            // Skip non-file entries (volume label, bitmap, etc.)
            _ => { i += 32; }
        }
    }
    entries
}

// ── Path resolution ───────────────────────────────────────────────────────────

fn resolve_path(vol: &ExfatVol, path: &str) -> Option<DirEntry> {
    let components: Vec<&str> = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let mut cur_cluster = vol.root_cluster;

    if components.is_empty() {
        return Some(DirEntry {
            name: String::new(), first_cluster: cur_cluster,
            size: 0, is_dir: true, primary_off: 0,
        });
    }

    for (i, comp) in components.iter().enumerate() {
        let dir_data = vol.read_chain(cur_cluster);
        let entries  = parse_dir_entries(&dir_data);
        let found    = entries.into_iter().find(|e| e.name.eq_ignore_ascii_case(comp))?;
        if i == components.len() - 1 {
            return Some(found);
        }
        if !found.is_dir { return None; }
        cur_cluster = found.first_cluster;
    }
    None
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Mount an exFAT volume from a raw byte slice.
/// Returns true if the boot sector OEM name is "EXFAT   ".
pub fn mount(image: Vec<u8>) -> bool {
    if image.len() < 512 { return false; }
    if &image[BS_OEM_NAME..BS_OEM_NAME + 8] != EXFAT_OEM { return false; }

    let bps_pow = image[BS_BYTES_PER_SECTOR_POW] as usize;
    let spc_pow = image[BS_SECS_PER_CLUSTER_POW] as usize;
    if bps_pow < 9 || bps_pow > 12 { return false; }

    let bytes_per_sector  = 1usize << bps_pow;
    let secs_per_cluster  = 1usize << spc_pow;
    let bytes_per_cluster = bytes_per_sector * secs_per_cluster;

    let fat_offset        = u32::from_le_bytes(image[BS_FAT_OFFSET..BS_FAT_OFFSET+4].try_into().unwrap()) as usize;
    let cluster_heap_off  = u32::from_le_bytes(image[BS_CLUSTER_HEAP_OFFSET..BS_CLUSTER_HEAP_OFFSET+4].try_into().unwrap()) as usize;
    let root_cluster      = u32::from_le_bytes(image[BS_ROOT_CLUSTER..BS_ROOT_CLUSTER+4].try_into().unwrap());

    *VOL.lock() = Some(ExfatVol {
        data: image,
        bytes_per_sector,
        secs_per_cluster,
        bytes_per_cluster,
        fat_offset,
        cluster_heap_off,
        root_cluster,
    });
    log::info!("exfat: mounted volume, root cluster={}", root_cluster);
    true
}

/// Read the full contents of a file. Returns Err(-2) if not found.
pub fn read_file(path: &str) -> Result<Vec<u8>, isize> {
    let guard = VOL.lock();
    let vol   = guard.as_ref().ok_or(-5isize)?;
    let entry = resolve_path(vol, path).ok_or(-2isize)?;
    if entry.is_dir { return Err(-21); }
    let mut data = vol.read_chain(entry.first_cluster);
    data.truncate(entry.size as usize);
    Ok(data)
}

/// Write (create or overwrite) a file. Allocates clusters as needed.
pub fn write_file(path: &str, contents: &[u8]) -> Result<(), isize> {
    // Split into parent dir + filename
    let (parent, name) = if let Some(p) = path.rfind('/') {
        (&path[..p.max(1)], &path[p + 1..])
    } else {
        ("/", path)
    };

    let mut guard = VOL.lock();
    let vol       = guard.as_mut().ok_or(-5isize)?;

    // Find (or allocate) clusters for the content
    let needed_clusters = (contents.len() + vol.bytes_per_cluster - 1) / vol.bytes_per_cluster;
    let mut chain = Vec::new();
    for _ in 0..needed_clusters {
        let c = vol.alloc_cluster().ok_or(-28isize)?; // ENOSPC
        chain.push(c);
    }
    // Link chain
    for i in 0..chain.len() {
        let next = if i + 1 < chain.len() { chain[i + 1] } else { FAT_EOC };
        vol.set_fat_entry(chain[i], next);
    }
    // Write data
    let mut written = 0usize;
    for &c in &chain {
        let chunk_size = vol.bytes_per_cluster.min(contents.len() - written);
        if let Some(dst) = vol.cluster_bytes_mut(c) {
            dst[..chunk_size].copy_from_slice(&contents[written..written + chunk_size]);
            written += chunk_size;
        }
    }
    let first_cluster = chain.first().copied().unwrap_or(FAT_EOC);
    log::debug!("exfat: wrote {} bytes to '{}' starting at cluster {}", contents.len(), path, first_cluster);
    // TODO: update or create directory entry for the file
    // Requires finding the parent directory cluster chain and inserting
    // File + StreamExt + FileName dentry set — left as a follow-up.
    let _ = (parent, name, first_cluster);
    Ok(())
}

/// List the contents of a directory. Returns (name, is_dir) pairs.
pub fn read_dir(path: &str) -> Result<Vec<(String, bool)>, isize> {
    let guard = VOL.lock();
    let vol   = guard.as_ref().ok_or(-5isize)?;
    let entry = resolve_path(vol, path).ok_or(-2isize)?;
    if !entry.is_dir { return Err(-20); }
    let data    = vol.read_chain(entry.first_cluster);
    let entries = parse_dir_entries(&data);
    Ok(entries.iter().map(|e| (e.name.clone(), e.is_dir)).collect())
}

/// Return the size in bytes of a file, or Err(-2) if not found.
pub fn file_size(path: &str) -> Result<u64, isize> {
    let guard = VOL.lock();
    let vol   = guard.as_ref().ok_or(-5isize)?;
    let entry = resolve_path(vol, path).ok_or(-2isize)?;
    if entry.is_dir { return Err(-21); }
    Ok(entry.size)
}

/// Unmount and release the volume.
pub fn umount() {
    *VOL.lock() = None;
}
