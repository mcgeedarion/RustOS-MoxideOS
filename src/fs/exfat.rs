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
//!   - Boot sector at sector 0 contains BPP-style fields
//!   - FAT region starting at FatOffset
//!   - Data region starting at ClusterHeapOffset
//!   - Root directory at FirstClusterOfRootDirectory

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use spin::Mutex;

const BS_JUMP_BOOT: usize = 0; // 3 bytes
const BS_OEM_NAME: usize = 3; // 8 bytes, must be "EXFAT   "
const BS_BYTES_PER_SECTOR_POW: usize = 108; // u8: 2^n bytes per sector (9..12)
const BS_SECS_PER_CLUSTER_POW: usize = 109; // u8: 2^n sectors per cluster
const BS_FAT_OFFSET: usize = 80; // u32: sector offset of First FAT
const BS_FAT_LENGTH: usize = 84; // u32: sector count of FAT
const BS_CLUSTER_HEAP_OFFSET: usize = 88; // u32: sector offset of cluster heap
const BS_CLUSTER_COUNT: usize = 92; // u32: total data clusters
const BS_ROOT_CLUSTER: usize = 96; // u32: first cluster of root directory
const BS_VOLUME_FLAGS: usize = 106; // u16

const EXFAT_OEM: &[u8] = b"EXFAT   ";

// FAT entry values
const FAT_FREE: u32 = 0x0000_0000;
const FAT_BAD: u32 = 0xFFFF_FFF7;
const FAT_EOC: u32 = 0xFFFF_FFFF;

// Directory entry types
const DENTRY_EOD: u8 = 0x00; // end of directory
const DENTRY_ALLOC_BITMAP: u8 = 0x81;
const DENTRY_UPCASE_TABLE: u8 = 0x82;
const DENTRY_VOLUME_LABEL: u8 = 0x83;
const DENTRY_FILE: u8 = 0x85; // primary file entry
const DENTRY_STREAM_EXT: u8 = 0xC0; // stream extension (follows DENTRY_FILE)
const DENTRY_FILE_NAME: u8 = 0xC1; // file name extension

const DENTRY_SIZE: usize = 32;
const FILE_NAME_CHARS_PER_DENTRY: usize = 15;
const MAX_FILE_NAME_UTF16_UNITS: usize = 255;

// File attribute bits
const ATTR_DIRECTORY: u16 = 0x0010;
const ATTR_ARCHIVE: u16 = 0x0020;

struct ExfatVol {
    data: Vec<u8>,
    bytes_per_sector: usize,
    secs_per_cluster: usize,
    bytes_per_cluster: usize,
    fat_offset: usize,       // in sectors
    cluster_heap_off: usize, // in sectors
    root_cluster: u32,
}

static VOL: Mutex<Option<ExfatVol>> = Mutex::new(None);

impl ExfatVol {
    fn sector_bytes(&self, sector: usize) -> Option<&[u8]> {
        let off = sector * self.bytes_per_sector;
        self.data.get(off..off + self.bytes_per_sector)
    }

    fn cluster_offset(&self, cluster: u32) -> Option<usize> {
        // Cluster numbers start at 2.
        if cluster < 2 {
            return None;
        }

        let sec = self.cluster_heap_off + (cluster as usize - 2) * self.secs_per_cluster;
        let off = sec * self.bytes_per_sector;

        if off + self.bytes_per_cluster <= self.data.len() {
            Some(off)
        } else {
            None
        }
    }

    fn cluster_bytes(&self, cluster: u32) -> Option<&[u8]> {
        let off = self.cluster_offset(cluster)?;
        self.data.get(off..off + self.bytes_per_cluster)
    }

    fn cluster_bytes_mut(&mut self, cluster: u32) -> Option<&mut [u8]> {
        let off = self.cluster_offset(cluster)?;
        self.data.get_mut(off..off + self.bytes_per_cluster)
    }

    fn fat_entry(&self, cluster: u32) -> u32 {
        let off = self.fat_offset * self.bytes_per_sector + cluster as usize * 4;
        if off + 4 > self.data.len() {
            return FAT_BAD;
        }

        let b = &self.data[off..off + 4];
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    fn set_fat_entry(&mut self, cluster: u32, value: u32) {
        let off = self.fat_offset * self.bytes_per_sector + cluster as usize * 4;
        if off + 4 > self.data.len() {
            return;
        }

        self.data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Collect all clusters in a chain starting at `first`.
    fn cluster_chain(&self, first: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut cur = first;

        while cur < FAT_BAD && cur >= 2 {
            chain.push(cur);
            cur = self.fat_entry(cur);

            // Cycle guard.
            if chain.len() > self.cluster_heap_sec_count() {
                break;
            }
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
        let max = (self.data.len() / self.bytes_per_sector - self.cluster_heap_off)
            / self.secs_per_cluster
            + 2;

        for c in 2..max as u32 {
            if self.fat_entry(c) == FAT_FREE {
                self.set_fat_entry(c, FAT_EOC);

                if let Some(bytes) = self.cluster_bytes_mut(c) {
                    bytes.fill(0);
                }

                return Some(c);
            }
        }

        None
    }

    fn free_chain(&mut self, first: u32) {
        let chain = self.cluster_chain(first);

        for c in chain {
            self.set_fat_entry(c, FAT_FREE);
        }
    }

    fn dir_entry_abs_off(&self, dir_first_cluster: u32, dir_relative_off: usize) -> Option<usize> {
        let chain = self.cluster_chain(dir_first_cluster);
        let cluster_index = dir_relative_off / self.bytes_per_cluster;
        let within_cluster = dir_relative_off % self.bytes_per_cluster;
        let cluster = *chain.get(cluster_index)?;

        Some(self.cluster_offset(cluster)? + within_cluster)
    }
}

#[derive(Debug, Clone)]
struct DirEntry {
    name: String,
    first_cluster: u32,
    size: u64,
    is_dir: bool,
    /// Byte offset of the primary File dentry within the directory cluster-chain data.
    primary_off: usize,
    secondary_count: usize,
}

fn parse_utf16le_name(data: &[u8], len: usize) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .take(len)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();

    char::decode_utf16(units)
        .map(|r| r.unwrap_or('?'))
        .collect()
}

/// Parse all directory entries from a flat byte slice.
fn parse_dir_entries(data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut i = 0usize;

    while i + DENTRY_SIZE <= data.len() {
        let etype = data[i];

        match etype {
            DENTRY_EOD => break,

            DENTRY_FILE => {
                let sec_count = data[i + 1] as usize;
                let attrs = u16::from_le_bytes([data[i + 4], data[i + 5]]);
                let is_dir = attrs & ATTR_DIRECTORY != 0;
                let primary_off = i;

                i += DENTRY_SIZE;

                let mut first_cluster = 0u32;
                let mut size = 0u64;
                let mut name_len = 0usize;
                let mut name_data = Vec::new();

                for _ in 0..sec_count {
                    if i + DENTRY_SIZE > data.len() {
                        break;
                    }

                    let stype = data[i];

                    match stype {
                        DENTRY_STREAM_EXT => {
                            name_len = data[i + 3] as usize;

                            size = u64::from_le_bytes(
                                data[i + 8..i + 16].try_into().unwrap_or([0; 8]),
                            );

                            first_cluster = u32::from_le_bytes(
                                data[i + 20..i + 24].try_into().unwrap_or([0; 4]),
                            );
                        }

                        DENTRY_FILE_NAME => {
                            name_data.extend_from_slice(&data[i + 2..i + 32]);
                        }

                        _ => {}
                    }

                    i += DENTRY_SIZE;
                }

                let name = parse_utf16le_name(&name_data, name_len);

                if !name.is_empty() {
                    entries.push(DirEntry {
                        name,
                        first_cluster,
                        size,
                        is_dir,
                        primary_off,
                        secondary_count: sec_count,
                    });
                }
            }

            // Skip non-file entries: volume label, bitmap, upcase table, deleted entries, etc.
            _ => {
                i += DENTRY_SIZE;
            }
        }
    }

    entries
}

fn resolve_path(vol: &ExfatVol, path: &str) -> Option<DirEntry> {
    let components: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    let mut cur_cluster = vol.root_cluster;

    if components.is_empty() {
        return Some(DirEntry {
            name: String::new(),
            first_cluster: cur_cluster,
            size: 0,
            is_dir: true,
            primary_off: 0,
            secondary_count: 0,
        });
    }

    for (i, comp) in components.iter().enumerate() {
        let dir_data = vol.read_chain(cur_cluster);
        let entries = parse_dir_entries(&dir_data);

        let found = entries
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(comp))?;

        if i == components.len() - 1 {
            return Some(found);
        }

        if !found.is_dir {
            return None;
        }

        cur_cluster = found.first_cluster;
    }

    None
}

fn resolve_parent_dir(vol: &ExfatVol, parent: &str) -> Option<DirEntry> {
    let entry = resolve_path(vol, parent)?;

    if entry.is_dir {
        Some(entry)
    } else {
        None
    }
}

fn utf16_name_units(name: &str) -> Result<Vec<u16>, isize> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(-22); // EINVAL
    }

    let units: Vec<u16> = name.encode_utf16().collect();

    if units.is_empty() || units.len() > MAX_FILE_NAME_UTF16_UNITS {
        return Err(-36); // ENAMETOOLONG
    }

    Ok(units)
}

fn name_hash(units: &[u16]) -> u16 {
    let mut hash = 0u16;

    for unit in units {
        for b in unit.to_le_bytes() {
            hash = ((hash & 1) << 15) | (hash >> 1);
            hash = hash.wrapping_add(b as u16);
        }
    }

    hash
}

fn entry_set_checksum(entries: &[u8]) -> u16 {
    let mut checksum = 0u16;

    for (i, b) in entries.iter().enumerate() {
        // Skip primary File entry SetChecksum field.
        if i == 2 || i == 3 {
            continue;
        }

        checksum = ((checksum & 1) << 15) | (checksum >> 1);
        checksum = checksum.wrapping_add(*b as u16);
    }

    checksum
}

fn build_file_dentries(name: &str, first_cluster: u32, size: u64) -> Result<Vec<u8>, isize> {
    let name_units = utf16_name_units(name)?;

    let filename_entries =
        (name_units.len() + FILE_NAME_CHARS_PER_DENTRY - 1) / FILE_NAME_CHARS_PER_DENTRY;

    let secondary_count = 1 + filename_entries;

    if secondary_count > u8::MAX as usize {
        return Err(-36); // ENAMETOOLONG
    }

    let total_entries = 1 + secondary_count;
    let mut entries = vec![0u8; total_entries * DENTRY_SIZE];

    // Primary File entry.
    entries[0] = DENTRY_FILE;
    entries[1] = secondary_count as u8;
    entries[4..6].copy_from_slice(&ATTR_ARCHIVE.to_le_bytes());

    // Stream Extension secondary entry.
    let stream_off = DENTRY_SIZE;
    entries[stream_off] = DENTRY_STREAM_EXT;
    entries[stream_off + 1] = 0x01; // allocation possible, FAT chain is used
    entries[stream_off + 3] = name_units.len() as u8;
    entries[stream_off + 4..stream_off + 6].copy_from_slice(&name_hash(&name_units).to_le_bytes());

    // ValidDataLength.
    entries[stream_off + 8..stream_off + 16].copy_from_slice(&size.to_le_bytes());

    // FirstCluster.
    entries[stream_off + 20..stream_off + 24].copy_from_slice(&first_cluster.to_le_bytes());

    // DataLength.
    entries[stream_off + 24..stream_off + 32].copy_from_slice(&size.to_le_bytes());

    // FileName secondary entries.
    for entry_idx in 0..filename_entries {
        let entry_off = (2 + entry_idx) * DENTRY_SIZE;

        entries[entry_off] = DENTRY_FILE_NAME;
        entries[entry_off + 1] = 0x00;

        for char_idx in 0..FILE_NAME_CHARS_PER_DENTRY {
            let unit_idx = entry_idx * FILE_NAME_CHARS_PER_DENTRY + char_idx;

            if unit_idx >= name_units.len() {
                break;
            }

            let dst = entry_off + 2 + char_idx * 2;
            entries[dst..dst + 2].copy_from_slice(&name_units[unit_idx].to_le_bytes());
        }
    }

    let checksum = entry_set_checksum(&entries);
    entries[2..4].copy_from_slice(&checksum.to_le_bytes());

    Ok(entries)
}

fn mark_dentry_range_deleted(
    vol: &mut ExfatVol,
    dir_first_cluster: u32,
    dir_relative_off: usize,
    entry_count: usize,
) {
    for idx in 0..entry_count {
        let rel = dir_relative_off + idx * DENTRY_SIZE;

        if let Some(abs_off) = vol.dir_entry_abs_off(dir_first_cluster, rel) {
            if abs_off < vol.data.len() {
                // exFAT marks deleted entries by clearing the high bit of EntryType.
                vol.data[abs_off] &= 0x7F;
            }
        }
    }
}

fn find_free_dentry_run(dir_data: &[u8], needed_entries: usize) -> Option<usize> {
    if needed_entries == 0 {
        return None;
    }

    let needed_len = needed_entries * DENTRY_SIZE;
    let mut i = 0usize;
    let mut run_start = 0usize;
    let mut run_len = 0usize;

    while i + DENTRY_SIZE <= dir_data.len() {
        let entry_type = dir_data[i];

        // EOD and deleted entries are available.
        if entry_type == DENTRY_EOD || entry_type & 0x80 == 0 {
            if run_len == 0 {
                run_start = i;
            }

            run_len += DENTRY_SIZE;

            if run_len >= needed_len {
                return Some(run_start);
            }

            if entry_type == DENTRY_EOD {
                let remaining = dir_data.len().saturating_sub(i + DENTRY_SIZE);

                if run_len + remaining >= needed_len {
                    return Some(run_start);
                }

                return None;
            }
        } else {
            run_len = 0;
        }

        i += DENTRY_SIZE;
    }

    None
}

fn write_dentries_to_dir(
    vol: &mut ExfatVol,
    dir_first_cluster: u32,
    dir_relative_off: usize,
    dentries: &[u8],
) -> Result<(), isize> {
    let mut written = 0usize;

    while written < dentries.len() {
        let abs_off = vol
            .dir_entry_abs_off(dir_first_cluster, dir_relative_off + written)
            .ok_or(-28isize)?; // ENOSPC / no room in directory chain

        let cluster_remaining =
            vol.bytes_per_cluster - ((dir_relative_off + written) % vol.bytes_per_cluster);

        let chunk_len = cluster_remaining.min(dentries.len() - written);

        if abs_off + chunk_len > vol.data.len() {
            return Err(-5); // EIO
        }

        vol.data[abs_off..abs_off + chunk_len]
            .copy_from_slice(&dentries[written..written + chunk_len]);

        written += chunk_len;
    }

    Ok(())
}

fn free_allocated_clusters(vol: &mut ExfatVol, chain: &[u32]) {
    for &cluster in chain {
        vol.set_fat_entry(cluster, FAT_FREE);
    }
}

/// Mount an exFAT volume from a raw byte slice.
/// Returns true if the boot sector OEM name is "EXFAT   ".
pub fn mount(image: Vec<u8>) -> bool {
    if image.len() < 512 {
        return false;
    }

    if &image[BS_OEM_NAME..BS_OEM_NAME + 8] != EXFAT_OEM {
        return false;
    }

    let bps_pow = image[BS_BYTES_PER_SECTOR_POW] as usize;
    let spc_pow = image[BS_SECS_PER_CLUSTER_POW] as usize;

    if bps_pow < 9 || bps_pow > 12 {
        return false;
    }

    let bytes_per_sector = 1usize << bps_pow;
    let secs_per_cluster = 1usize << spc_pow;
    let bytes_per_cluster = bytes_per_sector * secs_per_cluster;

    let fat_offset =
        u32::from_le_bytes(image[BS_FAT_OFFSET..BS_FAT_OFFSET + 4].try_into().unwrap()) as usize;

    let cluster_heap_off = u32::from_le_bytes(
        image[BS_CLUSTER_HEAP_OFFSET..BS_CLUSTER_HEAP_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    let root_cluster = u32::from_le_bytes(
        image[BS_ROOT_CLUSTER..BS_ROOT_CLUSTER + 4]
            .try_into()
            .unwrap(),
    );

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
    let vol = guard.as_ref().ok_or(-5isize)?;

    let entry = resolve_path(vol, path).ok_or(-2isize)?;

    if entry.is_dir {
        return Err(-21); // EISDIR
    }

    let mut data = vol.read_chain(entry.first_cluster);
    data.truncate(entry.size as usize);

    Ok(data)
}

/// Write, create, or overwrite a file. Allocates clusters and writes the
/// File + Stream Extension + FileName dentry set into the parent directory.
pub fn write_file(path: &str, contents: &[u8]) -> Result<(), isize> {
    let (parent, name) = if let Some(p) = path.rfind('/') {
        (&path[..p.max(1)], &path[p + 1..])
    } else {
        ("/", path)
    };

    let mut guard = VOL.lock();
    let vol = guard.as_mut().ok_or(-5isize)?;

    utf16_name_units(name)?;

    let parent_entry = resolve_parent_dir(vol, parent).ok_or(-2isize)?;
    let parent_cluster = parent_entry.first_cluster;

    let dir_data = vol.read_chain(parent_cluster);
    let entries = parse_dir_entries(&dir_data);

    let existing = entries
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
        .cloned();

    if existing.as_ref().map(|entry| entry.is_dir).unwrap_or(false) {
        return Err(-21); // EISDIR
    }

    let needed_clusters = if contents.is_empty() {
        0
    } else {
        (contents.len() + vol.bytes_per_cluster - 1) / vol.bytes_per_cluster
    };

    let mut chain = Vec::new();

    for _ in 0..needed_clusters {
        let cluster = vol.alloc_cluster().ok_or(-28isize)?; // ENOSPC
        chain.push(cluster);
    }

    for i in 0..chain.len() {
        let next = if i + 1 < chain.len() {
            chain[i + 1]
        } else {
            FAT_EOC
        };

        vol.set_fat_entry(chain[i], next);
    }

    let mut written = 0usize;

    for &cluster in &chain {
        let chunk_size = vol.bytes_per_cluster.min(contents.len() - written);

        if let Some(dst) = vol.cluster_bytes_mut(cluster) {
            dst[..chunk_size].copy_from_slice(&contents[written..written + chunk_size]);
            written += chunk_size;
        }
    }

    let first_cluster = chain.first().copied().unwrap_or(0);
    let dentries = build_file_dentries(name, first_cluster, contents.len() as u64)?;
    let new_entry_count = dentries.len() / DENTRY_SIZE;

    let dentry_off = if let Some(ref old) = existing {
        let old_entry_count = 1 + old.secondary_count;
        let old_len = old_entry_count * DENTRY_SIZE;

        if old_len >= dentries.len() {
            old.primary_off
        } else {
            let mut searchable_dir_data = dir_data.clone();

            for idx in 0..old_entry_count {
                let off = old.primary_off + idx * DENTRY_SIZE;
                if off < searchable_dir_data.len() {
                    searchable_dir_data[off] &= 0x7F;
                }
            }

            find_free_dentry_run(&searchable_dir_data, new_entry_count).ok_or(-28isize)?
        }
    } else {
        find_free_dentry_run(&dir_data, new_entry_count).ok_or(-28isize)?
    };

    if let Err(err) = write_dentries_to_dir(vol, parent_cluster, dentry_off, &dentries) {
        free_allocated_clusters(vol, &chain);
        return Err(err);
    }

    if let Some(ref old) = existing {
        let old_entry_count = 1 + old.secondary_count;

        if dentry_off == old.primary_off {
            if old_entry_count > new_entry_count {
                mark_dentry_range_deleted(
                    vol,
                    parent_cluster,
                    old.primary_off + new_entry_count * DENTRY_SIZE,
                    old_entry_count - new_entry_count,
                );
            }
        } else {
            mark_dentry_range_deleted(vol, parent_cluster, old.primary_off, old_entry_count);
        }

        if old.first_cluster >= 2 {
            vol.free_chain(old.first_cluster);
        }
    }

    log::debug!(
        "exfat: wrote {} bytes to '{}' starting at cluster {}",
        contents.len(),
        path,
        first_cluster
    );

    Ok(())
}

/// List the contents of a directory. Returns `(name, is_dir)` pairs.
pub fn read_dir(path: &str) -> Result<Vec<(String, bool)>, isize> {
    let guard = VOL.lock();
    let vol = guard.as_ref().ok_or(-5isize)?;

    let entry = resolve_path(vol, path).ok_or(-2isize)?;

    if !entry.is_dir {
        return Err(-20); // ENOTDIR
    }

    let data = vol.read_chain(entry.first_cluster);
    let entries = parse_dir_entries(&data);

    Ok(entries.iter().map(|e| (e.name.clone(), e.is_dir)).collect())
}

/// Return the size in bytes of a file, or Err(-2) if not found.
pub fn file_size(path: &str) -> Result<u64, isize> {
    let guard = VOL.lock();
    let vol = guard.as_ref().ok_or(-5isize)?;

    let entry = resolve_path(vol, path).ok_or(-2isize)?;

    if entry.is_dir {
        return Err(-21); // EISDIR
    }

    Ok(entry.size)
}

/// Unmount and release the volume.
pub fn umount() {
    *VOL.lock() = None;
}