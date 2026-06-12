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
const DENTRY_EOD: u8 = 0x00;
const DENTRY_ALLOC_BITMAP: u8 = 0x81;
const DENTRY_UPCASE_TABLE: u8 = 0x82;
const DENTRY_VOLUME_LABEL: u8 = 0x83;
const DENTRY_FILE: u8 = 0x85;
const DENTRY_STREAM_EXT: u8 = 0xC0;
const DENTRY_FILE_NAME: u8 = 0xC1;

const DENTRY_SIZE: usize = 32;
const FILE_NAME_CHARS_PER_DENTRY: usize = 15;
const MAX_FILE_NAME_UTF16_UNITS: usize = 255;

// File attribute bits
const ATTR_DIRECTORY: u16 = 0x0010;
const ATTR_ARCHIVE: u16 = 0x0020;

#[derive(Debug, Clone, Copy)]
struct ClusteredExtent {
    first_cluster: u32,
    len: u64,
}

struct ExfatVol {
    data: Vec<u8>,
    bytes_per_sector: usize,
    secs_per_cluster: usize,
    bytes_per_cluster: usize,
    fat_offset: usize,
    fat_length: usize,
    cluster_heap_off: usize,
    cluster_count: u32,
    root_cluster: u32,
    bitmap: Option<ClusteredExtent>,
    upcase: Option<ClusteredExtent>,
}

static VOL: Mutex<Option<ExfatVol>> = Mutex::new(None);

impl ExfatVol {
    fn sector_bytes(&self, sector: usize) -> Option<&[u8]> {
        let off = sector * self.bytes_per_sector;
        self.data.get(off..off + self.bytes_per_sector)
    }

    fn max_cluster_exclusive(&self) -> u32 {
        self.cluster_count.saturating_add(2)
    }

    fn cluster_offset(&self, cluster: u32) -> Option<usize> {
        if cluster < 2 || cluster >= self.max_cluster_exclusive() {
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
        let fat_end = (self.fat_offset + self.fat_length) * self.bytes_per_sector;

        if off + 4 > self.data.len() || off + 4 > fat_end {
            return FAT_BAD;
        }

        let b = &self.data[off..off + 4];
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    fn set_fat_entry(&mut self, cluster: u32, value: u32) {
        let off = self.fat_offset * self.bytes_per_sector + cluster as usize * 4;
        let fat_end = (self.fat_offset + self.fat_length) * self.bytes_per_sector;

        if off + 4 > self.data.len() || off + 4 > fat_end {
            return;
        }

        self.data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn cluster_chain(&self, first: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut cur = first;

        while cur >= 2 && cur < FAT_BAD && cur < self.max_cluster_exclusive() {
            chain.push(cur);

            let next = self.fat_entry(cur);
            if next == FAT_FREE || next >= FAT_BAD {
                break;
            }

            cur = next;

            if chain.len() > self.cluster_count as usize {
                break;
            }
        }

        chain
    }

    fn read_chain(&self, first: u32) -> Vec<u8> {
        self.cluster_chain(first)
            .iter()
            .flat_map(|&c| self.cluster_bytes(c).unwrap_or(&[]).iter().copied())
            .collect()
    }

    fn read_extent(&self, extent: ClusteredExtent) -> Vec<u8> {
        if extent.first_cluster < 2 || extent.len == 0 {
            return Vec::new();
        }

        let mut data = self.read_chain(extent.first_cluster);
        data.truncate(extent.len as usize);
        data
    }

    fn extent_abs_off(&self, extent: ClusteredExtent, rel_off: usize) -> Option<usize> {
        if rel_off >= extent.len as usize {
            return None;
        }

        let chain = self.cluster_chain(extent.first_cluster);
        let cluster_index = rel_off / self.bytes_per_cluster;
        let within_cluster = rel_off % self.bytes_per_cluster;
        let cluster = *chain.get(cluster_index)?;

        Some(self.cluster_offset(cluster)? + within_cluster)
    }

    fn bitmap_cluster_allocated(&self, cluster: u32) -> Option<bool> {
        let bitmap = self.bitmap?;
        let bit_index = cluster.checked_sub(2)? as usize;
        let byte_index = bit_index / 8;
        let bit = bit_index % 8;
        let abs_off = self.extent_abs_off(bitmap, byte_index)?;
        let byte = *self.data.get(abs_off)?;

        Some(byte & (1u8 << bit) != 0)
    }

    fn set_bitmap_cluster_allocated(&mut self, cluster: u32, allocated: bool) {
        let Some(bitmap) = self.bitmap else {
            return;
        };

        let Some(bit_index) = cluster.checked_sub(2).map(|v| v as usize) else {
            return;
        };

        let byte_index = bit_index / 8;
        let bit = bit_index % 8;

        let Some(abs_off) = self.extent_abs_off(bitmap, byte_index) else {
            return;
        };

        let Some(byte) = self.data.get_mut(abs_off) else {
            return;
        };

        if allocated {
            *byte |= 1u8 << bit;
        } else {
            *byte &= !(1u8 << bit);
        }
    }

    fn alloc_cluster(&mut self) -> Option<u32> {
        for c in 2..self.max_cluster_exclusive() {
            let fat_free = self.fat_entry(c) == FAT_FREE;
            let bitmap_free = !self.bitmap_cluster_allocated(c).unwrap_or(false);

            if fat_free && bitmap_free {
                self.set_fat_entry(c, FAT_EOC);
                self.set_bitmap_cluster_allocated(c, true);

                if let Some(bytes) = self.cluster_bytes_mut(c) {
                    bytes.fill(0);
                }

                return Some(c);
            }
        }

        None
    }

    fn free_chain(&mut self, first: u32) {
        if first < 2 {
            return;
        }

        let chain = self.cluster_chain(first);

        for c in chain {
            self.set_fat_entry(c, FAT_FREE);
            self.set_bitmap_cluster_allocated(c, false);
        }
    }

    fn append_clusters_to_chain(&mut self, first: u32, additional: usize) -> Result<(), isize> {
        if first < 2 {
            return Err(-5);
        }

        if additional == 0 {
            return Ok(());
        }

        let chain = self.cluster_chain(first);
        let tail = *chain.last().ok_or(-5isize)?;

        let mut new_clusters = Vec::new();

        for _ in 0..additional {
            match self.alloc_cluster() {
                Some(cluster) => new_clusters.push(cluster),
                None => {
                    free_allocated_clusters(self, &new_clusters);
                    return Err(-28);
                },
            }
        }

        self.set_fat_entry(tail, new_clusters[0]);

        for i in 0..new_clusters.len() {
            let next = if i + 1 < new_clusters.len() {
                new_clusters[i + 1]
            } else {
                FAT_EOC
            };

            self.set_fat_entry(new_clusters[i], next);
        }

        Ok(())
    }

    fn dir_entry_abs_off(&self, dir_first_cluster: u32, dir_relative_off: usize) -> Option<usize> {
        let chain = self.cluster_chain(dir_first_cluster);
        let cluster_index = dir_relative_off / self.bytes_per_cluster;
        let within_cluster = dir_relative_off % self.bytes_per_cluster;
        let cluster = *chain.get(cluster_index)?;

        Some(self.cluster_offset(cluster)? + within_cluster)
    }

    fn upcase_unit(&self, unit: u16) -> u16 {
        let Some(upcase) = self.upcase else {
            return ascii_upcase_unit(unit);
        };

        let table = self.read_extent(upcase);
        let target = unit as usize;
        let mut logical_index = 0usize;
        let mut off = 0usize;

        while off + 2 <= table.len() {
            let value = u16::from_le_bytes([table[off], table[off + 1]]);
            off += 2;

            if value == 0xFFFF {
                if off + 2 > table.len() {
                    break;
                }

                let run_len = u16::from_le_bytes([table[off], table[off + 1]]) as usize;
                off += 2;

                if target >= logical_index && target < logical_index + run_len {
                    return unit;
                }

                logical_index += run_len;
            } else {
                if logical_index == target {
                    return value;
                }

                logical_index += 1;
            }
        }

        ascii_upcase_unit(unit)
    }
}

#[derive(Debug, Clone)]
struct DirEntry {
    name: String,
    first_cluster: u32,
    size: u64,
    is_dir: bool,
    primary_off: usize,
    secondary_count: usize,
    parent_cluster: u32,
}

fn ascii_upcase_unit(unit: u16) -> u16 {
    if unit >= b'a' as u16 && unit <= b'z' as u16 {
        unit - 32
    } else {
        unit
    }
}

fn folded_name_units(vol: &ExfatVol, name: &str) -> Vec<u16> {
    name.encode_utf16()
        .map(|unit| vol.upcase_unit(unit))
        .collect()
}

fn names_equal(vol: &ExfatVol, lhs: &str, rhs: &str) -> bool {
    folded_name_units(vol, lhs) == folded_name_units(vol, rhs)
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

fn parse_dir_entries(data: &[u8], parent_cluster: u32) -> Vec<DirEntry> {
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
                        },

                        DENTRY_FILE_NAME => {
                            name_data.extend_from_slice(&data[i + 2..i + 32]);
                        },

                        _ => {},
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
                        parent_cluster,
                    });
                }
            },

            _ => {
                i += DENTRY_SIZE;
            },
        }
    }

    entries
}

fn discover_metadata(vol: &mut ExfatVol) {
    let data = vol.read_chain(vol.root_cluster);
    let mut i = 0usize;

    while i + DENTRY_SIZE <= data.len() {
        match data[i] {
            DENTRY_EOD => break,

            DENTRY_ALLOC_BITMAP => {
                let flags = data[i + 1];

                // Use the first/main allocation bitmap. TexFAT secondary bitmap has bit 0 set.
                if flags & 0x01 == 0 {
                    let first_cluster =
                        u32::from_le_bytes(data[i + 20..i + 24].try_into().unwrap_or([0; 4]));

                    let len = u64::from_le_bytes(data[i + 24..i + 32].try_into().unwrap_or([0; 8]));

                    vol.bitmap = Some(ClusteredExtent { first_cluster, len });
                }

                i += DENTRY_SIZE;
            },

            DENTRY_UPCASE_TABLE => {
                let first_cluster =
                    u32::from_le_bytes(data[i + 20..i + 24].try_into().unwrap_or([0; 4]));

                let len = u64::from_le_bytes(data[i + 24..i + 32].try_into().unwrap_or([0; 8]));

                vol.upcase = Some(ClusteredExtent { first_cluster, len });

                i += DENTRY_SIZE;
            },

            DENTRY_FILE => {
                let secondary_count = data[i + 1] as usize;
                i += DENTRY_SIZE * (1 + secondary_count);
            },

            _ => {
                i += DENTRY_SIZE;
            },
        }
    }
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
            parent_cluster: 0,
        });
    }

    for (i, comp) in components.iter().enumerate() {
        let dir_data = vol.read_chain(cur_cluster);
        let entries = parse_dir_entries(&dir_data, cur_cluster);

        let found = entries
            .into_iter()
            .find(|entry| names_equal(vol, &entry.name, comp))?;

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

fn split_parent_name(path: &str) -> (&str, &str) {
    if let Some(p) = path.rfind('/') {
        (&path[..p.max(1)], &path[p + 1..])
    } else {
        ("/", path)
    }
}

fn utf16_name_units(name: &str) -> Result<Vec<u16>, isize> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(-22);
    }

    for ch in name.chars() {
        if ch < '\u{20}' {
            return Err(-22);
        }

        match ch {
            '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|' => return Err(-22),
            _ => {},
        }
    }

    let units: Vec<u16> = name.encode_utf16().collect();

    if units.is_empty() || units.len() > MAX_FILE_NAME_UTF16_UNITS {
        return Err(-36);
    }

    Ok(units)
}

fn name_hash(vol: &ExfatVol, units: &[u16]) -> u16 {
    let mut hash = 0u16;

    for unit in units {
        let folded = vol.upcase_unit(*unit);

        for b in folded.to_le_bytes() {
            hash = ((hash & 1) << 15) | (hash >> 1);
            hash = hash.wrapping_add(b as u16);
        }
    }

    hash
}

fn entry_set_checksum(entries: &[u8]) -> u16 {
    let mut checksum = 0u16;

    for (i, b) in entries.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }

        checksum = ((checksum & 1) << 15) | (checksum >> 1);
        checksum = checksum.wrapping_add(*b as u16);
    }

    checksum
}

fn build_dentries(
    vol: &ExfatVol,
    name: &str,
    first_cluster: u32,
    valid_data_len: u64,
    data_len: u64,
    attrs: u16,
) -> Result<Vec<u8>, isize> {
    let name_units = utf16_name_units(name)?;

    let filename_entries =
        (name_units.len() + FILE_NAME_CHARS_PER_DENTRY - 1) / FILE_NAME_CHARS_PER_DENTRY;

    let secondary_count = 1 + filename_entries;

    if secondary_count > u8::MAX as usize {
        return Err(-36);
    }

    let total_entries = 1 + secondary_count;
    let mut entries = vec![0u8; total_entries * DENTRY_SIZE];

    entries[0] = DENTRY_FILE;
    entries[1] = secondary_count as u8;
    entries[4..6].copy_from_slice(&attrs.to_le_bytes());

    let stream_off = DENTRY_SIZE;
    entries[stream_off] = DENTRY_STREAM_EXT;
    entries[stream_off + 1] = 0x01;
    entries[stream_off + 3] = name_units.len() as u8;
    entries[stream_off + 4..stream_off + 6]
        .copy_from_slice(&name_hash(vol, &name_units).to_le_bytes());
    entries[stream_off + 8..stream_off + 16].copy_from_slice(&valid_data_len.to_le_bytes());
    entries[stream_off + 20..stream_off + 24].copy_from_slice(&first_cluster.to_le_bytes());
    entries[stream_off + 24..stream_off + 32].copy_from_slice(&data_len.to_le_bytes());

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

fn build_file_dentries(
    vol: &ExfatVol,
    name: &str,
    first_cluster: u32,
    size: u64,
) -> Result<Vec<u8>, isize> {
    build_dentries(vol, name, first_cluster, size, size, ATTR_ARCHIVE)
}

fn build_dir_dentries(
    vol: &ExfatVol,
    name: &str,
    first_cluster: u32,
    size: u64,
) -> Result<Vec<u8>, isize> {
    build_dentries(
        vol,
        name,
        first_cluster,
        size,
        size,
        ATTR_DIRECTORY | ATTR_ARCHIVE,
    )
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
                vol.data[abs_off] &= 0x7F;
            }
        }
    }
}

fn find_eod_offset(dir_data: &[u8]) -> usize {
    let mut i = 0usize;

    while i + DENTRY_SIZE <= dir_data.len() {
        if dir_data[i] == DENTRY_EOD {
            return i;
        }

        i += DENTRY_SIZE;
    }

    dir_data.len()
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

fn ensure_dentry_run(
    vol: &mut ExfatVol,
    dir_first_cluster: u32,
    dir_data: &[u8],
    needed_entries: usize,
) -> Result<(usize, bool), isize> {
    if let Some(off) = find_free_dentry_run(dir_data, needed_entries) {
        return Ok((off, false));
    }

    let eod_off = find_eod_offset(dir_data);
    let needed_end = eod_off + needed_entries * DENTRY_SIZE;

    let additional_clusters = if needed_end <= dir_data.len() {
        0
    } else {
        let missing = needed_end - dir_data.len();
        (missing + vol.bytes_per_cluster - 1) / vol.bytes_per_cluster
    };

    vol.append_clusters_to_chain(dir_first_cluster, additional_clusters)?;

    Ok((eod_off, additional_clusters > 0))
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
            .ok_or(-28isize)?;

        let cluster_remaining =
            vol.bytes_per_cluster - ((dir_relative_off + written) % vol.bytes_per_cluster);

        let chunk_len = cluster_remaining.min(dentries.len() - written);

        if abs_off + chunk_len > vol.data.len() {
            return Err(-5);
        }

        vol.data[abs_off..abs_off + chunk_len]
            .copy_from_slice(&dentries[written..written + chunk_len]);

        written += chunk_len;
    }

    Ok(())
}

fn read_dentry_set_bytes(
    vol: &ExfatVol,
    dir_first_cluster: u32,
    primary_off: usize,
    entry_count: usize,
) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();

    for rel in primary_off..primary_off + entry_count * DENTRY_SIZE {
        let abs = vol.dir_entry_abs_off(dir_first_cluster, rel)?;
        bytes.push(*vol.data.get(abs)?);
    }

    Some(bytes)
}

fn recompute_entry_checksum(
    vol: &mut ExfatVol,
    dir_first_cluster: u32,
    primary_off: usize,
    entry_count: usize,
) {
    let Some(bytes) = read_dentry_set_bytes(vol, dir_first_cluster, primary_off, entry_count)
    else {
        return;
    };

    let checksum = entry_set_checksum(&bytes);
    let checksum_bytes = checksum.to_le_bytes();

    for i in 0..2 {
        if let Some(abs) = vol.dir_entry_abs_off(dir_first_cluster, primary_off + 2 + i) {
            if abs < vol.data.len() {
                vol.data[abs] = checksum_bytes[i];
            }
        }
    }
}

fn update_stream_lengths(vol: &mut ExfatVol, entry: &DirEntry, valid_data_len: u64, data_len: u64) {
    if entry.parent_cluster < 2 || entry.secondary_count == 0 {
        return;
    }

    let stream_rel = entry.primary_off + DENTRY_SIZE;

    let Some(stream_abs) = vol.dir_entry_abs_off(entry.parent_cluster, stream_rel) else {
        return;
    };

    if stream_abs + DENTRY_SIZE > vol.data.len() || vol.data[stream_abs] != DENTRY_STREAM_EXT {
        return;
    }

    vol.data[stream_abs + 8..stream_abs + 16].copy_from_slice(&valid_data_len.to_le_bytes());
    vol.data[stream_abs + 24..stream_abs + 32].copy_from_slice(&data_len.to_le_bytes());

    recompute_entry_checksum(
        vol,
        entry.parent_cluster,
        entry.primary_off,
        1 + entry.secondary_count,
    );
}

fn update_dir_size_after_expansion(vol: &mut ExfatVol, dir_entry: &DirEntry) {
    if dir_entry.parent_cluster < 2 {
        return;
    }

    let size = (vol.cluster_chain(dir_entry.first_cluster).len() * vol.bytes_per_cluster) as u64;
    update_stream_lengths(vol, dir_entry, size, size);
}

fn free_allocated_clusters(vol: &mut ExfatVol, chain: &[u32]) {
    for &cluster in chain {
        vol.set_fat_entry(cluster, FAT_FREE);
        vol.set_bitmap_cluster_allocated(cluster, false);
    }
}

fn find_entry_by_name(vol: &ExfatVol, entries: &[DirEntry], name: &str) -> Option<DirEntry> {
    entries
        .iter()
        .find(|entry| names_equal(vol, &entry.name, name))
        .cloned()
}

fn choose_dentry_offset(
    vol: &mut ExfatVol,
    parent_cluster: u32,
    parent_dir_data: &[u8],
    existing: Option<&DirEntry>,
    new_entry_count: usize,
) -> Result<(usize, bool), isize> {
    if let Some(old) = existing {
        let old_entry_count = 1 + old.secondary_count;
        let old_len = old_entry_count * DENTRY_SIZE;

        if old_len >= new_entry_count * DENTRY_SIZE {
            return Ok((old.primary_off, false));
        }

        let mut searchable = parent_dir_data.to_vec();

        for idx in 0..old_entry_count {
            let off = old.primary_off + idx * DENTRY_SIZE;
            if off < searchable.len() {
                searchable[off] &= 0x7F;
            }
        }

        ensure_dentry_run(vol, parent_cluster, &searchable, new_entry_count)
    } else {
        ensure_dentry_run(vol, parent_cluster, parent_dir_data, new_entry_count)
    }
}

fn insert_or_replace_dentries(
    vol: &mut ExfatVol,
    parent_entry: &DirEntry,
    name: &str,
    dentries: &[u8],
    old_data_first_cluster: Option<u32>,
) -> Result<(), isize> {
    let parent_cluster = parent_entry.first_cluster;
    let parent_dir_data = vol.read_chain(parent_cluster);
    let entries = parse_dir_entries(&parent_dir_data, parent_cluster);
    let existing = find_entry_by_name(vol, &entries, name);

    if existing.as_ref().map(|entry| entry.is_dir).unwrap_or(false)
        && old_data_first_cluster.is_some()
    {
        return Err(-21);
    }

    let new_entry_count = dentries.len() / DENTRY_SIZE;

    let (dentry_off, expanded) = choose_dentry_offset(
        vol,
        parent_cluster,
        &parent_dir_data,
        existing.as_ref(),
        new_entry_count,
    )?;

    write_dentries_to_dir(vol, parent_cluster, dentry_off, dentries)?;

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

        if let Some(old_first_cluster) = old_data_first_cluster {
            if old_first_cluster >= 2 {
                vol.free_chain(old_first_cluster);
            }
        }
    }

    if expanded {
        update_dir_size_after_expansion(vol, parent_entry);
    }

    Ok(())
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

    let fat_length =
        u32::from_le_bytes(image[BS_FAT_LENGTH..BS_FAT_LENGTH + 4].try_into().unwrap()) as usize;

    let cluster_heap_off = u32::from_le_bytes(
        image[BS_CLUSTER_HEAP_OFFSET..BS_CLUSTER_HEAP_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    let cluster_count = u32::from_le_bytes(
        image[BS_CLUSTER_COUNT..BS_CLUSTER_COUNT + 4]
            .try_into()
            .unwrap(),
    );

    let root_cluster = u32::from_le_bytes(
        image[BS_ROOT_CLUSTER..BS_ROOT_CLUSTER + 4]
            .try_into()
            .unwrap(),
    );

    let mut vol = ExfatVol {
        data: image,
        bytes_per_sector,
        secs_per_cluster,
        bytes_per_cluster,
        fat_offset,
        fat_length,
        cluster_heap_off,
        cluster_count,
        root_cluster,
        bitmap: None,
        upcase: None,
    };

    discover_metadata(&mut vol);

    *VOL.lock() = Some(vol);

    log::info!("exfat: mounted volume, root cluster={}", root_cluster);

    true
}

/// Read the full contents of a file. Returns Err(-2) if not found.
pub fn read_file(path: &str) -> Result<Vec<u8>, isize> {
    let guard = VOL.lock();
    let vol = guard.as_ref().ok_or(-5isize)?;

    let entry = resolve_path(vol, path).ok_or(-2isize)?;

    if entry.is_dir {
        return Err(-21);
    }

    let mut data = vol.read_chain(entry.first_cluster);
    data.truncate(entry.size as usize);

    Ok(data)
}

/// Write, create, or overwrite a file.
pub fn write_file(path: &str, contents: &[u8]) -> Result<(), isize> {
    let (parent, name) = split_parent_name(path);

    let mut guard = VOL.lock();
    let vol = guard.as_mut().ok_or(-5isize)?;

    utf16_name_units(name)?;

    let parent_entry = resolve_parent_dir(vol, parent).ok_or(-2isize)?;
    let parent_cluster = parent_entry.first_cluster;

    let parent_dir_data = vol.read_chain(parent_cluster);
    let entries = parse_dir_entries(&parent_dir_data, parent_cluster);
    let existing = find_entry_by_name(vol, &entries, name);

    if existing.as_ref().map(|entry| entry.is_dir).unwrap_or(false) {
        return Err(-21);
    }

    let needed_clusters = if contents.is_empty() {
        0
    } else {
        (contents.len() + vol.bytes_per_cluster - 1) / vol.bytes_per_cluster
    };

    let mut chain = Vec::new();

    for _ in 0..needed_clusters {
        match vol.alloc_cluster() {
            Some(cluster) => chain.push(cluster),
            None => {
                free_allocated_clusters(vol, &chain);
                return Err(-28);
            },
        }
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
    let dentries = build_file_dentries(vol, name, first_cluster, contents.len() as u64)?;

    let old_first_cluster = existing.as_ref().and_then(|entry| {
        if entry.first_cluster >= 2 {
            Some(entry.first_cluster)
        } else {
            None
        }
    });

    if let Err(err) =
        insert_or_replace_dentries(vol, &parent_entry, name, &dentries, old_first_cluster)
    {
        free_allocated_clusters(vol, &chain);
        return Err(err);
    }

    log::debug!(
        "exfat: wrote {} bytes to '{}' starting at cluster {}",
        contents.len(),
        path,
        first_cluster
    );

    Ok(())
}

/// Create a directory.
pub fn create_dir(path: &str) -> Result<(), isize> {
    let (parent, name) = split_parent_name(path);

    let mut guard = VOL.lock();
    let vol = guard.as_mut().ok_or(-5isize)?;

    utf16_name_units(name)?;

    let parent_entry = resolve_parent_dir(vol, parent).ok_or(-2isize)?;
    let parent_cluster = parent_entry.first_cluster;

    let parent_dir_data = vol.read_chain(parent_cluster);
    let entries = parse_dir_entries(&parent_dir_data, parent_cluster);

    if find_entry_by_name(vol, &entries, name).is_some() {
        return Err(-17);
    }

    let dir_cluster = vol.alloc_cluster().ok_or(-28isize)?;
    vol.set_fat_entry(dir_cluster, FAT_EOC);

    if let Some(bytes) = vol.cluster_bytes_mut(dir_cluster) {
        bytes.fill(0);
    }

    let dir_size = vol.bytes_per_cluster as u64;
    let dentries = build_dir_dentries(vol, name, dir_cluster, dir_size)?;

    if let Err(err) = insert_or_replace_dentries(vol, &parent_entry, name, &dentries, None) {
        vol.free_chain(dir_cluster);
        return Err(err);
    }

    log::debug!(
        "exfat: created directory '{}' at cluster {}",
        path,
        dir_cluster
    );

    Ok(())
}

/// Alias for create_dir.
pub fn mkdir(path: &str) -> Result<(), isize> {
    create_dir(path)
}

/// List the contents of a directory. Returns `(name, is_dir)` pairs.
pub fn read_dir(path: &str) -> Result<Vec<(String, bool)>, isize> {
    let guard = VOL.lock();
    let vol = guard.as_ref().ok_or(-5isize)?;

    let entry = resolve_path(vol, path).ok_or(-2isize)?;

    if !entry.is_dir {
        return Err(-20);
    }

    let data = vol.read_chain(entry.first_cluster);
    let entries = parse_dir_entries(&data, entry.first_cluster);

    Ok(entries.iter().map(|e| (e.name.clone(), e.is_dir)).collect())
}

/// Return the size in bytes of a file, or Err(-2) if not found.
pub fn file_size(path: &str) -> Result<u64, isize> {
    let guard = VOL.lock();
    let vol = guard.as_ref().ok_or(-5isize)?;

    let entry = resolve_path(vol, path).ok_or(-2isize)?;

    if entry.is_dir {
        return Err(-21);
    }

    Ok(entry.size)
}

/// Unmount and release the volume.
pub fn umount() {
    *VOL.lock() = None;
}
