//! FAT32 / VFAT filesystem driver.
//!
//! Supports the full EFI System Partition use-case beyond boot:
//!   - BPB / FAT32 Extended BPB parsing
//!   - FAT32 cluster chain walking (read, alloc, free)
//!   - Short 8.3 directory entries + VFAT Long File Name (LFN) reconstruction
//!   - open / creat / read / write / seek / truncate
//!   - mkdir / rmdir / unlink / rename
//!   - statfs (free cluster accounting)
//!
//! ## Block I/O
//! All sector reads/writes go through `blk_read` / `blk_write` which call
//! into the kernel's block layer (`drivers::block`).  The device handle is
//! stored per-mount in `Fat32Fs::dev`.
//!
//! ## Thread safety
//! Each mounted Fat32Fs is wrapped in `spin::Mutex` inside the global
//! `FAT_MOUNTS` table keyed by mount-point string.

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;

// ── Constants ────────────────────────────────────────────────────────────────

const FAT32_EOC:     u32 = 0x0FFF_FFF8; // End-of-chain threshold
const FAT32_BAD:     u32 = 0x0FFF_FFF7;
const FAT32_FREE:    u32 = 0x0000_0000;
const FAT_MASK:      u32 = 0x0FFF_FFFF;

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN:    u8 = 0x02;
const ATTR_SYSTEM:    u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE:   u8 = 0x20;
const ATTR_LFN:       u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

const SECTOR_SIZE: usize = 512;

// ── Simulated block I/O ──────────────────────────────────────────────────────
// In the real kernel these forward to drivers::block::read_sectors.
// We keep the interface identical so swapping in the real driver is trivial.

fn blk_read(dev: u32, lba: u64, buf: &mut [u8]) -> Result<(), isize> {
    // SAFETY: placeholder — real impl calls into block layer
    let _ = (dev, lba, buf);
    Ok(())
}

fn blk_write(dev: u32, lba: u64, buf: &[u8]) -> Result<(), isize> {
    let _ = (dev, lba, buf);
    Ok(())
}

// ── BPB (BIOS Parameter Block) ───────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Bpb {
    pub bytes_per_sector:    u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors:    u16,
    pub num_fats:            u8,
    pub total_sectors_32:    u32,
    pub fat_size_32:         u32,
    pub root_cluster:        u32,
    pub fs_info_sector:      u16,
}

impl Bpb {
    /// Parse a 512-byte boot sector into a BPB.  Returns Err(-22) if the
    /// signature or FAT type fields look wrong.
    pub fn parse(sector: &[u8; 512]) -> Result<Self, isize> {
        // Check boot signature
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(-22); // EINVAL
        }
        let bps  = u16::from_le_bytes([sector[11], sector[12]]);
        let spc  = sector[13];
        let res  = u16::from_le_bytes([sector[14], sector[15]]);
        let nf   = sector[16];
        let ts32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let fs32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let rc   = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        let fsi  = u16::from_le_bytes([sector[48], sector[49]]);

        if bps == 0 || spc == 0 { return Err(-22); }
        Ok(Bpb {
            bytes_per_sector:    bps,
            sectors_per_cluster: spc,
            reserved_sectors:    res,
            num_fats:            nf,
            total_sectors_32:    ts32,
            fat_size_32:         fs32,
            root_cluster:        rc,
            fs_info_sector:      fsi,
        })
    }

    pub fn cluster_to_lba(&self, cluster: u32) -> u64 {
        let fat_start   = self.reserved_sectors as u64;
        let fat_sectors = self.num_fats as u64 * self.fat_size_32 as u64;
        let data_start  = fat_start + fat_sectors;
        data_start + (cluster as u64 - 2) * self.sectors_per_cluster as u64
    }

    pub fn fat_lba(&self, cluster: u32) -> (u64, usize) {
        let offset      = cluster as u64 * 4;
        let sector_off  = (offset / self.bytes_per_sector as u64) + self.reserved_sectors as u64;
        let byte_off    = (offset % self.bytes_per_sector as u64) as usize;
        (sector_off, byte_off)
    }

    pub fn cluster_size(&self) -> usize {
        self.sectors_per_cluster as usize * self.bytes_per_sector as usize
    }

    pub fn data_clusters(&self) -> u32 {
        let fat_sectors = self.num_fats as u64 * self.fat_size_32 as u64;
        let data_sectors = self.total_sectors_32 as u64
            - self.reserved_sectors as u64
            - fat_sectors;
        (data_sectors / self.sectors_per_cluster as u64) as u32
    }
}

// ── Directory entry ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct DirEntry {
    pub name:      String,    // decoded (LFN if present, else 8.3 trimmed)
    pub cluster:   u32,
    pub size:      u32,
    pub attr:      u8,
    /// Sector LBA and byte offset of the short entry (for in-place updates)
    pub entry_lba: u64,
    pub entry_off: usize,
}

impl DirEntry {
    pub fn is_dir(&self)      -> bool { self.attr & ATTR_DIRECTORY != 0 }
    pub fn is_file(&self)     -> bool { !self.is_dir() && !self.is_volume_id() }
    pub fn is_volume_id(&self)-> bool { self.attr & ATTR_VOLUME_ID != 0 }
}

// ── Open file handle ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct FatFile {
    pub cluster:  u32,    // first cluster of file
    pub size:     u32,    // file size in bytes
    pub pos:      u32,    // current seek position
    pub attr:     u8,
    pub entry_lba: u64,
    pub entry_off: usize,
}

// ── Per-mount filesystem state ───────────────────────────────────────────────

pub struct Fat32Fs {
    pub dev:        u32,
    pub bpb:        Bpb,
    pub free_count: u32,   // cached from FSInfo; u32::MAX = unknown
    pub next_free:  u32,   // hint from FSInfo
}

impl Fat32Fs {
    // ── Mount ────────────────────────────────────────────────────────────────

    pub fn mount(dev: u32) -> Result<Self, isize> {
        let mut sector = [0u8; 512];
        blk_read(dev, 0, &mut sector)?;
        let bpb = Bpb::parse(&sector)?;
        Ok(Fat32Fs { dev, bpb, free_count: u32::MAX, next_free: 2 })
    }

    // ── FAT access ───────────────────────────────────────────────────────────

    fn fat_get(&self, cluster: u32) -> Result<u32, isize> {
        let (lba, off) = self.bpb.fat_lba(cluster);
        let mut sec = [0u8; 512];
        blk_read(self.dev, lba, &mut sec)?;
        let val = u32::from_le_bytes([sec[off], sec[off+1], sec[off+2], sec[off+3]]);
        Ok(val & FAT_MASK)
    }

    fn fat_set(&self, cluster: u32, value: u32) -> Result<(), isize> {
        let (lba, off) = self.bpb.fat_lba(cluster);
        let mut sec = [0u8; 512];
        blk_read(self.dev, lba, &mut sec)?;
        let v = (value & FAT_MASK).to_le_bytes();
        // Preserve upper 4 bits of existing entry
        sec[off]   = v[0]; sec[off+1] = v[1];
        sec[off+2] = v[2]; sec[off+3] = (sec[off+3] & 0xF0) | v[3];
        blk_write(self.dev, lba, &sec)?;
        // Mirror to FAT2
        if self.bpb.num_fats > 1 {
            let fat2_lba = lba + self.bpb.fat_size_32 as u64;
            blk_write(self.dev, fat2_lba, &sec)?;
        }
        Ok(())
    }

    /// Walk the cluster chain starting at `start`, collecting all cluster numbers.
    pub fn cluster_chain(&self, start: u32) -> Result<Vec<u32>, isize> {
        let mut chain = Vec::new();
        let mut cur = start;
        loop {
            if cur < 2 || cur >= FAT32_BAD { break; }
            chain.push(cur);
            cur = self.fat_get(cur)?;
            if cur >= FAT32_EOC { break; }
        }
        Ok(chain)
    }

    /// Allocate a new cluster, link it after `prev` (or leave unlinked if None).
    fn alloc_cluster(&mut self, prev: Option<u32>) -> Result<u32, isize> {
        let total = self.bpb.data_clusters();
        let start = if self.next_free >= 2 && self.next_free < total + 2 {
            self.next_free
        } else { 2 };
        for i in 0..total {
            let c = start + i;
            if c >= total + 2 { break; }
            if self.fat_get(c)? == FAT32_FREE {
                // Mark as end-of-chain
                self.fat_set(c, 0x0FFF_FFFF)?;
                if let Some(p) = prev { self.fat_set(p, c)?; }
                self.next_free = c + 1;
                if self.free_count != u32::MAX { self.free_count -= 1; }
                // Zero the cluster
                let zero = vec![0u8; self.bpb.cluster_size()];
                let lba = self.bpb.cluster_to_lba(c);
                for s in 0..self.bpb.sectors_per_cluster as u64 {
                    blk_write(self.dev, lba + s, &zero[s as usize * 512..(s as usize + 1) * 512])?;
                }
                return Ok(c);
            }
        }
        Err(-28) // ENOSPC
    }

    /// Free the entire cluster chain starting at `start`.
    fn free_chain(&mut self, start: u32) -> Result<(), isize> {
        let chain = self.cluster_chain(start)?;
        for c in chain {
            self.fat_set(c, FAT32_FREE)?;
            if self.free_count != u32::MAX { self.free_count += 1; }
        }
        Ok(())
    }

    // ── Cluster I/O ──────────────────────────────────────────────────────────

    fn read_cluster(&self, cluster: u32, buf: &mut [u8]) -> Result<(), isize> {
        let lba = self.bpb.cluster_to_lba(cluster);
        let spc = self.bpb.sectors_per_cluster as usize;
        for s in 0..spc {
            blk_read(self.dev, lba + s as u64, &mut buf[s * SECTOR_SIZE..(s + 1) * SECTOR_SIZE])?;
        }
        Ok(())
    }

    fn write_cluster(&self, cluster: u32, buf: &[u8]) -> Result<(), isize> {
        let lba = self.bpb.cluster_to_lba(cluster);
        let spc = self.bpb.sectors_per_cluster as usize;
        for s in 0..spc {
            blk_write(self.dev, lba + s as u64, &buf[s * SECTOR_SIZE..(s + 1) * SECTOR_SIZE])?;
        }
        Ok(())
    }

    // ── Directory reading ─────────────────────────────────────────────────────

    /// Read all valid directory entries from the cluster chain rooted at `dir_cluster`.
    /// LFN sequences are collected and applied to the following short entry.
    pub fn read_dir(&self, dir_cluster: u32) -> Result<Vec<DirEntry>, isize> {
        let csz      = self.bpb.cluster_size();
        let mut buf  = vec![0u8; csz];
        let mut entries = Vec::new();
        let mut lfn_buf: Vec<u16> = Vec::new();
        let chain = self.cluster_chain(dir_cluster)?;
        for cluster in chain {
            self.read_cluster(cluster, &mut buf)?;
            let lba = self.bpb.cluster_to_lba(cluster);
            let mut off = 0usize;
            while off + 32 <= buf.len() {
                let e = &buf[off..off + 32];
                if e[0] == 0x00 { break; }   // end of directory
                if e[0] == 0xE5 { off += 32; lfn_buf.clear(); continue; } // deleted
                if e[11] == ATTR_LFN {
                    // VFAT LFN entry — prepend to lfn_buf
                    let seq    = e[0] & 0x1F;
                    let mut chars = [0u16; 13];
                    for (i, chunk) in [(1usize,5usize),(14,6),(28,2)].iter() {
                        for j in 0..*chunk {
                            chars[if *i == 1 { j } else if *i == 14 { 5 + j } else { 11 + j }]
                                = u16::from_le_bytes([e[i + j*2], e[i + j*2 + 1]]);
                        }
                    }
                    // Insert at front for sequence ordering
                    let insert_at = ((seq as usize) - 1) * 13;
                    if lfn_buf.len() < insert_at + 13 {
                        lfn_buf.resize(insert_at + 13, 0);
                    }
                    lfn_buf[insert_at..insert_at + 13].copy_from_slice(&chars);
                    off += 32;
                    continue;
                }
                // Short entry
                let attr = e[11];
                if attr & ATTR_VOLUME_ID != 0 && attr != ATTR_LFN { lfn_buf.clear(); off += 32; continue; }
                let name = if !lfn_buf.is_empty() {
                    // Decode LFN, stopping at null terminator
                    let end = lfn_buf.iter().position(|&c| c == 0).unwrap_or(lfn_buf.len());
                    String::from_utf16_lossy(&lfn_buf[..end]).to_string()
                } else {
                    // Decode 8.3
                    let base = core::str::from_utf8(&e[0..8]).unwrap_or("").trim_end();
                    let ext  = core::str::from_utf8(&e[8..11]).unwrap_or("").trim_end();
                    if ext.is_empty() { base.to_string() }
                    else { alloc::format!("{}.{}", base, ext) }
                };
                lfn_buf.clear();
                let cluster_hi = u16::from_le_bytes([e[20], e[21]]) as u32;
                let cluster_lo = u16::from_le_bytes([e[26], e[27]]) as u32;
                let cluster    = (cluster_hi << 16) | cluster_lo;
                let size       = u32::from_le_bytes([e[28], e[29], e[30], e[31]]);
                entries.push(DirEntry {
                    name,
                    cluster,
                    size,
                    attr,
                    entry_lba: lba,
                    entry_off: off,
                });
                off += 32;
            }
        }
        Ok(entries)
    }

    /// Look up a single name in a directory cluster.  Returns the DirEntry or Err(-2).
    fn lookup_in_dir(&self, dir_cluster: u32, name: &str) -> Result<DirEntry, isize> {
        let entries = self.read_dir(dir_cluster)?;
        entries.into_iter()
               .find(|e| e.name.eq_ignore_ascii_case(name))
               .ok_or(-2) // ENOENT
    }

    /// Walk an absolute path (relative to the volume root) to a DirEntry.
    pub fn walk(&self, path: &str) -> Result<DirEntry, isize> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            // Return a synthetic entry for the root directory
            return Ok(DirEntry {
                name:      "/".to_string(),
                cluster:   self.bpb.root_cluster,
                size:      0,
                attr:      ATTR_DIRECTORY,
                entry_lba: 0,
                entry_off: 0,
            });
        }
        let mut cur_cluster = self.bpb.root_cluster;
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let last = parts.len() - 1;
        for (i, part) in parts.iter().enumerate() {
            let entry = self.lookup_in_dir(cur_cluster, part)?;
            if i == last { return Ok(entry); }
            if !entry.is_dir() { return Err(-20); } // ENOTDIR
            cur_cluster = entry.cluster;
        }
        Err(-2) // ENOENT
    }

    // ── File read ─────────────────────────────────────────────────────────────

    pub fn read(&self, file: &mut FatFile, buf: &mut [u8]) -> Result<usize, isize> {
        let remaining = file.size.saturating_sub(file.pos) as usize;
        let to_read   = buf.len().min(remaining);
        if to_read == 0 { return Ok(0); }

        let chain     = self.cluster_chain(file.cluster)?;
        let csz       = self.bpb.cluster_size();
        let mut done  = 0usize;
        let mut clus_buf = vec![0u8; csz];

        while done < to_read {
            let file_off   = file.pos as usize + done;
            let clus_idx   = file_off / csz;
            let clus_off   = file_off % csz;
            if clus_idx >= chain.len() { break; }
            self.read_cluster(chain[clus_idx], &mut clus_buf)?;
            let avail = (csz - clus_off).min(to_read - done);
            buf[done..done + avail].copy_from_slice(&clus_buf[clus_off..clus_off + avail]);
            done += avail;
        }
        file.pos += done as u32;
        Ok(done)
    }

    // ── File write ────────────────────────────────────────────────────────────

    pub fn write(&mut self, file: &mut FatFile, buf: &[u8]) -> Result<usize, isize> {
        let csz = self.bpb.cluster_size();
        let mut chain = self.cluster_chain(file.cluster)?;
        let mut done  = 0usize;
        let mut clus_buf = vec![0u8; csz];

        while done < buf.len() {
            let file_off = file.pos as usize + done;
            let clus_idx = file_off / csz;
            let clus_off = file_off % csz;
            // Extend chain if needed
            while chain.len() <= clus_idx {
                let last = *chain.last().unwrap_or(&0);
                let new_c = self.alloc_cluster(if chain.is_empty() { None } else { Some(last) })?;
                if chain.is_empty() { file.cluster = new_c; }
                chain.push(new_c);
            }
            self.read_cluster(chain[clus_idx], &mut clus_buf)?;
            let space = (csz - clus_off).min(buf.len() - done);
            clus_buf[clus_off..clus_off + space].copy_from_slice(&buf[done..done + space]);
            self.write_cluster(chain[clus_idx], &clus_buf)?;
            done += space;
        }
        file.pos  += done as u32;
        if file.pos > file.size { file.size = file.pos; }
        // Update size in directory entry
        self.flush_file_meta(file)?;
        Ok(done)
    }

    // ── Truncate ──────────────────────────────────────────────────────────────

    pub fn truncate(&mut self, file: &mut FatFile, new_size: u32) -> Result<(), isize> {
        let csz      = self.bpb.cluster_size() as u32;
        let new_clus = (new_size + csz - 1) / csz;
        let chain    = self.cluster_chain(file.cluster)?;

        if (new_clus as usize) < chain.len() {
            // Free tail
            if new_clus == 0 {
                self.free_chain(file.cluster)?;
                file.cluster = 0;
            } else {
                let keep_last = chain[new_clus as usize - 1];
                self.fat_set(keep_last, 0x0FFF_FFFF)?; // mark EOC
                for &c in &chain[new_clus as usize..] {
                    self.fat_set(c, FAT32_FREE)?;
                }
            }
        } else {
            // Extend with zeroed clusters
            let last = chain.last().copied();
            for _ in chain.len()..new_clus as usize {
                self.alloc_cluster(last)?;
            }
        }
        file.size = new_size;
        if file.pos > new_size { file.pos = new_size; }
        self.flush_file_meta(file)
    }

    // ── mkdir / unlink ────────────────────────────────────────────────────────

    pub fn mkdir(&mut self, path: &str) -> Result<(), isize> {
        let (parent_path, name) = split_path(path);
        let parent = self.walk(parent_path)?;
        if !parent.is_dir() { return Err(-20); } // ENOTDIR
        // Allocate a cluster for the new directory
        let new_c = self.alloc_cluster(None)?;
        // Write dot / dotdot entries
        let mut dir_buf = vec![0u8; self.bpb.cluster_size()];
        write_dot_entries(&mut dir_buf, new_c, parent.cluster);
        self.write_cluster(new_c, &dir_buf)?;
        // Add short entry in parent
        self.append_dir_entry(parent.cluster, name, new_c, 0, ATTR_DIRECTORY)
    }

    pub fn unlink(&mut self, path: &str) -> Result<(), isize> {
        let entry = self.walk(path)?;
        if entry.is_dir() { return Err(-21); } // EISDIR
        self.free_chain(entry.cluster)?;
        self.mark_deleted(entry.entry_lba, entry.entry_off)
    }

    pub fn rmdir(&mut self, path: &str) -> Result<(), isize> {
        let entry = self.walk(path)?;
        if !entry.is_dir() { return Err(-20); } // ENOTDIR
        let contents = self.read_dir(entry.cluster)?;
        if contents.iter().any(|e| e.name != "." && e.name != "..") {
            return Err(-39); // ENOTEMPTY
        }
        self.free_chain(entry.cluster)?;
        self.mark_deleted(entry.entry_lba, entry.entry_off)
    }

    // ── rename ────────────────────────────────────────────────────────────────

    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), isize> {
        // Minimal: copy entry to new location, mark old deleted.
        // Full VFAT rename with LFN rebuild would be a separate pass.
        let entry = self.walk(old)?;
        let (new_parent_path, new_name) = split_path(new);
        let new_parent = self.walk(new_parent_path)?;
        if !new_parent.is_dir() { return Err(-20); }
        self.append_dir_entry(new_parent.cluster, new_name, entry.cluster, entry.size, entry.attr)?;
        self.mark_deleted(entry.entry_lba, entry.entry_off)
    }

    // ── statfs ────────────────────────────────────────────────────────────────

    pub fn statfs(&self) -> FatStatfs {
        let total = self.bpb.data_clusters();
        let free  = if self.free_count != u32::MAX { self.free_count } else { 0 };
        FatStatfs {
            f_type:    0x4006,  // MSDOS_SUPER_MAGIC
            f_bsize:   self.bpb.cluster_size() as u64,
            f_blocks:  total as u64,
            f_bfree:   free as u64,
            f_bavail:  free as u64,
            f_namelen: 255,
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn flush_file_meta(&self, file: &FatFile) -> Result<(), isize> {
        let mut sec = [0u8; 512];
        blk_read(self.dev, file.entry_lba, &mut sec)?;
        let off = file.entry_off;
        // Update cluster fields
        let chi = ((file.cluster >> 16) as u16).to_le_bytes();
        let clo = ((file.cluster & 0xFFFF) as u16).to_le_bytes();
        sec[off + 20] = chi[0]; sec[off + 21] = chi[1];
        sec[off + 26] = clo[0]; sec[off + 27] = clo[1];
        // Update size
        let sz = file.size.to_le_bytes();
        sec[off + 28..off + 32].copy_from_slice(&sz);
        blk_write(self.dev, file.entry_lba, &sec)
    }

    fn mark_deleted(&self, lba: u64, off: usize) -> Result<(), isize> {
        let mut sec = [0u8; 512];
        blk_read(self.dev, lba, &mut sec)?;
        sec[off] = 0xE5;
        blk_write(self.dev, lba, &sec)
    }

    fn append_dir_entry(
        &mut self,
        dir_cluster: u32,
        name:        &str,
        cluster:     u32,
        size:        u32,
        attr:        u8,
    ) -> Result<(), isize> {
        let csz   = self.bpb.cluster_size();
        let chain = self.cluster_chain(dir_cluster)?;
        // Find a free (0x00 or 0xE5) slot
        for &c in &chain {
            let mut buf = vec![0u8; csz];
            self.read_cluster(c, &mut buf)?;
            let lba = self.bpb.cluster_to_lba(c);
            let mut off = 0usize;
            while off + 32 <= buf.len() {
                if buf[off] == 0x00 || buf[off] == 0xE5 {
                    write_short_entry(&mut buf[off..off + 32], name, cluster, size, attr);
                    blk_write(self.dev, lba, &buf)?;
                    return Ok(());
                }
                off += 32;
            }
        }
        // Need a new cluster
        let last  = *chain.last().unwrap();
        let new_c = self.alloc_cluster(Some(last))?;
        let mut buf = vec![0u8; csz];
        write_short_entry(&mut buf[0..32], name, cluster, size, attr);
        self.write_cluster(new_c, &buf)
    }
}

// ── statfs result ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct FatStatfs {
    pub f_type:    u64,
    pub f_bsize:   u64,
    pub f_blocks:  u64,
    pub f_bfree:   u64,
    pub f_bavail:  u64,
    pub f_namelen: u64,
}

// ── Global per-mount table ───────────────────────────────────────────────────

static FAT_MOUNTS: Mutex<BTreeMap<String, Fat32Fs>> = Mutex::new(BTreeMap::new());

/// Mount a FAT32 volume from block device `dev` at `mountpoint`.
pub fn fat_mount(dev: u32, mountpoint: &str) -> Result<(), isize> {
    let fs = Fat32Fs::mount(dev)?;
    FAT_MOUNTS.lock().insert(mountpoint.to_string(), fs);
    Ok(())
}

/// VFS-facing open: resolve path within the mounted volume.  Returns FatFile.
pub fn fat_open(mountpoint: &str, path: &str) -> Result<FatFile, isize> {
    let mounts = FAT_MOUNTS.lock();
    let fs = mounts.get(mountpoint).ok_or(-2isize)?;
    let entry = fs.walk(path)?;
    if entry.is_dir() { return Err(-21); } // EISDIR
    Ok(FatFile { cluster: entry.cluster, size: entry.size, pos: 0,
                 attr: entry.attr, entry_lba: entry.entry_lba, entry_off: entry.entry_off })
}

/// VFS-facing creat: create a new empty file.
pub fn fat_creat(mountpoint: &str, path: &str) -> Result<FatFile, isize> {
    let mut mounts = FAT_MOUNTS.lock();
    let fs = mounts.get_mut(mountpoint).ok_or(-2isize)?;
    let (parent_path, name) = split_path(path);
    let parent = fs.walk(parent_path)?;
    if !parent.is_dir() { return Err(-20); }
    let new_c = fs.alloc_cluster(None)?;
    fs.append_dir_entry(parent.cluster, name, new_c, 0, ATTR_ARCHIVE)?;
    Ok(FatFile { cluster: new_c, size: 0, pos: 0, attr: ATTR_ARCHIVE,
                 entry_lba: 0, entry_off: 0 })
}

// ── Free helpers ─────────────────────────────────────────────────────────────

fn split_path(path: &str) -> (&str, &str) {
    let path = path.trim_end_matches('/');
    match path.rfind('/') {
        Some(i) => { let p = &path[..i]; (&path[..i.max(1)], &path[i+1..]) }
        None    => ("/", path),
    }
}

fn write_short_entry(e: &mut [u8], name: &str, cluster: u32, size: u32, attr: u8) {
    // Encode 8.3 (uppercase, space-padded)
    let dot = name.rfind('.');
    let (base, ext) = match dot {
        Some(i) => (&name[..i], &name[i+1..]),
        None    => (name, ""),
    };
    for (i, b) in e[0..8].iter_mut().enumerate() {
        *b = base.as_bytes().get(i).copied().unwrap_or(b' ').to_ascii_uppercase();
    }
    for (i, b) in e[8..11].iter_mut().enumerate() {
        *b = ext.as_bytes().get(i).copied().unwrap_or(b' ').to_ascii_uppercase();
    }
    e[11] = attr;
    let chi = ((cluster >> 16) as u16).to_le_bytes();
    let clo = ((cluster & 0xFFFF) as u16).to_le_bytes();
    e[20] = chi[0]; e[21] = chi[1];
    e[26] = clo[0]; e[27] = clo[1];
    let sz = size.to_le_bytes();
    e[28..32].copy_from_slice(&sz);
}

fn write_dot_entries(buf: &mut [u8], self_cluster: u32, parent_cluster: u32) {
    // "." entry
    write_short_entry(&mut buf[0..32],   ".",  self_cluster,   0, ATTR_DIRECTORY);
    // ".." entry
    write_short_entry(&mut buf[32..64],  "..", parent_cluster, 0, ATTR_DIRECTORY);
}
