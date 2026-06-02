//! NTFS read-only filesystem driver.
//!
//! Supports:
//!   - Boot sector / BPB parsing
//!   - MFT (Master File Table) record loading
//!   - $FILE_NAME and $DATA attribute parsing (resident data only)
//!   - Directory index ($INDEX_ROOT) traversal for path resolution
//!
//! Write support is intentionally omitted — NTFS write is complex and
//! risky; read-only is enough for Windows disk interoperability.
//!
//! Non-resident $DATA attributes (files > ~700 bytes) use a data-run
//! list to locate clusters; this driver decodes those runs to support
//! large files.

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
    vec,
};
use spin::Mutex;

const BS_BYTES_PER_SECTOR: usize = 0x0B; // u16 LE
const BS_SECS_PER_CLUSTER: usize = 0x0D; // u8
const BS_MFT_LCN:          usize = 0x30; // i64 LE: logical cluster of $MFT
const BS_CLUSTERS_PER_MFT: usize = 0x40; // i8: positive=clusters, negative=2^|n|

const NTFS_SIGNATURE:      &[u8] = b"NTFS    "; // at offset 3

const MFT_RECORD_SIZE:  usize = 1024;
const MFT_MAGIC:        &[u8] = b"FILE";
const MFT_FLAG_IN_USE:  u16   = 0x0001;
const MFT_FLAG_DIR:     u16   = 0x0002;

// MFT record field offsets
const MFT_UPDATE_SEQ_OFF: usize = 4;   // u16: offset to update sequence
const MFT_UPDATE_SEQ_CNT: usize = 6;   // u16: size of update sequence in words
const MFT_FLAGS:          usize = 22;  // u16
const MFT_ATTR_OFF:       usize = 20;  // u16: offset to first attribute

// Attribute type codes
const ATTR_STANDARD_INFO:  u32 = 0x10;
const ATTR_FILE_NAME:      u32 = 0x30;
const ATTR_DATA:           u32 = 0x80;
const ATTR_INDEX_ROOT:     u32 = 0x90;
const ATTR_INDEX_ALLOC:    u32 = 0xA0;
const ATTR_END:            u32 = 0xFFFF_FFFF;

// Attribute header offsets
const AHDR_TYPE:           usize = 0;  // u32
const AHDR_LENGTH:         usize = 4;  // u32
const AHDR_NON_RESIDENT:   usize = 8;  // u8: 0=resident, 1=non-resident
const AHDR_NAME_LEN:       usize = 9;  // u8
const AHDR_CONTENT_OFF:    usize = 20; // u16: for resident attributes
const AHDR_CONTENT_SIZE:   usize = 16; // u32: for resident attributes

// Non-resident attribute extra fields
const NR_LOWEST_VCN:   usize = 16; // i64
const NR_HIGHEST_VCN:  usize = 24; // i64
const NR_DATARUN_OFF:  usize = 32; // u16
const NR_ALLOC_SIZE:   usize = 40; // u64
const NR_REAL_SIZE:    usize = 48; // u64

// $FILE_NAME attribute body offsets (relative to content start)
const FN_PARENT_REF:   usize = 0;  // u64 (low 48 bits = MFT ref)
const FN_NAME_LEN:     usize = 64; // u8: length in UTF-16 chars
const FN_NAME_TYPE:    usize = 65; // u8: 0=POSIX,1=Win32,2=DOS,3=Win32&DOS
const FN_NAME:         usize = 66; // UTF-16LE name

// Well-known MFT record numbers
const MFT_REC_MFT:    u64 = 0;
const MFT_REC_ROOT:   u64 = 5; // root directory

struct NtfsVol {
    data:              Vec<u8>,
    bytes_per_sector:  usize,
    bytes_per_cluster: usize,
    mft_offset:        usize, // byte offset of $MFT in the volume data
    mft_record_size:   usize,
}

static VOL: Mutex<Option<NtfsVol>> = Mutex::new(None);

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off+2].try_into().unwrap_or([0;2]))
}
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off+4].try_into().unwrap_or([0;4]))
}
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off+8].try_into().unwrap_or([0;8]))
}
fn read_i64_le(buf: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(buf[off..off+8].try_into().unwrap_or([0;8]))
}

/// Decode a data-run byte stream into (length_in_clusters, lcn_delta) pairs.
fn decode_data_runs(runs: &[u8]) -> Vec<(i64, i64)> {
    let mut out = Vec::new();
    let mut i   = 0usize;
    while i < runs.len() {
        let header = runs[i];
        if header == 0 { break; }
        i += 1;
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = (header >> 4)   as usize;
        if i + len_bytes + off_bytes > runs.len() { break; }

        let mut length = 0i64;
        for j in 0..len_bytes {
            length |= (runs[i + j] as i64) << (j * 8);
        }
        i += len_bytes;

        let mut delta = 0i64;
        if off_bytes > 0 {
            for j in 0..off_bytes {
                delta |= (runs[i + j] as i64) << (j * 8);
            }
            // Sign-extend
            let sign_bit = 1i64 << (off_bytes * 8 - 1);
            if delta & sign_bit != 0 {
                delta |= -(sign_bit << 1);
            }
        }
        i += off_bytes;
        out.push((length, delta));
    }
    out
}

impl NtfsVol {
    /// Apply the MFT update sequence fixup to a 1024-byte record copy.
    fn fixup_record(&self, rec: &mut [u8; MFT_RECORD_SIZE]) {
        let usn_off = read_u16_le(rec, MFT_UPDATE_SEQ_OFF) as usize;
        let usn_cnt = read_u16_le(rec, MFT_UPDATE_SEQ_CNT) as usize;
        if usn_off + usn_cnt * 2 > MFT_RECORD_SIZE { return; }
        // usn_cnt includes the USN itself in position [0], then (usn_cnt-1) replacements
        for i in 1..usn_cnt {
            let sector_end = i * self.bytes_per_sector - 2;
            if sector_end + 2 > MFT_RECORD_SIZE { break; }
            rec[sector_end]     = rec[usn_off + i * 2];
            rec[sector_end + 1] = rec[usn_off + i * 2 + 1];
        }
    }

    /// Load MFT record `n` into a fixed-size buffer.
    fn read_mft_record(&self, n: u64) -> Option<[u8; MFT_RECORD_SIZE]> {
        let off = self.mft_offset + n as usize * self.mft_record_size;
        let src = self.data.get(off..off + MFT_RECORD_SIZE)?;
        if &src[..4] != MFT_MAGIC { return None; }
        let mut rec = [0u8; MFT_RECORD_SIZE];
        rec.copy_from_slice(src);
        self.fixup_record(&mut rec);
        Some(rec)
    }

    /// Iterate over attributes of a record, calling `f` for each.
    /// `f` receives (attr_type, resident_data_or_empty, full_attr_slice).
    fn iter_attrs<F>(&self, rec: &[u8; MFT_RECORD_SIZE], mut f: F)
    where F: FnMut(u32, &[u8], &[u8])
    {
        let mut off = read_u16_le(rec, MFT_ATTR_OFF) as usize;
        loop {
            if off + 8 > MFT_RECORD_SIZE { break; }
            let atype  = read_u32_le(rec, off + AHDR_TYPE);
            let alen   = read_u32_le(rec, off + AHDR_LENGTH) as usize;
            if atype == ATTR_END || alen < 8 { break; }
            let non_res = rec[off + AHDR_NON_RESIDENT];
            let attr_slice = rec.get(off..off + alen).unwrap_or(&[]);
            let content = if non_res == 0 {
                let coff  = read_u16_le(rec, off + AHDR_CONTENT_OFF) as usize;
                let csize = read_u32_le(rec, off + AHDR_CONTENT_SIZE) as usize;
                attr_slice.get(coff..coff + csize).unwrap_or(&[])
            } else {
                &[]
            };
            f(atype, content, attr_slice);
            off += alen;
        }
    }

    /// Read all data bytes of a file record (handles resident and non-resident $DATA).
    fn read_file_data(&self, rec: &[u8; MFT_RECORD_SIZE]) -> Vec<u8> {
        let mut result = Vec::new();
        self.iter_attrs(rec, |atype, content, attr_slice| {
            if atype != ATTR_DATA { return; }
            let non_res = attr_slice.get(AHDR_NON_RESIDENT).copied().unwrap_or(0);
            if non_res == 0 {
                result = content.to_vec();
            } else {
                // Non-resident: decode data runs
                let run_off   = read_u16_le(attr_slice, NR_DATARUN_OFF) as usize;
                let real_size = read_u64_le(attr_slice, NR_REAL_SIZE)   as usize;
                let runs      = attr_slice.get(run_off..).unwrap_or(&[]);
                let decoded   = decode_data_runs(runs);
                let mut lcn   = 0i64;
                let mut data  = Vec::new();
                for (len_clusters, delta) in decoded {
                    lcn += delta;
                    for c in 0..len_clusters {
                        let byte_off = (lcn + c) as usize * self.bytes_per_cluster;
                        if let Some(slice) = self.data.get(byte_off..byte_off + self.bytes_per_cluster) {
                            data.extend_from_slice(slice);
                        }
                    }
                }
                data.truncate(real_size);
                result = data;
            }
        });
        result
    }

    /// List children of a directory MFT record. Returns (name, mft_record_no, is_dir).
    fn list_dir_record(&self, rec: &[u8; MFT_RECORD_SIZE]) -> Vec<(String, u64, bool)> {
        let mut entries = Vec::new();
        self.iter_attrs(rec, |atype, content, _| {
            if atype != ATTR_INDEX_ROOT { return; }
            // INDEX_ROOT: 16-byte header then index entries
            let entry_off_base = 16usize;
            let mut eoff = entry_off_base;
            while eoff + 16 <= content.len() {
                let ref_num    = read_u64_le(content, eoff) & 0x0000_FFFF_FFFF_FFFF;
                let entry_len  = read_u16_le(content, eoff + 8) as usize;
                let key_len    = read_u16_le(content, eoff + 10) as usize;
                let flags      = read_u16_le(content, eoff + 12);
                if entry_len < 16 { break; }
                if flags & 0x02 != 0 { break; } // end-of-index-block flag
                // $FILE_NAME key follows the 16-byte index entry header
                if key_len >= FN_NAME + 2 {
                    let key = match content.get(eoff + 16..eoff + 16 + key_len) {
                        Some(k) => k,
                        None    => { eoff += entry_len; continue; }
                    };
                    let name_len   = key[FN_NAME_LEN] as usize;
                    let name_chars = key.get(FN_NAME..FN_NAME + name_len * 2).unwrap_or(&[]);
                    let units: Vec<u16> = name_chars.chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect();
                    let name: String = char::decode_utf16(units).map(|r| r.unwrap_or('?')).collect();
                    // Determine if directory by reading the referenced MFT record
                    let is_dir = self.read_mft_record(ref_num)
                        .map(|r| read_u16_le(&r, MFT_FLAGS) & MFT_FLAG_DIR != 0)
                        .unwrap_or(false);
                    if name != "." && name != ".." {
                        entries.push((name, ref_num, is_dir));
                    }
                }
                eoff += entry_len;
            }
        });
        entries
    }

    /// Resolve a path to an MFT record number.
    fn resolve_path(&self, path: &str) -> Option<u64> {
        let components: Vec<&str> = path.trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut cur_rec_no = MFT_REC_ROOT;
        for comp in &components {
            let rec     = self.read_mft_record(cur_rec_no)?;
            let entries = self.list_dir_record(&rec);
            let found   = entries.into_iter().find(|(n, ..)| n.eq_ignore_ascii_case(comp))?;
            cur_rec_no  = found.1;
        }
        Some(cur_rec_no)
    }
}

/// Mount an NTFS volume from a raw byte slice.
/// Returns true if the boot sector contains the NTFS OEM ID.
pub fn mount(image: Vec<u8>) -> bool {
    if image.len() < 512 { return false; }
    if &image[3..11] != NTFS_SIGNATURE { return false; }

    let bytes_per_sector  = read_u16_le(&image, BS_BYTES_PER_SECTOR) as usize;
    let secs_per_cluster  = image[BS_SECS_PER_CLUSTER] as usize;
    let bytes_per_cluster = bytes_per_sector * secs_per_cluster;
    let mft_lcn           = read_i64_le(&image, BS_MFT_LCN);
    let cpf_raw           = image[BS_CLUSTERS_PER_MFT] as i8;
    let mft_record_size   = if cpf_raw >= 0 {
        cpf_raw as usize * bytes_per_cluster
    } else {
        1usize << (-cpf_raw as usize)
    };
    let mft_offset = mft_lcn as usize * bytes_per_cluster;

    *VOL.lock() = Some(NtfsVol {
        data: image,
        bytes_per_sector,
        bytes_per_cluster,
        mft_offset,
        mft_record_size,
    });
    log::info!("ntfs: mounted volume (ro), MFT at byte offset {}", mft_offset);
    true
}

/// Read the full contents of a file (read-only). Returns Err(-2) if not found.
pub fn read_file(path: &str) -> Result<Vec<u8>, isize> {
    let guard  = VOL.lock();
    let vol    = guard.as_ref().ok_or(-5isize)?;
    let rec_no = vol.resolve_path(path).ok_or(-2isize)?;
    let rec    = vol.read_mft_record(rec_no).ok_or(-5isize)?;
    let flags  = read_u16_le(&rec, MFT_FLAGS);
    if flags & MFT_FLAG_DIR != 0 { return Err(-21); } // EISDIR
    Ok(vol.read_file_data(&rec))
}

/// List directory entries at `path`. Returns (name, is_dir) pairs.
pub fn read_dir(path: &str) -> Result<Vec<(String, bool)>, isize> {
    let guard  = VOL.lock();
    let vol    = guard.as_ref().ok_or(-5isize)?;
    let rec_no = vol.resolve_path(path).ok_or(-2isize)?;
    let rec    = vol.read_mft_record(rec_no).ok_or(-5isize)?;
    let flags  = read_u16_le(&rec, MFT_FLAGS);
    if flags & MFT_FLAG_DIR == 0 { return Err(-20); } // ENOTDIR
    let entries = vol.list_dir_record(&rec);
    Ok(entries.into_iter().map(|(n, _, d)| (n, d)).collect())
}

/// Return the size of a file in bytes, or Err(-2) if not found.
pub fn file_size(path: &str) -> Result<u64, isize> {
    let guard  = VOL.lock();
    let vol    = guard.as_ref().ok_or(-5isize)?;
    let rec_no = vol.resolve_path(path).ok_or(-2isize)?;
    let rec    = vol.read_mft_record(rec_no).ok_or(-5isize)?;
    let flags  = read_u16_le(&rec, MFT_FLAGS);
    if flags & MFT_FLAG_DIR != 0 { return Err(-21); }
    let data = vol.read_file_data(&rec);
    Ok(data.len() as u64)
}

/// Unmount and release the volume.
pub fn umount() {
    *VOL.lock() = None;
}
