//! ISO 9660 (CDFS) read-only filesystem driver.
//!
//! Supports:
//!   - Primary Volume Descriptor detection (magic at sector 0x8000)
//!   - Directory record traversal
//!   - File data reads via LBA + extent
//!
//! Used for:
//!   - Bootable ISO testing in QEMU (e.g. cdrom device)
//!   - Reading files off mounted ISO images
//!
//! All operations are read-only; ISO 9660 has no write spec.

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use spin::Mutex;

const SECTOR_SIZE: usize = 2048;
const PVD_SECTOR: usize = 16; // Primary Volume Descriptor lives at sector 16
const PVD_MAGIC_OFFSET: usize = 1;
const PVD_MAGIC: &[u8] = b"CD001";
const PVD_TYPE_PRIMARY: u8 = 1;
const PVD_ROOT_DIR_OFF: usize = 156; // byte offset of root directory record in PVD

// Directory record field offsets
const DR_LEN: usize = 0;
const DR_EXT_LBA: usize = 2; // LE u32: starting LBA of extent
const DR_EXT_SIZE: usize = 10; // LE u32: size of extent in bytes
const DR_FLAGS: usize = 25; // file flags (bit 1 = directory)
const DR_NAME_LEN: usize = 32;
const DR_NAME: usize = 33;

const FLAG_DIRECTORY: u8 = 0x02;

struct CdImage {
    data: Vec<u8>,
    root_lba: u32,
    root_len: u32,
}

static IMAGE: Mutex<Option<CdImage>> = Mutex::new(None);

fn read_sector(img: &[u8], lba: u32) -> Option<&[u8]> {
    let off = lba as usize * SECTOR_SIZE;
    img.get(off..off + SECTOR_SIZE)
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    let b = &buf[off..off + 4];
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse file/directory name from a directory record, stripping the `;1`
/// version suffix.
fn parse_name(rec: &[u8]) -> String {
    let len = rec[DR_NAME_LEN] as usize;
    let raw = &rec[DR_NAME..DR_NAME + len];
    // special entries: \x00 = current dir, \x01 = parent dir
    if raw == [0x00] {
        return ".".to_string();
    }
    if raw == [0x01] {
        return "..".to_string();
    }
    let s = core::str::from_utf8(raw).unwrap_or("");
    // strip version suffix e.g. "FILE.TXT;1" → "FILE.TXT"
    let s = s.split(';').next().unwrap_or(s);
    s.to_ascii_lowercase()
}

/// Walk a directory extent and return all (name, lba, size, is_dir) entries.
fn list_dir(img: &[u8], lba: u32, size: u32) -> Vec<(String, u32, u32, bool)> {
    let mut out = Vec::new();
    let end = lba as usize * SECTOR_SIZE + size as usize;
    let mut pos = lba as usize * SECTOR_SIZE;

    while pos < end {
        let rec_len = match img.get(pos + DR_LEN) {
            Some(&l) if l >= 34 => l as usize,
            Some(&0) => {
                // padding: advance to next sector boundary
                let next = (pos / SECTOR_SIZE + 1) * SECTOR_SIZE;
                pos = next;
                continue;
            },
            _ => break,
        };
        let rec = match img.get(pos..pos + rec_len) {
            Some(r) => r,
            None => break,
        };
        let elba = read_u32_le(rec, DR_EXT_LBA);
        let esize = read_u32_le(rec, DR_EXT_SIZE);
        let flags = rec[DR_FLAGS];
        let name = parse_name(rec);
        let is_dir = flags & FLAG_DIRECTORY != 0;
        out.push((name, elba, esize, is_dir));
        pos += rec_len;
    }
    out
}

/// Resolve an absolute path (e.g. "/boot/kernel") to (lba, size, is_dir).
fn resolve_path(img: &CdImage, path: &str) -> Option<(u32, u32, bool)> {
    let mut cur_lba = img.root_lba;
    let mut cur_size = img.root_len;
    let components: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if components.is_empty() {
        return Some((cur_lba, cur_size, true));
    }

    for (i, comp) in components.iter().enumerate() {
        let entries = list_dir(&img.data, cur_lba, cur_size);
        let found = entries
            .into_iter()
            .find(|(name, ..)| name.eq_ignore_ascii_case(comp))?;
        if i == components.len() - 1 {
            return Some((found.1, found.2, found.3));
        }
        if !found.3 {
            return None;
        } // not a directory
        cur_lba = found.1;
        cur_size = found.2;
    }
    None
}

/// Load an ISO image from a raw byte slice (e.g. from a virtio-blk cdrom
/// device). Returns true if the image contains a valid ISO 9660 Primary Volume
/// Descriptor.
pub fn mount(image_data: Vec<u8>) -> bool {
    let pvd_off = PVD_SECTOR * SECTOR_SIZE;
    let pvd = match image_data.get(pvd_off..pvd_off + SECTOR_SIZE) {
        Some(s) => s,
        None => return false,
    };
    if pvd[0] != PVD_TYPE_PRIMARY {
        return false;
    }
    if &pvd[PVD_MAGIC_OFFSET..PVD_MAGIC_OFFSET + 5] != PVD_MAGIC {
        return false;
    }

    let root_rec = &pvd[PVD_ROOT_DIR_OFF..PVD_ROOT_DIR_OFF + 34];
    let root_lba = read_u32_le(root_rec, DR_EXT_LBA);
    let root_len = read_u32_le(root_rec, DR_EXT_SIZE);

    *IMAGE.lock() = Some(CdImage {
        data: image_data,
        root_lba,
        root_len,
    });
    log::info!(
        "cdfs: mounted ISO 9660 image, root LBA={} size={}",
        root_lba,
        root_len
    );
    true
}

/// Read the entire contents of a file at `path`. Returns Err(-2) if not found.
pub fn read_file(path: &str) -> Result<Vec<u8>, isize> {
    let guard = IMAGE.lock();
    let img = guard.as_ref().ok_or(-5isize)?; // EIO: not mounted
    let (lba, size, is_dir) = resolve_path(img, path).ok_or(-2isize)?; // ENOENT
    if is_dir {
        return Err(-21);
    } // EISDIR
    let start = lba as usize * SECTOR_SIZE;
    let end = start + size as usize;
    img.data.get(start..end).map(|s| s.to_vec()).ok_or(-5)
}

/// List directory entries at `path`. Returns (name, is_dir) pairs.
pub fn read_dir(path: &str) -> Result<Vec<(String, bool)>, isize> {
    let guard = IMAGE.lock();
    let img = guard.as_ref().ok_or(-5isize)?;
    let (lba, size, is_dir) = resolve_path(img, path).ok_or(-2isize)?;
    if !is_dir {
        return Err(-20);
    } // ENOTDIR
    let entries = list_dir(&img.data, lba, size);
    Ok(entries
        .into_iter()
        .filter(|(n, ..)| n != "." && n != "..")
        .map(|(n, _, _, d)| (n, d))
        .collect())
}

/// Return the size in bytes of the file at `path`, or Err(-2) if not found.
pub fn file_size(path: &str) -> Result<u64, isize> {
    let guard = IMAGE.lock();
    let img = guard.as_ref().ok_or(-5isize)?;
    let (_, size, is_dir) = resolve_path(img, path).ok_or(-2isize)?;
    if is_dir {
        return Err(-21);
    }
    Ok(size as u64)
}

/// Unmount and release the in-memory image.
pub fn umount() {
    *IMAGE.lock() = None;
}
