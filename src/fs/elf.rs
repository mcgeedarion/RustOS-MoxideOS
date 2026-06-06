//! fs::elf — VFS-layer ELF metadata helpers.
//!
//! This module complements `crate::exec::elf` (the ELF loader) with
//! filesystem-oriented helpers: reading ELF headers and notes from
//! open file descriptors or VFS paths, and producing NT_FILE / NT_PRSTATUS
//! note data for core dumps.
//!
//! ## Why separate from exec::elf?
//!   `exec::elf` operates on raw byte slices already in memory.  This
//!   module opens files through the VFS, performs ranged reads, and
//!   returns structured data without requiring the entire binary in RAM.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::exec::elf::{
    parse_elf_header, parse_phdrs_with_hdr, Elf64Hdr, Elf64Phdr, EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3,
};
use crate::fs::vfs;

/// Return `true` if the first 4 bytes of `data` are the ELF magic bytes.
#[inline]
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4
        && data[EI_MAG0] == 0x7f
        && data[EI_MAG1] == b'E'
        && data[EI_MAG2] == b'L'
        && data[EI_MAG3] == b'F'
}

/// Read just the ELF header (64 bytes) from a file at `path`.
/// Returns `None` if the file cannot be opened, is too small, or is not ELF.
pub fn read_elf_header(path: &str) -> Option<Elf64Hdr> {
    let fd = vfs::open(path, vfs::O_RDONLY).ok()?;
    let mut buf = alloc::vec![0u8; 64];
    let n = vfs::read(fd, &mut buf);
    vfs::close(fd);
    if n < 64 {
        return None;
    }
    if !is_elf(&buf) {
        return None;
    }
    parse_elf_header(&buf).ok()
}

/// Read the ELF header **and** all program headers from `path`.
/// Returns `(header, phdrs)` or `None` on any error.
pub fn read_phdrs(path: &str) -> Option<(Elf64Hdr, Vec<Elf64Phdr>)> {
    let fd = vfs::open(path, vfs::O_RDONLY).ok()?;
    let file_size = vfs::fstat(fd).unwrap_or(0);
    if file_size == 0 || file_size > 64 * 1024 * 1024 {
        vfs::close(fd);
        return None;
    }
    let mut buf = alloc::vec![0u8; file_size];
    let n = vfs::pread(fd, buf.as_mut_ptr(), buf.len(), 0);
    vfs::close(fd);
    if n <= 0 {
        return None;
    }
    let buf = &buf[..n as usize];
    let hdr = parse_elf_header(buf).ok()?;
    let phdrs = parse_phdrs_with_hdr(buf, &hdr)?;
    Some((hdr, phdrs))
}

/// A single ELF note entry (from a PT_NOTE segment or `.note` section).
#[derive(Debug, Clone)]
pub struct ElfNote {
    pub name: String,
    pub note_type: u32,
    pub desc: Vec<u8>,
}

/// Parse ELF note entries from a raw PT_NOTE segment byte slice.
pub fn parse_notes(data: &[u8]) -> Vec<ElfNote> {
    let mut notes = Vec::new();
    let mut pos = 0usize;

    while pos + 12 <= data.len() {
        let namesz = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4])) as usize;
        let descsz =
            u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        let ntype = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap_or([0; 4]));
        pos += 12;

        // name is padded to 4-byte boundary
        let name_padded = (namesz + 3) & !3;
        let desc_padded = (descsz + 3) & !3;

        if pos + name_padded + desc_padded > data.len() {
            break;
        }

        let name_bytes = &data[pos..pos + namesz.saturating_sub(1)]; // strip NUL
        let name = core::str::from_utf8(name_bytes).unwrap_or("").to_string(); // alloc::string::ToString
        pos += name_padded;

        let desc = data[pos..pos + descsz].to_vec();
        pos += desc_padded;

        notes.push(ElfNote {
            name,
            note_type: ntype,
            desc,
        });
    }
    notes
}

/// Read and parse the PT_NOTE segment(s) from the ELF binary at `path`.
pub fn read_notes(path: &str) -> Vec<ElfNote> {
    use crate::exec::elf::PT_NOTE;

    let (hdr, phdrs) = match read_phdrs(path) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let _ = hdr; // used implicitly via phdrs

    let fd = match vfs::open(path, vfs::O_RDONLY) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let mut all_notes = Vec::new();
    for ph in &phdrs {
        if ph.p_type != PT_NOTE {
            continue;
        }
        let off = ph.p_offset as usize;
        let sz = ph.p_filesz as usize;
        if sz == 0 {
            continue;
        }
        let mut buf = alloc::vec![0u8; sz];
        let n = vfs::pread(fd, buf.as_mut_ptr(), sz, off);
        if n > 0 {
            all_notes.extend(parse_notes(&buf[..n as usize]));
        }
    }
    vfs::close(fd);
    all_notes
}

/// NT_FILE note entry: a mapped file region.
#[derive(Debug, Clone)]
pub struct NtFileEntry {
    pub start: u64,
    pub end: u64,
    pub file_ofs: u64,
    pub filename: String,
}

/// Encode a list of `NtFileEntry` records into a raw NT_FILE note `desc`
/// payload. Format matches Linux: count, page_size, then (start, end, ofs) * n,
/// then names.
pub fn encode_nt_file(entries: &[NtFileEntry], page_size: u64) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    let count = entries.len() as u64;
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&page_size.to_le_bytes());

    for e in entries {
        buf.extend_from_slice(&e.start.to_le_bytes());
        buf.extend_from_slice(&e.end.to_le_bytes());
        buf.extend_from_slice(&e.file_ofs.to_le_bytes());
    }
    for e in entries {
        buf.extend_from_slice(e.filename.as_bytes());
        buf.push(0); // NUL terminate
    }
    buf
}
