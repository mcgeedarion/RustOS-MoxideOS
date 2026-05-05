//! Minimal ELF64 header parser used by the kernel loader.
extern crate alloc;
use alloc::vec::Vec;

// ELF type constants
pub const ET_EXEC: u16 = 2;
pub const ET_DYN:  u16 = 3;

// Program header type constants
pub const PT_LOAD:    u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP:  u32 = 3;

// Program header permission flags
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// ELF magic bytes at e_ident[0..4].
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
/// ELFCLASS64
const ELFCLASS64: u8 = 2;
/// ELFDATA2LSB (little-endian)
const ELFDATA2LSB: u8 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Elf64Hdr {
    pub e_ident:     [u8; 16],
    pub e_type:      u16,
    pub e_machine:   u16,
    pub e_version:   u32,
    pub e_entry:     u64,
    pub e_phoff:     u64,
    pub e_shoff:     u64,
    pub e_flags:     u32,
    pub e_ehsize:    u16,
    pub e_phentsize: u16,
    pub e_phnum:     u16,
    pub e_shentsize: u16,
    pub e_shnum:     u16,
    pub e_shstrndx:  u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Elf64Phdr {
    pub p_type:   u32,
    pub p_flags:  u32,
    pub p_offset: u64,
    pub p_vaddr:  u64,
    pub p_paddr:  u64,
    pub p_filesz: u64,
    pub p_memsz:  u64,
    pub p_align:  u64,
}

/// Parse and validate an ELF64 header from `data`.
///
/// Returns `None` if the data is too small, the magic is wrong,
/// the class is not 64-bit, or the encoding is not little-endian.
pub fn parse_header(data: &[u8]) -> Option<&Elf64Hdr> {
    if data.len() < core::mem::size_of::<Elf64Hdr>() { return None; }
    let hdr = unsafe { &*(data.as_ptr() as *const Elf64Hdr) };
    if &hdr.e_ident[0..4] != ELF_MAGIC     { return None; }
    if hdr.e_ident[4]     != ELFCLASS64    { return None; } // must be 64-bit
    if hdr.e_ident[5]     != ELFDATA2LSB   { return None; } // must be LE
    Some(hdr)
}

/// Parse all program headers from a validated ELF image.
///
/// Validates each entry's offset + size against `data.len()` and
/// validates that `e_phentsize >= sizeof(Elf64Phdr)` to prevent
/// out-of-bounds reads on malformed binaries.
pub fn parse_phdrs(data: &[u8]) -> Option<Vec<Elf64Phdr>> {
    let hdr = parse_header(data)?;
    let phent = hdr.e_phentsize as usize;
    if phent < core::mem::size_of::<Elf64Phdr>() { return None; }

    let mut phdrs = Vec::with_capacity(hdr.e_phnum as usize);
    for i in 0..hdr.e_phnum as usize {
        let off = (hdr.e_phoff as usize).checked_add(i.checked_mul(phent)?)? ;
        if off.checked_add(core::mem::size_of::<Elf64Phdr>())? > data.len() {
            break;
        }
        // SAFETY: bounds checked above; data is at least Elf64Phdr-aligned
        // because it comes from a page-aligned kernel buffer.
        let ph = unsafe { *(data.as_ptr().add(off) as *const Elf64Phdr) };
        phdrs.push(ph);
    }
    Some(phdrs)
}
