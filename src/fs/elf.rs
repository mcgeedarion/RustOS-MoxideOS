//! ELF64 parser for execve.
//!
//! Only ELF64 LSB executables and shared objects are supported.
//! Statically linked binaries are the primary target; dynamic linking
//! requires a separate interpreter load (ld-musl / ld.so) which exec.rs
//! handles by detecting PT_INTERP and loading the interpreter instead.
//!
//! ## Functions
//!   parse_elf_header(data)          -> Result<Elf64Hdr, errno>
//!   parse_phdrs(data, hdr)          -> Vec<Elf64Phdr>
//!   load_elf_into(cr3, data, phdrs) -> Result<entry_va, errno>
//!   find_interp(data, phdrs)        -> Option<&str>

extern crate alloc;
use alloc::vec::Vec;

// ── ELF64 types ──────────────────────────────────────────────────────────

pub type Elf64Addr  = u64;
pub type Elf64Off   = u64;
pub type Elf64Half  = u16;
pub type Elf64Word  = u32;
pub type Elf64Xword = u64;

pub const ELFMAG:    &[u8] = b"\x7fELF";
pub const ELFCLASS64: u8   = 2;
pub const ELFDATA2LSB: u8  = 1;
pub const ET_EXEC:   u16   = 2;
pub const ET_DYN:    u16   = 3;
pub const PT_LOAD:   u32   = 1;
pub const PT_INTERP: u32   = 3;
pub const PT_PHDR:   u32   = 6;
pub const PF_X: u32        = 1;
pub const PF_W: u32        = 2;
pub const PF_R: u32        = 4;

/// ELF64 file header (64 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Hdr {
    pub e_ident:     [u8; 16],
    pub e_type:      Elf64Half,
    pub e_machine:   Elf64Half,
    pub e_version:   Elf64Word,
    pub e_entry:     Elf64Addr,
    pub e_phoff:     Elf64Off,
    pub e_shoff:     Elf64Off,
    pub e_flags:     Elf64Word,
    pub e_ehsize:    Elf64Half,
    pub e_phentsize: Elf64Half,
    pub e_phnum:     Elf64Half,
    pub e_shentsize: Elf64Half,
    pub e_shnum:     Elf64Half,
    pub e_shstrndx:  Elf64Half,
}

/// ELF64 program header (56 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type:   Elf64Word,
    pub p_flags:  Elf64Word,
    pub p_offset: Elf64Off,
    pub p_vaddr:  Elf64Addr,
    pub p_paddr:  Elf64Addr,
    pub p_filesz: Elf64Xword,
    pub p_memsz:  Elf64Xword,
    pub p_align:  Elf64Xword,
}

// ── parse_elf_header ──────────────────────────────────────────────────────

/// Validate and return a copy of the ELF64 header from `data`.
/// Returns -ENOEXEC (-8) on any format error.
pub fn parse_elf_header(data: &[u8]) -> Result<Elf64Hdr, i32> {
    if data.len() < core::mem::size_of::<Elf64Hdr>() { return Err(-8); }
    if &data[..4] != ELFMAG           { return Err(-8); }
    if data[4] != ELFCLASS64          { return Err(-8); }
    if data[5] != ELFDATA2LSB         { return Err(-8); }
    let hdr = unsafe { *(data.as_ptr() as *const Elf64Hdr) };
    if hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN { return Err(-8); }
    if hdr.e_machine != 0x3E          { return Err(-8); }
    if hdr.e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() { return Err(-8); }
    Ok(hdr)
}

// ── parse_phdrs ────────────────────────────────────────────────────────────

/// Return a Vec of all program headers from `data`.
pub fn parse_phdrs(data: &[u8], hdr: &Elf64Hdr) -> Vec<Elf64Phdr> {
    let mut out = Vec::new();
    let off  = hdr.e_phoff as usize;
    let sz   = core::mem::size_of::<Elf64Phdr>();
    let n    = hdr.e_phnum as usize;
    if off + n * sz > data.len() { return out; }
    for i in 0..n {
        let phdr = unsafe { *(data.as_ptr().add(off + i * sz) as *const Elf64Phdr) };
        out.push(phdr);
    }
    out
}

// ── load_elf_into ──────────────────────────────────────────────────────────

/// Load all PT_LOAD segments from `data` into the page tables rooted at `cr3`.
///
/// Each segment's virtual range is rounded to page boundaries.
/// Pages covered by the file image are copied in; any BSS gap
/// (p_memsz > p_filesz) is zero-filled (pages are zeroed before copy).
///
/// PTE flags derived from p_flags:
///   PF_W (2) → Writable bit set
///   PF_X (1) → NX bit cleared  (NX is set by default for data pages)
///
/// Returns the ELF entry point VA, adjusted by the load bias for ET_DYN.
pub fn load_elf_into(cr3: usize, data: &[u8], hdr: &Elf64Hdr, phdrs: &[Elf64Phdr])
    -> Result<usize, i32>
{
    use crate::arch::x86_64::paging::map_page;
    use crate::mm::pmm::{alloc_page, free_page};

    const PAGE_SIZE: usize = 4096;

    // ET_DYN: fixed load bias at 4 MiB.  ET_EXEC: no bias.
    let bias: usize = if hdr.e_type == ET_DYN { 0x0040_0000 } else { 0 };

    for ph in phdrs {
        if ph.p_type != PT_LOAD { continue; }
        if ph.p_memsz == 0      { continue; }

        let va_start = (ph.p_vaddr as usize + bias) & !(PAGE_SIZE - 1);
        let va_end   = (ph.p_vaddr as usize + bias + ph.p_memsz as usize + PAGE_SIZE - 1)
                       & !(PAGE_SIZE - 1);
        let pte_flags = seg_pte_flags(ph.p_flags);

        for va in (va_start..va_end).step_by(PAGE_SIZE) {
            let pa = alloc_page().ok_or(-12i32)?;
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }

            let seg_va_base = ph.p_vaddr as usize + bias;
            if va < seg_va_base + ph.p_filesz as usize {
                let page_offset_in_seg = va.saturating_sub(seg_va_base);
                let file_src = ph.p_offset as usize + page_offset_in_seg;
                let copy_len = PAGE_SIZE
                    .min(ph.p_filesz as usize
                             .saturating_sub(page_offset_in_seg))
                    .min(data.len().saturating_sub(file_src));
                if copy_len > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(file_src),
                            pa as *mut u8,
                            copy_len,
                        );
                    }
                }
            }
            // Pages beyond filesz are already zero (BSS).

            map_page(cr3, va, pa, pte_flags);
        }
    }

    Ok(hdr.e_entry as usize + bias)
}

/// Convert ELF p_flags to x86-64 PTE flags.
/// bit 0 = Present (always), bit 1 = Writable (PF_W), bit 2 = User (always),
/// bit 63 = NX (set unless PF_X).
fn seg_pte_flags(p_flags: u32) -> u64 {
    let mut f: u64 = 1 | (1 << 2); // Present | User
    if p_flags & PF_W != 0 { f |= 1 << 1; }
    if p_flags & PF_X == 0 { f |= 1u64 << 63; }
    f
}

// ── find_interp ────────────────────────────────────────────────────────────

/// Return the interpreter path from a PT_INTERP segment, if present.
pub fn find_interp<'a>(data: &'a [u8], phdrs: &[Elf64Phdr]) -> Option<&'a str> {
    for ph in phdrs {
        if ph.p_type != PT_INTERP { continue; }
        let off = ph.p_offset as usize;
        let len = ph.p_filesz as usize;
        if off + len > data.len() { return None; }
        let s = &data[off..off + len];
        let s = if s.last() == Some(&0) { &s[..s.len()-1] } else { s };
        return core::str::from_utf8(s).ok();
    }
    None
}
