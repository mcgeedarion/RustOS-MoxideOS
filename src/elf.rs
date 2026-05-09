//! ELF64 parser and loader used by the kernel.
//!
//! ## Parsing
//!   `parse_header(data)`          — validate magic/class/endian/machine
//!   `parse_elf_header(data)`      — Result<> wrapper (used by exec.rs)
//!   `parse_phdrs(data)`           — single-arg, returns Option<Vec<Elf64Phdr>>
//!   `parse_phdrs_with_hdr(data, hdr)` — two-arg form used by exec.rs
//!
//! ## Loading
//!   `load_elf_into(cr3, data, hdr, phdrs)` — map PT_LOAD segs into cr3
//!   `end_of_bss(phdrs, bias)`     — highest mapped VA (for brk base)
//!   `find_interp(data, phdrs)`    — extract PT_INTERP path string

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

// ── ELF type constants ────────────────────────────────────────────────────────

pub const ET_EXEC: u16 = 2;
pub const ET_DYN:  u16 = 3;

// ── Program header type constants ─────────────────────────────────────────────

pub const PT_LOAD:    u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP:  u32 = 3;
pub const PT_PHDR:    u32 = 6;

// ── Program header permission flags ───────────────────────────────────────────

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// ── Internal constants ────────────────────────────────────────────────────────

const ELF_MAGIC:   &[u8; 4] = b"\x7fELF";
const ELFCLASS64:  u8  = 2;
const ELFDATA2LSB: u8  = 1;
const EV_CURRENT:  u32 = 1;
const EM_X86_64:   u16 = 0x3E;
const EM_RISCV:    u16 = 0xF3;

/// Load bias applied to ET_DYN (PIE) images that have no PT_PHDR hint.
pub const ELF_DYN_BIAS: usize = 0x0040_0000;

const PAGE: usize = 4096;

// ── ELF64 header ──────────────────────────────────────────────────────────────

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

// ── ELF64 program header ──────────────────────────────────────────────────────

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

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Validate and return a reference to the ELF64 header in `data`.
///
/// Returns `None` if the image is too small, has a bad magic/class/endian,
/// a version other than EV_CURRENT, or an unsupported machine type.
pub fn parse_header(data: &[u8]) -> Option<&Elf64Hdr> {
    if data.len() < core::mem::size_of::<Elf64Hdr>() { return None; }
    let hdr = unsafe { &*(data.as_ptr() as *const Elf64Hdr) };
    if &hdr.e_ident[0..4] != ELF_MAGIC   { return None; }
    if hdr.e_ident[4]     != ELFCLASS64  { return None; }
    if hdr.e_ident[5]     != ELFDATA2LSB { return None; }
    if hdr.e_version      != EV_CURRENT  { return None; }
    // Accept x86-64 or RISC-V 64-bit.
    #[cfg(target_arch = "x86_64")]
    if hdr.e_machine != EM_X86_64 && hdr.e_machine != EM_RISCV { return None; }
    Some(hdr)
}

/// Result<>-returning wrapper used by exec.rs.
/// Returns a *copy* of the header (avoids lifetime issues with `do_execve`).
pub fn parse_elf_header(data: &[u8]) -> Result<Elf64Hdr, i32> {
    parse_header(data).copied().ok_or(-8) // -ENOEXEC
}

/// Parse all program headers from `data` (single-arg form).
///
/// Returns `None` if the header is invalid or any phdr entry is out of bounds.
pub fn parse_phdrs(data: &[u8]) -> Option<Vec<Elf64Phdr>> {
    let hdr = parse_header(data)?;
    parse_phdrs_with_hdr(data, hdr)
}

/// Two-argument form used by exec.rs (hdr already parsed and validated).
pub fn parse_phdrs_with_hdr(data: &[u8], hdr: &Elf64Hdr) -> Option<Vec<Elf64Phdr>> {
    let phent = hdr.e_phentsize as usize;
    if phent < core::mem::size_of::<Elf64Phdr>() { return None; }

    let mut phdrs = Vec::with_capacity(hdr.e_phnum as usize);
    for i in 0..hdr.e_phnum as usize {
        let off = (hdr.e_phoff as usize).checked_add(i.checked_mul(phent)?)? ;
        if off.checked_add(core::mem::size_of::<Elf64Phdr>())? > data.len() {
            return None;
        }
        let ph = unsafe { *(data.as_ptr().add(off) as *const Elf64Phdr) };
        phdrs.push(ph);
    }
    Some(phdrs)
}

// ── Loading ───────────────────────────────────────────────────────────────────

/// Map all PT_LOAD segments of `data` into the address space rooted at `cr3`
/// (physical address of the PML4 on x86_64, or SATP PPN on RISC-V).
///
/// For ET_DYN images the caller must add `ELF_DYN_BIAS` to the desired base
/// before calling (exec.rs does this); this function adds no bias itself.
///
/// Returns the ELF entry point VA on success, or `-ENOEXEC` on failure.
pub fn load_elf_into(
    cr3:   usize,
    data:  &[u8],
    hdr:   &Elf64Hdr,
    phdrs: &[Elf64Phdr],
) -> Result<usize, i32> {
    let bias: usize = if hdr.e_type == ET_DYN { ELF_DYN_BIAS } else { 0 };
    let entry = hdr.e_entry as usize + bias;

    for ph in phdrs {
        if ph.p_type != PT_LOAD { continue; }

        let vaddr  = ph.p_vaddr  as usize + bias;
        let filesz = ph.p_filesz as usize;
        let memsz  = ph.p_memsz  as usize;
        let offset = ph.p_offset as usize;

        if filesz > 0 && (offset > data.len() || offset + filesz > data.len()) {
            return Err(-8); // truncated image
        }
        if memsz == 0 { continue; }

        let va_start = vaddr & !(PAGE - 1);
        let va_end   = (vaddr + memsz + PAGE - 1) & !(PAGE - 1);
        let file_end = vaddr + filesz;

        let mut va = va_start;
        while va < va_end {
            let pa = crate::mm::pmm::alloc_page().ok_or(-12i32)?;
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }

            // Copy file bytes that fall inside this page.
            let pg_file_start = va.max(vaddr);
            let pg_file_end   = (va + PAGE).min(file_end);
            if pg_file_start < pg_file_end {
                let src_off  = offset + (pg_file_start - vaddr);
                let dst_off  = pg_file_start - va;
                let copy_len = pg_file_end - pg_file_start;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(src_off),
                        (pa + dst_off) as *mut u8,
                        copy_len,
                    );
                }
            }

            map_page_arch(cr3, va, pa, ph.p_flags);
            va += PAGE;
        }
    }

    Ok(entry)
}

/// Return the first page-aligned address above the highest PT_LOAD segment
/// (accounting for `bias`).  This is the initial brk / end-of-BSS.
pub fn end_of_bss(phdrs: &[Elf64Phdr], bias: usize) -> usize {
    let top = phdrs.iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr as usize + ph.p_memsz as usize + bias)
        .max()
        .unwrap_or(0);
    (top + PAGE - 1) & !(PAGE - 1)
}

/// If the image has a PT_INTERP segment, return the interpreter path string.
///
/// Returns `None` for statically-linked executables.
pub fn find_interp<'a>(data: &'a [u8], phdrs: &[Elf64Phdr]) -> Option<&'a str> {
    for ph in phdrs {
        if ph.p_type != PT_INTERP { continue; }
        let off = ph.p_offset as usize;
        let sz  = ph.p_filesz as usize;
        if off + sz > data.len() { return None; }
        let bytes = &data[off..off + sz];
        // Strip trailing NUL.
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(sz);
        return core::str::from_utf8(&bytes[..nul]).ok();
    }
    None
}

// ── Architecture-specific page mapping ───────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn map_page_arch(cr3: usize, va: usize, pa: usize, flags: u32) {
    use crate::arch::x86_64::paging;
    let mut pte: u64 = paging::PTE_PRESENT | paging::PTE_USER;
    if flags & PF_W != 0 { pte |= paging::PTE_WRITABLE; }
    if flags & PF_X == 0 { pte |= paging::PTE_NX; }
    unsafe { paging::map_page(cr3, va, pa, pte); }
}

#[cfg(target_arch = "riscv64")]
fn map_page_arch(satp_ppn: usize, va: usize, pa: usize, flags: u32) {
    use crate::arch::riscv64::paging as rv;
    let mut f = rv::PTE_V | rv::PTE_U | rv::PTE_R;
    if flags & PF_W != 0 { f |= rv::PTE_W; }
    if flags & PF_X != 0 { f |= rv::PTE_X; }
    unsafe { rv::map_page(satp_ppn, va, pa, f); }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
fn map_page_arch(_cr3: usize, _va: usize, _pa: usize, _flags: u32) {
    unimplemented!("map_page_arch")
}
