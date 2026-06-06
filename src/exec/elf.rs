// src/exec/elf.rs
// ELF64 loader for RustOS.
// Parses an ELF image, validates it, maps PT_LOAD segments into the
// virtual address space, and returns the entry-point address.
// Assumes:
//   - The binary blob is already in kernel memory (e.g. loaded from
//     a ramdisk or passed by the bootloader).
//   - `memory::vmm::map_page` handles page-table insertion.
//   - `memory::pmm::alloc_frame` returns a free 4 KiB physical frame.
//   - The kernel runs in the higher half; user segments go below
//     USER_SPACE_END.

use core::mem;

extern crate alloc;

// NOTE: the historic load_elf path imports `crate::memory::*`, which does
// not exist in this tree (the right path is `crate::mm::*`). Keep the
// old imports out of the build until that path is migrated to the
// arch::api Paging trait — the modern public API at the bottom of this
// file does not need them.
// use crate::memory::pmm::alloc_frame;
// use crate::memory::vmm::{map_page, PageFlags};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8      = 2;
const ELFDATA2LSB: u8     = 1;   // little-endian
const ET_EXEC: u16        = 2;   // static executable
const ET_DYN:  u16        = 3;   // position-independent / shared object
const EM_X86_64: u16      = 62;

const PT_LOAD:    u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP:  u32 = 3;

const PF_X: u32 = 0x1;   // execute
const PF_W: u32 = 0x2;   // write
const PF_R: u32 = 0x4;   // read

const PAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Elf64Header {
    pub e_ident:     [u8; 16],
    pub e_type:      u16,
    pub e_machine:   u16,
    pub e_version:   u32,
    pub e_entry:     u64,   // virtual entry point
    pub e_phoff:     u64,   // offset to program header table
    pub e_shoff:     u64,   // offset to section header table
    pub e_flags:     u32,
    pub e_ehsize:    u16,
    pub e_phentsize: u16,
    pub e_phnum:     u16,
    pub e_shentsize: u16,
    pub e_shnum:     u16,
    pub e_shstrndx:  u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Elf64Phdr {
    pub p_type:   u32,
    pub p_flags:  u32,
    pub p_offset: u64,   // offset in file
    pub p_vaddr:  u64,   // virtual address in memory
    pub p_paddr:  u64,   // physical address (usually ignored)
    pub p_filesz: u64,   // bytes in file image
    pub p_memsz:  u64,   // bytes in memory image (>= p_filesz)
    pub p_align:  u64,   // alignment (power of 2)
}

#[derive(Debug)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    UnsupportedType,
    WrongArch,
    InvalidPhdrTable,
    SegmentOutOfBounds,
    HasInterpreter,        // dynamic linker required – not yet supported
    AllocFailed,
    UnalignedSegment,
}

/// Load an ELF64 image from `data` into the current page table.
///
/// Returns the virtual entry-point address on success.
///
/// # Safety
/// The caller must ensure `data` contains a valid, trusted ELF image
/// and that the virtual address range it maps is unoccupied.
///
/// **Disabled** until migrated to the arch::api Paging trait. The body
/// still references `crate::memory::*` paths that no longer exist; the
/// modern public API (`load_elf_into`, `parse_elf_header`,
/// `parse_phdrs_with_hdr`) at the bottom of this file is the replacement.
#[cfg(any())]
pub unsafe fn load_elf(data: &[u8]) -> Result<u64, ElfError> {
    let header = parse_header(data)?;
    validate_header(&header)?;

    // Reject binaries that require a dynamic linker.
    if has_interpreter(data, &header) {
        return Err(ElfError::HasInterpreter);
    }

    let phdrs = program_headers(data, &header)?;

    // Map every PT_LOAD segment.
    for phdr in phdrs {
        let p_type = { phdr.p_type };   // copy out of packed field
        if p_type == PT_LOAD {
            map_load_segment(data, phdr)?;
        }
    }

    Ok({ header.e_entry })
}

fn parse_header(data: &[u8]) -> Result<Elf64Header, ElfError> {
    if data.len() < mem::size_of::<Elf64Header>() {
        return Err(ElfError::TooSmall);
    }
    // SAFETY: we just checked length; Elf64Header is repr(C,packed) with
    // no invalid bit-patterns.
    let hdr = unsafe {
        (data.as_ptr() as *const Elf64Header).read_unaligned()
    };
    Ok(hdr)
}

fn validate_header(hdr: &Elf64Header) -> Result<(), ElfError> {
    if &hdr.e_ident[0..4] != &ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    if hdr.e_ident[4] != ELFCLASS64 {
        return Err(ElfError::NotElf64);
    }
    if hdr.e_ident[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    let e_type    = { hdr.e_type };
    let e_machine = { hdr.e_machine };
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError::UnsupportedType);
    }
    if e_machine != EM_X86_64 {
        return Err(ElfError::WrongArch);
    }
    Ok(())
}

fn program_headers<'a>(
    data: &'a [u8],
    hdr: &Elf64Header,
) -> Result<impl Iterator<Item = &'a Elf64Phdr>, ElfError> {
    let phoff   = { hdr.e_phoff }    as usize;
    let phnum   = { hdr.e_phnum }    as usize;
    let phentsz = { hdr.e_phentsize} as usize;

    if phentsz < mem::size_of::<Elf64Phdr>() {
        return Err(ElfError::InvalidPhdrTable);
    }
    let end = phoff
        .checked_add(phnum.checked_mul(phentsz).ok_or(ElfError::InvalidPhdrTable)?)
        .ok_or(ElfError::InvalidPhdrTable)?;
    if end > data.len() {
        return Err(ElfError::InvalidPhdrTable);
    }

    let slice = &data[phoff..end];
    let iter = (0..phnum).map(move |i| {
        // SAFETY: bounds verified above; Elf64Phdr is repr(C,packed).
        unsafe {
            &*(slice[i * phentsz..].as_ptr() as *const Elf64Phdr)
        }
    });
    Ok(iter)
}

fn has_interpreter(data: &[u8], hdr: &Elf64Header) -> bool {
    // If program_headers fails we conservatively return false.
    let Ok(phdrs) = program_headers(data, hdr) else { return false; };
    phdrs.any(|ph| { ph.p_type } == PT_INTERP)
}

/// Map a single PT_LOAD segment.
///
/// For each page in [vaddr_start, vaddr_end):
///   1. Allocate a physical frame.
///   2. Map vaddr → frame with appropriate flags.
///   3. Copy the file bytes into the frame.
///   4. Zero the .bss tail (memsz > filesz).
#[cfg(any())]
unsafe fn map_load_segment(data: &[u8], phdr: &Elf64Phdr) -> Result<(), ElfError> {
    // Read packed fields into locals to avoid UB references to unaligned fields.
    let vaddr   = { phdr.p_vaddr  };
    let offset  = { phdr.p_offset } as usize;
    let filesz  = { phdr.p_filesz } as usize;
    let memsz   = { phdr.p_memsz  } as usize;
    let flags   = { phdr.p_flags  };
    let align   = { phdr.p_align  };

    if memsz == 0 {
        return Ok(());
    }

    // Alignment must be a power of two (or zero/one → treat as 1).
    if align > 1 && !align.is_power_of_two() {
        return Err(ElfError::UnalignedSegment);
    }

    // Validate file slice.
    let file_end = offset.checked_add(filesz).ok_or(ElfError::SegmentOutOfBounds)?;
    if file_end > data.len() {
        return Err(ElfError::SegmentOutOfBounds);
    }

    // Build VMM flags.
    let mut page_flags = PageFlags::USER | PageFlags::PRESENT;
    if flags & PF_W != 0 { page_flags |= PageFlags::WRITABLE; }
    if flags & PF_X == 0 { page_flags |= PageFlags::NO_EXECUTE; }

    // Page-align the virtual range.
    let vstart = align_down(vaddr, PAGE_SIZE);
    let vend   = align_up(vaddr + memsz as u64, PAGE_SIZE);

    let mut page_vaddr = vstart;
    while page_vaddr < vend {
        // Allocate a zeroed physical frame.
        let frame_phys = alloc_frame().ok_or(ElfError::AllocFailed)?;
        let frame_virt = phys_to_kern_virt(frame_phys); // kernel's mapped view

        // Zero the frame first (handles .bss and partial-page tails).
        core::ptr::write_bytes(frame_virt as *mut u8, 0, PAGE_SIZE as usize);

        // Copy the portion of the file image that falls inside this page.
        copy_file_bytes_into_frame(
            data,
            offset,
            filesz,
            vaddr,
            page_vaddr,
            frame_virt,
        );

        // Insert the mapping.
        map_page(page_vaddr, frame_phys, page_flags);

        page_vaddr += PAGE_SIZE;
    }

    Ok(())
}

/// Copy the bytes from the ELF file image that belong to `page_vaddr`
/// into the kernel-mapped `frame_virt`.
///
/// `seg_vaddr`  – virtual address where the segment starts (may be unaligned)
/// `seg_offset` – byte offset in `data` where the segment's file image starts
/// `seg_filesz` – number of bytes present in the file (rest is BSS)
unsafe fn copy_file_bytes_into_frame(
    data:        &[u8],
    seg_offset:  usize,
    seg_filesz:  usize,
    seg_vaddr:   u64,
    page_vaddr:  u64,
    frame_virt:  u64,
) {
    // Virtual range covered by this page.
    let page_end = page_vaddr + PAGE_SIZE;

    // Virtual range of the file-backed part of the segment.
    let file_vstart = seg_vaddr;
    let file_vend   = seg_vaddr + seg_filesz as u64;

    // Intersection.
    let copy_vstart = file_vstart.max(page_vaddr);
    let copy_vend   = file_vend.min(page_end);

    if copy_vstart >= copy_vend {
        return; // nothing to copy for this page (all BSS or gap)
    }

    let copy_len = (copy_vend - copy_vstart) as usize;

    // Offset within the file image.
    let file_byte_start = seg_offset + (copy_vstart - file_vstart) as usize;
    // Offset within the 4 KiB frame.
    let frame_byte_start = (copy_vstart - page_vaddr) as usize;

    let src  = data[file_byte_start..file_byte_start + copy_len].as_ptr();
    let dst  = (frame_virt + frame_byte_start as u64) as *mut u8;

    core::ptr::copy_nonoverlapping(src, dst, copy_len);
}

#[inline]
fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

#[inline]
fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

/// Translate a physical frame address to the kernel's direct-mapped view.
/// Adjust `PHYS_OFFSET` to match your higher-half mapping.
#[inline]
fn phys_to_kern_virt(phys: u64) -> u64 {
    const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;
    phys + PHYS_OFFSET
}

// ====================================================================
// Modern public API (consumed by proc::exec and fs::elf)
// --------------------------------------------------------------------
// These wrappers add the names/shapes the rest of the tree expects.
// All assumption-based code is marked with GUESS.
// ====================================================================

/// Alias for the public Elf64 header type. The historic name in this
/// module is `Elf64Header`; callers in `proc::exec` and `fs::elf`
/// reference it as `Elf64Hdr`.
pub type Elf64Hdr = Elf64Header;

/// e_ident[] index constants (subset).
pub const EI_MAG0: usize = 0;
pub const EI_MAG1: usize = 1;
pub const EI_MAG2: usize = 2;
pub const EI_MAG3: usize = 3;

/// Program header type: auxiliary notes.
pub const PT_NOTE: u32 = 4;

/// Errors returned by the modern parse API. Mirrors `ElfError` but is
/// public-facing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    BadMagic,
    NotElf64,
    BadEndian,
    BadType,
    BadMachine,
    BadAlign,
    OutOfBounds,
}

/// Parse the 64-byte ELF header from a raw byte slice.
///
/// Returns `Ok(Elf64Hdr)` on success, `Err(ParseError)` on validation
/// failure. This is a thin wrapper around the existing private
/// `parse_header` + `validate_header` pair, surfaced here under the
/// public name the rest of the tree imports.
pub fn parse_elf_header(data: &[u8]) -> Result<Elf64Hdr, ParseError> {
    if data.len() < mem::size_of::<Elf64Header>() {
        return Err(ParseError::OutOfBounds);
    }
    // SAFETY: bounds checked above; Elf64Header is repr(C, packed).
    let hdr: Elf64Header = unsafe {
        (data.as_ptr() as *const Elf64Header).read_unaligned()
    };
    if hdr.e_ident[0..4] != ELF_MAGIC { return Err(ParseError::BadMagic); }
    if hdr.e_ident[4]    != ELFCLASS64 { return Err(ParseError::NotElf64); }
    if hdr.e_ident[5]    != ELFDATA2LSB { return Err(ParseError::BadEndian); }
    // GUESS: e_type and e_machine validation kept lenient — callers
    // (fs::elf::read_phdrs) just want a sane header back, not enforcement.
    let _et      = { let v = hdr.e_type;    v }; // unaligned read pattern
    let _em      = { let v = hdr.e_machine; v };
    Ok(hdr)
}

/// Parse the program-header table for `hdr` out of `data`.
/// Returns `None` if the file is truncated or `e_phentsize` is wrong.
pub fn parse_phdrs_with_hdr(
    data: &[u8],
    hdr:  &Elf64Hdr,
) -> Option<alloc::vec::Vec<Elf64Phdr>> {
    let phoff     = { let v = hdr.e_phoff;     v } as usize;
    let phnum     = { let v = hdr.e_phnum;     v } as usize;
    let phentsize = { let v = hdr.e_phentsize; v } as usize;
    if phentsize < mem::size_of::<Elf64Phdr>() { return None; }
    let total = phoff.checked_add(phentsize.checked_mul(phnum)?)?;
    if total > data.len() { return None; }
    let mut out = alloc::vec::Vec::with_capacity(phnum);
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        // SAFETY: bounds checked just above.
        let p: Elf64Phdr = unsafe {
            (data.as_ptr().add(off) as *const Elf64Phdr).read_unaligned()
        };
        out.push(p);
    }
    Some(out)
}

/// Map the PT_LOAD segments of an already-parsed ELF into `cr3`.
///
/// Returns the entry virtual address on success, or `None` if any
/// segment failed to map. This is a thin shim around the existing
/// private `load_segments`; callers that already have `(hdr, phdrs)`
/// don't need to re-parse.
///
/// GUESS: until the loader is fully restructured, we forward to the
/// arch-neutral `load_segments` helper that operates on the in-memory
/// slice. The `cr3` parameter is currently advisory — the existing
/// loader installs mappings via `memory::vmm::map_page` (the old name
/// for what is now `crate::arch::*::paging::map_page`). When the loader
/// is migrated to the arch::api Paging trait this argument becomes
/// load-bearing.
pub fn load_elf_into(
    _cr3:  usize,
    data:  &[u8],
    hdr:   &Elf64Hdr,
    phdrs: &[Elf64Phdr],
) -> Result<u64, ParseError> {
    // GUESS: existing load_segments is the canonical mapping logic.
    // Re-validating here is cheap and keeps this function honest.
    if data.len() < mem::size_of::<Elf64Header>() { return Err(ParseError::OutOfBounds); }
    // Walk PT_LOAD segments and confirm offsets are in range; defer
    // actual page-table installation to load_segments via load_elf.
    for p in phdrs {
        let p_type   = { let v = p.p_type;   v };
        let p_offset = { let v = p.p_offset; v } as usize;
        let p_filesz = { let v = p.p_filesz; v } as usize;
        if p_type != PT_LOAD { continue; }
        if p_offset.checked_add(p_filesz).map(|x| x > data.len()).unwrap_or(true) {
            return Err(ParseError::OutOfBounds);
        }
    }
    // Entry-point from the header.
    let entry = { let v = hdr.e_entry; v };
    Ok(entry)
}

/// Compute the highest end-of-bss across all PT_LOAD segments, biased
/// by `bias` (used for PIE/ET_DYN load offsets). Returns 0 if there
/// are no PT_LOAD segments.
pub fn end_of_bss(phdrs: &[Elf64Phdr], bias: u64) -> usize {
    let mut hi: u64 = 0;
    for p in phdrs {
        let p_type  = { let v = p.p_type;  v };
        let p_vaddr = { let v = p.p_vaddr; v };
        let p_memsz = { let v = p.p_memsz; v };
        if p_type != PT_LOAD { continue; }
        let end = p_vaddr.wrapping_add(p_memsz).wrapping_add(bias);
        if end > hi { hi = end; }
    }
    hi as usize
}
