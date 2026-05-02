//! Minimal ELF64 header parser used by the kernel loader.
extern crate alloc;
use alloc::vec::Vec;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN:  u16 = 3;
pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PT_DYNAMIC: u32 = 2;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const PF_X: u32 = 1;

#[repr(C)] #[derive(Copy,Clone)]
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

#[repr(C)] #[derive(Copy,Clone)]
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

pub fn parse_phdrs(data: &[u8]) -> Option<Vec<Elf64Phdr>> {
    if data.len() < core::mem::size_of::<Elf64Hdr>() { return None; }
    let hdr = unsafe { &*(data.as_ptr() as *const Elf64Hdr) };
    if &hdr.e_ident[..4] != b"\x7fELF" { return None; }
    let mut phdrs = Vec::new();
    for i in 0..hdr.e_phnum as usize {
        let off = hdr.e_phoff as usize + i * hdr.e_phentsize as usize;
        if off + core::mem::size_of::<Elf64Phdr>() > data.len() { break; }
        let ph = unsafe { *(data.as_ptr().add(off) as *const Elf64Phdr) };
        phdrs.push(ph);
    }
    Some(phdrs)
}
