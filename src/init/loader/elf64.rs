//! 64-bit ELF loader.
//!
//! Parses an ELF64 executable and maps its PT_LOAD segments into a new
//! address space.  Called by proc::exec::sys_execve and kernel_main.
//!
//! ## What this does
//!   1. Validate ELF header (magic, class=64, type=EXEC or DYN).
//!   2. Walk PT_LOAD program headers:
//!        - Allocate physical pages via pmm::alloc_page.
//!        - Copy file data (filesz bytes).
//!        - Zero-fill the BSS region (memsz - filesz bytes).
//!        - Map each page into the process CR3/SATP via paging::map_page.
//!   3. Return entry point, brk, and PHDR metadata for auxv.

extern crate alloc;
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::paging;

const ELFMAG:     &[u8; 4] = b"\x7FELF";
const ELFCLASS64: u8  = 2;
const ET_EXEC:    u16 = 2;
const ET_DYN:     u16 = 3;
const EM_X86_64:  u16 = 62;
const EM_RISCV:   u16 = 243;
const PT_LOAD:    u32 = 1;
const PT_PHDR:    u32 = 6;
const PF_X:       u32 = 1;
const PF_W:       u32 = 2;
const PF_R:       u32 = 4;

const PAGE: usize = 4096;

#[repr(C)]
struct Elf64Ehdr {
    e_ident:     [u8; 16],
    e_type:      u16,
    e_machine:   u16,
    e_version:   u32,
    e_entry:     u64,
    e_phoff:     u64,
    e_shoff:     u64,
    e_flags:     u32,
    e_ehsize:    u16,
    e_phentsize: u16,
    e_phnum:     u16,
    e_shentsize: u16,
    e_shnum:     u16,
    e_shstrndx:  u16,
}

#[repr(C)]
struct Elf64Phdr {
    p_type:   u32,
    p_flags:  u32,
    p_offset: u64,
    p_vaddr:  u64,
    p_paddr:  u64,
    p_filesz: u64,
    p_memsz:  u64,
    p_align:  u64,
}

pub struct LoadedElf {
    pub entry:      usize,
    pub brk:        usize,
    pub is_dyn:     bool,
    pub base:       usize,
    pub pages:      Vec<usize>,
    pub phdr_va:    usize,
    pub phdr_count: usize,
    pub phdr_size:  usize,
}

pub fn load(image: &[u8], cr3: usize) -> Option<LoadedElf> {
    if image.len() < core::mem::size_of::<Elf64Ehdr>() { return None; }

    let ehdr = unsafe { &*(image.as_ptr() as *const Elf64Ehdr) };

    if &ehdr.e_ident[0..4] != ELFMAG.as_slice() { return None; }
    if ehdr.e_ident[4] != ELFCLASS64             { return None; }

    #[cfg(target_arch = "x86_64")]
    if ehdr.e_machine != EM_X86_64 { return None; }
    #[cfg(target_arch = "riscv64")]
    if ehdr.e_machine != EM_RISCV  { return None; }

    let is_dyn = match ehdr.e_type {
        t if t == ET_EXEC => false,
        t if t == ET_DYN  => true,
        _ => return None,
    };

    const ASLR_BASE:  usize = 0x0000_1000_0000_0000;
    const ASLR_RANGE: usize = 0x0000_6000_0000_0000;
    const ALIGN_2MB:  usize = 2 * 1024 * 1024;
    let bias = if is_dyn {
        let rand_off = (crate::rand::next_u64() as usize) % (ASLR_RANGE / ALIGN_2MB);
        ASLR_BASE + rand_off * ALIGN_2MB
    } else {
        0
    };

    let phoff   = ehdr.e_phoff    as usize;
    let phnum   = ehdr.e_phnum    as usize;
    let phentsz = ehdr.e_phentsize as usize;
    let entry   = ehdr.e_entry as usize + bias;

    if phoff + phnum * phentsz > image.len() { return None; }

    let mut pages: Vec<usize> = Vec::new();
    let mut brk: usize = 0;
    let mut phdr_va: usize = 0;
    let mut first_load_vaddr_base: Option<usize> = None;

    for i in 0..phnum {
        let ph = unsafe {
            &*((image.as_ptr() as usize + phoff + i * phentsz) as *const Elf64Phdr)
        };

        if ph.p_type == PT_PHDR {
            phdr_va = ph.p_vaddr as usize + bias;
        }

        if ph.p_type != PT_LOAD { continue; }

        let vaddr  = ph.p_vaddr  as usize + bias;
        let filesz = ph.p_filesz as usize;
        let memsz  = ph.p_memsz  as usize;
        let offset = ph.p_offset as usize;
        let flags  = ph.p_flags;

        if first_load_vaddr_base.is_none() {
            first_load_vaddr_base = Some(vaddr.wrapping_sub(offset));
        }

        if filesz > image.len() || offset + filesz > image.len() { return None; }
        if memsz == 0 { continue; }

        let vpage_start = vaddr & !(PAGE - 1);
        let vpage_end   = (vaddr + memsz + PAGE - 1) & !(PAGE - 1);
        let file_end    = vaddr + filesz;

        let mut va = vpage_start;
        while va < vpage_end {
            let pa = match crate::mm::pmm::alloc_page() {
                Some(p) => p,
                None    => return None,
            };
            pages.push(pa);
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }

            let pg_file_start = va.max(vaddr);
            let pg_file_end   = (va + PAGE).min(file_end);
            if pg_file_start < pg_file_end {
                let src_off  = offset + (pg_file_start - vaddr);
                let dst_off  = pg_file_start - va;
                let copy_len = pg_file_end - pg_file_start;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        image.as_ptr().add(src_off),
                        (pa + dst_off) as *mut u8,
                        copy_len,
                    );
                }
            }

            map_page_arch(cr3, va, pa, flags);
            va += PAGE;
        }

        let seg_top = vaddr + memsz;
        if seg_top > brk { brk = seg_top; }
    }

    if phdr_va == 0 && phoff != 0 {
        phdr_va = first_load_vaddr_base
            .and_then(|base| base.checked_add(phoff))
            .unwrap_or(0);
    }

    brk = (brk + PAGE - 1) & !(PAGE - 1);

    Some(LoadedElf {
        entry,
        brk,
        is_dyn,
        base: bias,
        pages,
        phdr_va,
        phdr_count: phnum,
        phdr_size:  phentsz,
    })
}

#[cfg(target_arch = "x86_64")]
fn map_page_arch(cr3: usize, va: usize, pa: usize, flags: u32) {
    let mut pte: u64 = paging::PTE_PRESENT | paging::PTE_USER;
    if flags & PF_W != 0 { pte |= paging::PTE_WRITABLE; }
    if flags & PF_X == 0 { pte |= paging::PTE_NX; }
    unsafe { paging::map_page(cr3, va, pa, pte); }
}

#[cfg(target_arch = "riscv64")]
fn map_page_arch(satp_ppn: usize, va: usize, pa: usize, flags: u32) {
    use crate::arch::riscv64::paging as rv_paging;
    let mut pte_flags = rv_paging::PTE_V | rv_paging::PTE_U | rv_paging::PTE_R;
    if flags & PF_W != 0 { pte_flags |= rv_paging::PTE_W; }
    if flags & PF_X != 0 { pte_flags |= rv_paging::PTE_X; }
    unsafe { rv_paging::map_page(satp_ppn, va, pa, pte_flags); }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
fn map_page_arch(_cr3: usize, _va: usize, _pa: usize, _flags: u32) {
    unimplemented!("map_page_arch not implemented for this architecture");
}
