//! 64-bit ELF loader.
//!
//! Parses an ELF64 executable and maps its PT_LOAD segments into a new
//! address space.  Called by proc::exec::sys_execve.
//!
//! ## What this does
//!   1. Validate ELF header (magic, class=64, type=EXEC or DYN, machine=x86_64).
//!   2. Walk PT_LOAD program headers:
//!        - Allocate physical pages via pmm::alloc_page.
//!        - Copy file data (filesz bytes).
//!        - Zero-fill the BSS region (memsz - filesz bytes).
//!        - Map each page into the process CR3 via paging::map_page.
//!   3. Return the ELF entry point and the highest mapped address (for brk init).
//!
//! ## Flags → PTE bits
//!   PF_R (4) → Present
//!   PF_W (2) → Writable
//!   PF_X (1) → !NX
//!
//! ## Limitation
//!   INTERP (dynamic linker) segments are not yet handled — static binaries only.
//!   A future pass can check for PT_INTERP and re-enter load() on the ld.so image.

extern crate alloc;
use alloc::vec::Vec;
use crate::mm::pmm;
use crate::arch::x86_64::paging;

// ── ELF64 constants ───────────────────────────────────────────────────────

const ELFMAG:    &[u8; 4] = b"\x7FELF";
const ELFCLASS64: u8 = 2;
const ET_EXEC:   u16 = 2;
const ET_DYN:    u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD:   u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X:      u32 = 1;
const PF_W:      u32 = 2;
const PF_R:      u32 = 4;

const PAGE: usize = 4096;

// ── ELF header ────────────────────────────────────────────────────────────

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

// ── Program header ────────────────────────────────────────────────────────

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

// ── Public result type ────────────────────────────────────────────────────

pub struct LoadedElf {
    pub entry:   usize,   // ELF entry point VA
    pub brk:     usize,   // initial brk = top of highest PT_LOAD segment
    pub is_dyn:  bool,    // true if ET_DYN (PIE)
    pub base:    usize,   // load bias (0 for ET_EXEC, LOAD_BASE for ET_DYN)
    pub pages:   Vec<usize>, // physical pages allocated (for owned_pages in PCB)
}

/// Parse and load an ELF64 image into the address space described by `cr3`.
/// Returns `None` if the image is invalid or memory allocation fails.
pub fn load(image: &[u8], cr3: usize) -> Option<LoadedElf> {
    if image.len() < core::mem::size_of::<Elf64Ehdr>() { return None; }

    // Safety: image is &[u8] so any alignment is fine for pointer cast.
    let ehdr = unsafe { &*(image.as_ptr() as *const Elf64Ehdr) };

    // Validate header.
    if &ehdr.e_ident[0..4] != ELFMAG.as_slice() { return None; }
    if ehdr.e_ident[4] != ELFCLASS64              { return None; }
    if ehdr.e_machine != EM_X86_64               { return None; }
    let is_dyn = match ehdr.e_type {
        t if t == ET_EXEC => false,
        t if t == ET_DYN  => true,
        _ => return None,
    };

    // For PIE (ET_DYN), choose a randomised load bias within the lower half
    // of user space.  We align to 2 MiB so huge-page mappings remain valid.
    // Bias range: [0x0000_1000_0000_0000, 0x0000_7000_0000_0000) in 2 MiB steps.
    const ASLR_BASE:  usize = 0x0000_1000_0000_0000;
    const ASLR_RANGE: usize = 0x0000_6000_0000_0000;
    const ALIGN_2MB:  usize = 2 * 1024 * 1024;
    let bias = if is_dyn {
        let rand_off = (crate::rand::next_u64() as usize) % (ASLR_RANGE / ALIGN_2MB);
        ASLR_BASE + rand_off * ALIGN_2MB
    } else {
        0
    };

    let phoff    = ehdr.e_phoff as usize;
    let phnum    = ehdr.e_phnum as usize;
    let phentsz  = ehdr.e_phentsize as usize;
    let entry    = ehdr.e_entry as usize + bias;

    if phoff + phnum * phentsz > image.len() { return None; }

    let mut pages: Vec<usize> = Vec::new();
    let mut brk: usize = 0;

    // Walk program headers.
    for i in 0..phnum {
        let ph_ptr = unsafe {
            &*((image.as_ptr() as usize + phoff + i * phentsz) as *const Elf64Phdr)
        };
        if ph_ptr.p_type != PT_LOAD { continue; }

        let vaddr   = ph_ptr.p_vaddr as usize + bias;
        let filesz  = ph_ptr.p_filesz as usize;
        let memsz   = ph_ptr.p_memsz  as usize;
        let offset  = ph_ptr.p_offset as usize;
        let flags   = ph_ptr.p_flags;

        if filesz > image.len() || offset + filesz > image.len() { return None; }
        if memsz == 0 { continue; }

        // PTE flags: Present always, Writable if PF_W, NX if !PF_X, User.
        let pte_flags: u64 = {
            let mut f: u64 = paging::PTE_PRESENT | paging::PTE_USER;
            if flags & PF_W != 0 { f |= paging::PTE_WRITABLE; }
            if flags & PF_X == 0 { f |= paging::PTE_NX; }
            f
        };

        // Map pages for [vaddr, vaddr + memsz).
        let vpage_start = vaddr & !(PAGE - 1);
        let vpage_end   = (vaddr + memsz + PAGE - 1) & !(PAGE - 1);

        // File data byte range within the segment.
        let file_start  = vaddr;        // first byte of file data
        let file_end    = vaddr + filesz;

        let mut va = vpage_start;
        while va < vpage_end {
            let pa = match pmm::alloc_page() {
                Some(p) => p,
                None    => return None,
            };
            pages.push(pa);

            // Zero the page.
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }

            // Copy file data that falls within this page.
            let pg_file_start = va.max(file_start);
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

            // Map page into address space.
            unsafe { paging::map_page(cr3, va, pa, pte_flags); }

            va += PAGE;
        }

        let seg_top = vaddr + memsz;
        if seg_top > brk { brk = seg_top; }
    }

    // Round brk up to page boundary.
    brk = (brk + PAGE - 1) & !(PAGE - 1);

    Some(LoadedElf { entry, brk, is_dyn, base: bias, pages })
}
