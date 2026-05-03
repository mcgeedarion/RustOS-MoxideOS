//! PT_INTERP ELF dynamic-linker stub.
//!
//! ## What this enables
//!   Dynamically linked ELF binaries (the vast majority of real Linux
//!   programs) embed a PT_INTERP segment whose content is the path to the
//!   dynamic linker, usually "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
//!   or "/lib/ld-musl-x86_64.so.1".
//!
//!   Without this, execve() rejects every dynamic binary with ENOEXEC.
//!   With it, execve() notices PT_INTERP, loads the interpreter from the
//!   VFS, maps it at its preferred address, and hands control to it.
//!   The interpreter then maps the main binary's PT_LOAD segments itself
//!   and resolves symbols.
//!
//! ## How it works
//!   1. elf_load() (in elf.rs) is extended to return the PT_INTERP path
//!      alongside the entry point and base address.
//!   2. If an interp path is present, load_interp() maps the interpreter
//!      ELF into user space at its p_vaddr (or a fixed offset if ET_DYN).
//!   3. The kernel sets up the auxiliary vector (auxv) on the user stack
//!      so the interpreter knows where the main binary is, the page size,
//!      the vDSO, etc.
//!   4. Control is transferred to the interpreter's e_entry, not the
//!      main binary's e_entry — the interpreter does the rest.
//!
//! ## Auxiliary vector entries written
//!   AT_PHDR    (3)  — program header table VA in loaded binary
//!   AT_PHENT   (4)  — size of one Phdr
//!   AT_PHNUM   (5)  — number of Phdrs
//!   AT_PAGESZ  (6)  — 4096
//!   AT_BASE    (7)  — load address of interpreter
//!   AT_FLAGS   (8)  — 0
//!   AT_ENTRY   (9)  — entry point of the main binary
//!   AT_UID    (11)  — 0
//!   AT_EUID   (12)  — 0
//!   AT_GID    (13)  — 0
//!   AT_EGID   (14)  — 0
//!   AT_SECURE (23)  — 0
//!   AT_RANDOM (25)  — pointer to 16 random bytes on stack
//!   AT_NULL    (0)  — terminator

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// Result from parsing an ELF that has PT_INTERP.
pub struct DynExecInfo {
    /// Path of the interpreter (e.g. "/lib/ld-musl-x86_64.so.1").
    pub interp_path: String,
    /// Load address of the interpreter in user VA space.
    pub interp_base: usize,
    /// Entry point of the interpreter.
    pub interp_entry: usize,
    /// VA of the main binary's program header table.
    pub main_phdr: usize,
    /// Size of one program header entry.
    pub main_phent: usize,
    /// Number of program headers.
    pub main_phnum: usize,
    /// Entry point of the main binary (handed to interpreter via AT_ENTRY).
    pub main_entry: usize,
}

/// Try to find PT_INTERP in a mapped ELF binary.
/// `elf_va` is the VA where the ELF is currently mapped (it must already
/// have been loaded by the static ELF loader for header inspection).
/// Returns None if there is no PT_INTERP segment.
pub fn find_interp(elf_va: usize) -> Option<String> {
    // Read ELF header.
    let ident = unsafe { core::slice::from_raw_parts(elf_va as *const u8, 64) };
    if &ident[0..4] != b"\x7FELF" { return None; }
    let is64 = ident[4] == 2;
    if !is64 { return None; } // 32-bit not supported yet

    let e_phoff  = usize::from_le_bytes(unsafe {
        *(((elf_va + 32) as *const [u8;8]))
    });
    let e_phentsize = u16::from_le_bytes(unsafe {
        *(((elf_va + 54) as *const [u8;2]))
    }) as usize;
    let e_phnum = u16::from_le_bytes(unsafe {
        *(((elf_va + 56) as *const [u8;2]))
    }) as usize;

    const PT_INTERP: u32 = 3;
    for i in 0..e_phnum {
        let phdr_va = elf_va + e_phoff + i * e_phentsize;
        let p_type  = u32::from_le_bytes(unsafe { *((phdr_va as *const [u8;4])) });
        if p_type == PT_INTERP {
            let p_offset = usize::from_le_bytes(unsafe {
                *(((phdr_va + 8) as *const [u8;8]))
            });
            let p_filesz = usize::from_le_bytes(unsafe {
                *(((phdr_va + 32) as *const [u8;8]))
            });
            if p_filesz == 0 { return None; }
            let interp_bytes = unsafe {
                core::slice::from_raw_parts((elf_va + p_offset) as *const u8,
                                           p_filesz.saturating_sub(1)) // strip NUL
            };
            return core::str::from_utf8(interp_bytes).ok()
                .map(String::from);
        }
    }
    None
}

/// Load the ELF interpreter from the VFS and map it into user space.
/// Returns (interp_base, interp_entry) on success.
pub fn load_interp(interp_path: &str) -> Result<(usize, usize), isize> {
    let flags = crate::fs::vfs::O_RDONLY;
    let fd = match crate::fs::vfs::open(interp_path, flags) {
        Ok(fd) => fd,
        Err(_) => return Err(-2), // ENOENT
    };

    // Read the whole interpreter into a heap buffer.
    let size = crate::fs::vfs::file_size(fd);
    if size == 0 { crate::fs::vfs::close(fd); return Err(-8); } // ENOEXEC
    let mut buf: Vec<u8> = alloc::vec![0u8; size];
    let n = crate::fs::vfs::read(fd, &mut buf);
    crate::fs::vfs::close(fd);
    if n < size as isize { return Err(-8); }

    // Parse and map PT_LOAD segments.
    let interp_base = map_elf_phdrs(&buf)?;
    let entry_off = get_entry_point(&buf)?;
    Ok((interp_base, interp_base + entry_off))
}

/// Build the ELF auxiliary vector on the user stack.
/// `stack_top` is the current user stack pointer (grows down).
/// Returns the new stack pointer after pushing argc/argv/envp/auxv.
pub fn build_auxv(
    stack_top: usize,
    info: &DynExecInfo,
    random_bytes: [u8; 16],
) -> usize {
    // We push auxv as pairs of (u64 type, u64 value), terminated by AT_NULL.
    // Stack layout (low → high):
    //   [random 16 bytes]
    //   [auxv pairs…]
    //   [NULL envp terminator]
    //   [NULL argv terminator]
    //   [argc = 0]
    // (argc/argv/envp are filled by the execve caller; we only do auxv here.)

    let mut sp = stack_top;

    // Place 16 random bytes for AT_RANDOM.
    sp -= 16;
    unsafe { core::ptr::copy_nonoverlapping(random_bytes.as_ptr(), sp as *mut u8, 16); }
    let random_va = sp;

    // Build auxv table.
    let auxv: &[(u64, u64)] = &[
        (3,  info.main_phdr   as u64),   // AT_PHDR
        (4,  info.main_phent  as u64),   // AT_PHENT
        (5,  info.main_phnum  as u64),   // AT_PHNUM
        (6,  4096),                       // AT_PAGESZ
        (7,  info.interp_base as u64),   // AT_BASE
        (8,  0),                          // AT_FLAGS
        (9,  info.main_entry  as u64),   // AT_ENTRY
        (11, 0), (12, 0), (13, 0), (14, 0), // AT_UID/EUID/GID/EGID = 0 (root)
        (23, 0),                          // AT_SECURE
        (25, random_va        as u64),   // AT_RANDOM
        (0,  0),                          // AT_NULL
    ];

    let auxv_bytes = auxv.len() * 16;
    sp -= auxv_bytes;
    for (i, (t, v)) in auxv.iter().enumerate() {
        unsafe {
            ((sp + i * 16)     as *mut u64).write_unaligned(*t);
            ((sp + i * 16 + 8) as *mut u64).write_unaligned(*v);
        }
    }

    sp
}

// ─── ELF mapping helpers ──────────────────────────────────────────────────────

/// Map PT_LOAD segments of an ELF image (given as a byte slice) into user
/// space.  Returns the load bias (base address) for ET_DYN, or 0 for ET_EXEC.
fn map_elf_phdrs(elf: &[u8]) -> Result<usize, isize> {
    if elf.len() < 64 { return Err(-8); }
    if &elf[0..4] != b"\x7FELF" { return Err(-8); }

    let e_type     = u16::from_le_bytes([elf[16], elf[17]]);
    let e_phoff    = usize::from_le_bytes(elf[32..40].try_into().unwrap());
    let e_phentsize= u16::from_le_bytes([elf[54], elf[55]]) as usize;
    let e_phnum    = u16::from_le_bytes([elf[56], elf[57]]) as usize;

    // For ET_DYN, pick a load base that doesn't clash with the main binary.
    // We use a fixed offset in the upper half of user space.
    const INTERP_LOAD_BASE: usize = 0x0000_7F00_0000_0000;
    let bias: usize = if e_type == 3 { INTERP_LOAD_BASE } else { 0 }; // ET_DYN=3

    const PT_LOAD: u32 = 1;
    let pid = crate::proc::scheduler::current_pid() as u32;
    let cr3 = crate::arch::x86_64::paging::current_cr3();
    const PAGE: usize = 4096;
    const PTE_PRESENT:  usize = 1;
    const PTE_WRITABLE: usize = 2;
    const PTE_USER:     usize = 4;

    for i in 0..e_phnum {
        let base = e_phoff + i * e_phentsize;
        if base + e_phentsize > elf.len() { break; }
        let p_type   = u32::from_le_bytes(elf[base..base+4].try_into().unwrap());
        if p_type != PT_LOAD { continue; }
        let p_offset = usize::from_le_bytes(elf[base+8 ..base+16].try_into().unwrap());
        let p_vaddr  = usize::from_le_bytes(elf[base+16..base+24].try_into().unwrap());
        let p_filesz = usize::from_le_bytes(elf[base+32..base+40].try_into().unwrap());
        let p_memsz  = usize::from_le_bytes(elf[base+40..base+48].try_into().unwrap());
        let p_flags  = u32::from_le_bytes(elf[base+4 ..base+8 ].try_into().unwrap());

        let load_va = (p_vaddr + bias) & !(PAGE - 1);
        let pages   = (p_memsz + PAGE - 1) / PAGE;
        let writable = p_flags & 2 != 0;

        for pg in 0..pages {
            let va = load_va + pg * PAGE;
            if let Some(pa) = crate::mm::pmm::alloc_page() {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                let pte_flags = PTE_PRESENT | PTE_USER
                    | if writable { PTE_WRITABLE } else { 0 };
                crate::arch::x86_64::paging::map_page(cr3, va, pa, pte_flags);
            }
        }

        // Copy file data.
        if p_filesz > 0 {
            let src = &elf[p_offset..p_offset + p_filesz.min(elf.len() - p_offset)];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    (p_vaddr + bias) as *mut u8,
                    src.len(),
                );
            }
        }

        crate::mm::mmap::insert_vma(pid, crate::mm::mmap::Vma {
            start: load_va,
            end:   load_va + pages * PAGE,
            prot:  p_flags & 7,
            flags: if bias != 0 { 0x22 } else { 0x02 },
            kind:  crate::mm::mmap::VmaKind::FileBacked(0, p_offset as u64),
            file_offset: p_offset as u64,
        });
    }

    Ok(bias)
}

fn get_entry_point(elf: &[u8]) -> Result<usize, isize> {
    if elf.len() < 64 { return Err(-8); }
    Ok(usize::from_le_bytes(elf[24..32].try_into().unwrap()))
}
