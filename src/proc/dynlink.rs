//! PT_INTERP ELF dynamic-linker stub.
//!
//! ## What this enables
//!   Dynamically linked ELF binaries embed a PT_INTERP segment whose content
//!   is the path to the dynamic linker (e.g. "/lib/ld-musl-x86_64.so.1").
//!   Without this, execve() rejects every dynamic binary with ENOEXEC.
//!   With it, execve() notices PT_INTERP, loads the interpreter from the
//!   VFS, maps it at its preferred address, and hands control to it.
//!   The interpreter then maps the main binary's PT_LOAD segments and
//!   resolves symbols.
//!
//! ## How it works
//!   1. elf_load() (elf.rs) returns the PT_INTERP path alongside entry/base.
//!   2. load_interp() maps the interpreter ELF into user space.
//!   3. build_auxv() writes the auxiliary vector on the user stack.
//!   4. Control transfers to the interpreter's e_entry.
//!
//! ## Auxiliary vector entries written
//!   AT_PHDR(3) AT_PHENT(4) AT_PHNUM(5) AT_PAGESZ(6) AT_BASE(7)
//!   AT_FLAGS(8) AT_ENTRY(9) AT_UID(11) AT_EUID(12) AT_GID(13)
//!   AT_EGID(14) AT_SECURE(23) AT_RANDOM(25) AT_NULL(0)

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::uaccess::copy_to_user;

/// Result from parsing an ELF that has PT_INTERP.
pub struct DynExecInfo {
    pub interp_path:  String,
    pub interp_base:  usize,
    pub interp_entry: usize,
    pub main_phdr:    usize,
    pub main_phent:   usize,
    pub main_phnum:   usize,
    pub main_entry:   usize,
}

/// Try to find PT_INTERP in a mapped ELF binary.
pub fn find_interp(elf_va: usize) -> Option<String> {
    let ident = unsafe { core::slice::from_raw_parts(elf_va as *const u8, 64) };
    if &ident[0..4] != b"\x7FELF" { return None; }
    if ident[4] != 2 { return None; } // 64-bit only

    let e_phoff     = usize::from_le_bytes(unsafe { *(((elf_va + 32) as *const [u8;8])) });
    let e_phentsize = u16::from_le_bytes(unsafe  { *(((elf_va + 54) as *const [u8;2])) }) as usize;
    let e_phnum     = u16::from_le_bytes(unsafe  { *(((elf_va + 56) as *const [u8;2])) }) as usize;

    const PT_INTERP: u32 = 3;
    for i in 0..e_phnum {
        let phdr_va = elf_va + e_phoff + i * e_phentsize;
        let p_type  = u32::from_le_bytes(unsafe { *((phdr_va as *const [u8;4])) });
        if p_type == PT_INTERP {
            let p_offset = usize::from_le_bytes(unsafe { *(((phdr_va + 8)  as *const [u8;8])) });
            let p_filesz = usize::from_le_bytes(unsafe { *(((phdr_va + 32) as *const [u8;8])) });
            if p_filesz == 0 { return None; }
            let interp_bytes = unsafe {
                core::slice::from_raw_parts(
                    (elf_va + p_offset) as *const u8,
                    p_filesz.saturating_sub(1),
                )
            };
            return core::str::from_utf8(interp_bytes).ok().map(String::from);
        }
    }
    None
}

/// Load the ELF interpreter from the VFS and map it into user space.
/// Returns (interp_base, interp_entry) on success.
pub fn load_interp(interp_path: &str) -> Result<(usize, usize), isize> {
    let fd = match crate::fs::vfs::open(interp_path, crate::fs::vfs::O_RDONLY) {
        Ok(fd) => fd,
        Err(_) => return Err(-2),
    };
    let size = crate::fs::vfs::file_size(fd);
    if size == 0 { crate::fs::vfs::close(fd); return Err(-8); }
    let mut buf: Vec<u8> = alloc::vec![0u8; size];
    let n = crate::fs::vfs::read(fd, &mut buf);
    crate::fs::vfs::close(fd);
    if n < size as isize { return Err(-8); }
    let interp_base = map_elf_phdrs(&buf)?;
    let entry_off   = get_entry_point(&buf)?;
    Ok((interp_base, interp_base + entry_off))
}

/// Build the ELF auxiliary vector on the user stack.
/// Serialises the entire auxv block into a kernel buffer first, then
/// writes it to user space in a single copy_to_user call.
/// Returns the new user stack pointer, or 0 on EFAULT.
pub fn build_auxv(
    stack_top: usize,
    info: &DynExecInfo,
    random_bytes: [u8; 16],
) -> usize {
    let auxv: &[(u64, u64)] = &[
        (3,  info.main_phdr   as u64),
        (4,  info.main_phent  as u64),
        (5,  info.main_phnum  as u64),
        (6,  4096),
        (7,  info.interp_base as u64),
        (8,  0),
        (9,  info.main_entry  as u64),
        (11, 0), (12, 0), (13, 0), (14, 0),
        (23, 0),
        // AT_RANDOM: pointer to 16 random bytes — written just below auxv.
        // We compute the VA first, then append the bytes after the pairs.
        (25, 0), // placeholder; patched below
        (0,  0), // AT_NULL
    ];

    // Layout (stack grows down):
    //   [16 random bytes]  <- random_va
    //   [auxv pairs]       <- sp
    let auxv_sz    = auxv.len() * 16;
    let total_sz   = auxv_sz + 16;
    let sp         = stack_top - total_sz;
    let random_va  = sp + auxv_sz;   // random bytes sit above (higher addr) the auxv

    // Serialise into a kernel-side buffer.
    let mut kbuf: Vec<u8> = alloc::vec![0u8; total_sz];
    for (i, (t, v)) in auxv.iter().enumerate() {
        let off = i * 16;
        // Patch AT_RANDOM value with the actual VA.
        let val = if *t == 25 { random_va as u64 } else { *v };
        kbuf[off..off+8].copy_from_slice(&t.to_le_bytes());
        kbuf[off+8..off+16].copy_from_slice(&val.to_le_bytes());
    }
    // Append the 16 random bytes at the end of the buffer.
    kbuf[auxv_sz..auxv_sz+16].copy_from_slice(&random_bytes);

    // Single validated write to user space.
    if copy_to_user(sp, &kbuf).is_err() {
        return 0; // EFAULT — execve caller should propagate -EFAULT
    }
    sp
}

// ── ELF mapping helpers ────────────────────────────────────────────────────────

fn map_elf_phdrs(elf: &[u8]) -> Result<usize, isize> {
    if elf.len() < 64 { return Err(-8); }
    if &elf[0..4] != b"\x7FELF" { return Err(-8); }

    let e_type      = u16::from_le_bytes([elf[16], elf[17]]);
    let e_phoff     = usize::from_le_bytes(elf[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes([elf[54], elf[55]]) as usize;
    let e_phnum     = u16::from_le_bytes([elf[56], elf[57]]) as usize;

    const INTERP_LOAD_BASE: usize = 0x0000_7F00_0000_0000;
    let bias: usize = if e_type == 3 { INTERP_LOAD_BASE } else { 0 };

    const PT_LOAD: u32 = 1;
    const PAGE:    usize = 4096;

    let pid = crate::proc::scheduler::current_pid();
    let cr3 = crate::proc::scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.user_satp)
    });
    if cr3 == 0 { return Err(-12); }

    for i in 0..e_phnum {
        let base = e_phoff + i * e_phentsize;
        if base + e_phentsize > elf.len() { break; }
        let p_type = u32::from_le_bytes(elf[base..base+4].try_into().unwrap());
        if p_type != PT_LOAD { continue; }

        let p_offset = usize::from_le_bytes(elf[base+8 ..base+16].try_into().unwrap());
        let p_vaddr  = usize::from_le_bytes(elf[base+16..base+24].try_into().unwrap());
        let p_filesz = usize::from_le_bytes(elf[base+32..base+40].try_into().unwrap());
        let p_memsz  = usize::from_le_bytes(elf[base+40..base+48].try_into().unwrap());
        let p_flags  = u32::from_le_bytes(elf[base+4 ..base+8 ].try_into().unwrap());

        let load_va  = (p_vaddr + bias) & !(PAGE - 1);
        let pages    = (p_memsz + PAGE - 1) / PAGE;
        let writable = p_flags & 2 != 0;
        let exec     = p_flags & 1 != 0;

        let pte_flags = {
            let mut f = PageFlags::PRESENT | PageFlags::USER;
            if writable { f |= PageFlags::WRITE; }
            if !exec    { f |= PageFlags::NX; }
            f
        };

        for pg in 0..pages {
            if let Some(pa) = crate::mm::pmm::alloc_page() {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                <Arch as Paging>::map_page(cr3, load_va + pg * PAGE, pa, pte_flags);
            }
        }

        if p_filesz > 0 {
            let end = (p_offset + p_filesz).min(elf.len());
            let src = &elf[p_offset..end];
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
