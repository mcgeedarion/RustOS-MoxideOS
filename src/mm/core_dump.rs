//! Minimal ELF core dump writer.
//!
//! ## Overview
//!
//! When a process terminates due to a fatal signal (SIGSEGV, SIGABRT, SIGBUS,
//! SIGFPE, SIGILL, SIGQUIT, SIGSYS, SIGTRAP, SIGXCPU, SIGXFSZ) the kernel
//! should write a core file if:
//!
//!   1. `RLIMIT_CORE` soft limit > 0 (or is `RLIM_INFINITY`).
//!   2. The process's `exe_path` is known (so we can name the file).
//!
//! The file is written to the process's current working directory as `core`.
//!
//! ## Format
//!
//! We emit a minimal ELF64 core file containing:
//!   - ELF header
//!   - One `PT_NOTE` segment with `NT_PRSTATUS` and `NT_PRPSINFO` notes.
//!   - One `PT_LOAD` segment per readable VMA (data follows the headers).
//!
//! The note format follows the Linux `elf_prstatus` / `elf_prpsinfo` layout
//! so that `gdb` and `lldb` can open the resulting file.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

use crate::proc::rlimit::{RLIMIT_CORE, RLIM_INFINITY};
use crate::proc::scheduler::{current_pid, with_proc};

// ── ELF constants (64-bit) ────────────────────────────────────────────────────

const ELFMAG:     [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64:  u8     = 2;
const ELFDATA2LSB: u8     = 1;
const ET_CORE:     u16    = 4;
const PT_LOAD:     u32    = 1;
const PT_NOTE:     u32    = 4;
const PF_R:        u32    = 4;
const PF_W:        u32    = 2;
const PF_X:        u32    = 1;

/// ELF machine type — selected at compile time so the core file is accepted
/// by gdb/lldb on both x86-64 and RISC-V targets.
#[cfg(target_arch = "x86_64")]
const EM_MACHINE: u16 = 62;  // EM_X86_64
#[cfg(target_arch = "riscv64")]
const EM_MACHINE: u16 = 243; // EM_RISCV
#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
const EM_MACHINE: u16 = 0;   // EM_NONE — unsupported arch

// ── Note type numbers ────────────────────────────────────────────────────────

const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;

// ── Serialisation helpers ─────────────────────────────────────────────────────

fn push_u16(buf: &mut Vec<u8>, v: u16) { buf.extend_from_slice(&v.to_le_bytes()); }
fn push_u32(buf: &mut Vec<u8>, v: u32) { buf.extend_from_slice(&v.to_le_bytes()); }
fn push_u64(buf: &mut Vec<u8>, v: u64) { buf.extend_from_slice(&v.to_le_bytes()); }
fn push_zeros(buf: &mut Vec<u8>, n: usize) { buf.resize(buf.len() + n, 0); }
fn align4(n: usize) -> usize { (n + 3) & !3 }

// ── ELF Ehdr ─────────────────────────────────────────────────────────────────

fn write_elf_header(buf: &mut Vec<u8>, phnum: u16) {
    buf.extend_from_slice(&ELFMAG);
    buf.push(ELFCLASS64);    // EI_CLASS
    buf.push(ELFDATA2LSB);   // EI_DATA
    buf.push(1);             // EI_VERSION = EV_CURRENT
    buf.push(0);             // EI_OSABI = ELFOSABI_NONE
    push_zeros(buf, 8);      // EI_ABIVERSION + padding
    push_u16(buf, ET_CORE);  // e_type
    push_u16(buf, EM_MACHINE); // e_machine — arch-selected above
    push_u32(buf, 1);        // e_version
    push_u64(buf, 0);        // e_entry
    push_u64(buf, 64);       // e_phoff — phdrs start right after ehdr
    push_u64(buf, 0);        // e_shoff
    push_u32(buf, 0);        // e_flags
    push_u16(buf, 64);       // e_ehsize
    push_u16(buf, 56);       // e_phentsize
    push_u16(buf, phnum);    // e_phnum
    push_u16(buf, 64);       // e_shentsize
    push_u16(buf, 0);        // e_shnum
    push_u16(buf, 0);        // e_shstrndx
    // total: 64 bytes
}

// ── ELF Phdr ─────────────────────────────────────────────────────────────────

fn write_phdr(
    buf: &mut Vec<u8>,
    p_type:   u32,
    p_flags:  u32,
    p_offset: u64,
    p_vaddr:  u64,
    p_filesz: u64,
    p_memsz:  u64,
    p_align:  u64,
) {
    push_u32(buf, p_type);
    push_u32(buf, p_flags);
    push_u64(buf, p_offset);
    push_u64(buf, p_vaddr);
    push_u64(buf, 0);        // p_paddr (irrelevant for core)
    push_u64(buf, p_filesz);
    push_u64(buf, p_memsz);
    push_u64(buf, p_align);
    // total: 56 bytes
}

// ── ELF Note ──────────────────────────────────────────────────────────────────
//
// Linux note layout (per elf(5)):
//   u32  namesz  — length of name[] INCLUDING the NUL terminator
//   u32  descsz  — length of desc[] in bytes (no padding counted)
//   u32  type
//   char name[]  — padded to 4-byte boundary
//   char desc[]  — padded to 4-byte boundary

fn write_note(buf: &mut Vec<u8>, name: &[u8], typ: u32, desc: &[u8]) {
    // `name` must already include a NUL terminator (e.g. b"CORE\0").
    // namesz = name.len() (includes NUL); descsz = desc.len() (raw bytes only).
    let namesz = name.len() as u32;
    let descsz = desc.len() as u32;
    push_u32(buf, namesz);
    push_u32(buf, descsz);
    push_u32(buf, typ);
    buf.extend_from_slice(name);
    push_zeros(buf, align4(name.len()) - name.len()); // pad name to 4B boundary
    buf.extend_from_slice(desc);
    push_zeros(buf, align4(desc.len()) - desc.len()); // pad desc to 4B boundary
}

// ── NT_PRSTATUS ───────────────────────────────────────────────────────────────

fn prstatus_note(pid: usize, signo: u32) -> Vec<u8> {
    let mut n = Vec::with_capacity(148);
    push_u32(&mut n, signo);         // pr_info.si_signo
    push_u32(&mut n, 0);             // pr_info.si_code
    push_u32(&mut n, 0);             // pr_info.si_errno
    push_u16(&mut n, signo as u16);  // pr_cursig
    push_u16(&mut n, 0);             // pad
    push_u64(&mut n, 0);             // pr_sigpend
    push_u64(&mut n, 0);             // pr_sighold
    push_u32(&mut n, pid as u32);    // pr_pid
    push_u32(&mut n, 0);             // pr_ppid
    push_u32(&mut n, 0);             // pr_pgrp
    push_u32(&mut n, 0);             // pr_sid
    // pr_utime, pr_stime, pr_cutime, pr_cstime: 4 × 16 bytes (timeval64)
    push_zeros(&mut n, 4 * 16);
    // pr_reg: 27 × 8 bytes (general-purpose registers, zeroed)
    push_zeros(&mut n, 27 * 8);
    push_u32(&mut n, 0);             // pr_fpvalid
    n
}

// ── NT_PRPSINFO ───────────────────────────────────────────────────────────────

fn prpsinfo_note(pid: usize, exe: &str) -> Vec<u8> {
    let mut n = Vec::with_capacity(124);
    n.push(0u8);   // pr_state
    n.push(b' ');  // pr_sname
    n.push(0u8);   // pr_zomb
    n.push(0u8);   // pr_nice
    push_u64(&mut n, 0);           // pr_flag
    push_u32(&mut n, 0);           // pr_uid
    push_u32(&mut n, 0);           // pr_gid
    push_u32(&mut n, pid as u32);  // pr_pid
    push_u32(&mut n, 0);           // pr_ppid
    push_u32(&mut n, 0);           // pr_pgrp
    push_u32(&mut n, 0);           // pr_sid
    // pr_fname: 16 bytes (basename, NUL-padded)
    let name_bytes = exe.as_bytes();
    let fname_len  = name_bytes.len().min(15);
    n.extend_from_slice(&name_bytes[..fname_len]);
    push_zeros(&mut n, 16 - fname_len);
    // pr_psargs: 80 bytes (argv string, NUL-padded)
    let args_len = name_bytes.len().min(79);
    n.extend_from_slice(&name_bytes[..args_len]);
    push_zeros(&mut n, 80 - args_len);
    n
}

// ── Safe page-by-page copy from user address space ───────────────────────────
//
// Reading VMA contents through raw user virtual addresses (the old approach)
// is unsafe: pages may be swapped out, CoW-frozen, or absent at dump time.
// A fault in kernel context would panic the kernel.
//
// Instead we copy one page at a time.  For each page we attempt the read; if
// it faults (indicated by copy_from_user_page returning false) we substitute
// PAGE_SIZE zero bytes.  This matches Linux's behaviour in fs/coredump.c.

const PAGE_SIZE: usize = 4096;

/// Copy `size` bytes from user VA `src_va` into `dst`, page by page.
/// Pages that cannot be read are filled with zeros.
fn copy_user_range(dst: &mut Vec<u8>, src_va: usize, size: usize) {
    let mut offset = 0usize;
    while offset < size {
        let page_va   = src_va + offset;
        let page_base = page_va & !0xFFF;
        let page_off  = page_va & 0xFFF;
        let copy_len  = PAGE_SIZE.min(size - offset).min(PAGE_SIZE - page_off);

        // Try to read one page through the architecture's safe-copy helper.
        // copy_from_user_page returns true on success, false on fault.
        let ok = unsafe {
            crate::mm::user_copy::copy_from_user_page(
                page_base,
                page_off,
                dst,
                copy_len,
            )
        };
        if !ok {
            // Page not readable (swapped, not present, etc.) — emit zeros.
            push_zeros(dst, copy_len);
        }
        offset += copy_len;
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Build an ELF core image for the current process and write it to the VFS.
///
/// `signo` is the signal that caused the dump.  Returns the number of bytes
/// written, or a negative errno.
///
/// Called from `signal.rs` fatal-signal delivery path.
pub fn write_core_dump(signo: u32) -> isize {
    let pid = current_pid();

    // ── Gate on RLIMIT_CORE ───────────────────────────────────────────────────
    let (soft, _) = with_proc(pid, |p| p.rlimits.get(RLIMIT_CORE))
        .unwrap_or((0, 0));
    if soft == 0 {
        return 0; // core dumps disabled
    }
    let max_bytes: u64 = if soft == RLIM_INFINITY { u64::MAX } else { soft };

    // ── Collect VMA snapshot ─────────────────────────────────────────────────
    struct VmaSnap { start: usize, end: usize, flags: u32 }
    let (vmas, exe_path): (Vec<VmaSnap>, String) = with_proc(pid, |p| {
        let snaps = p.vmas.iter().map(|v| VmaSnap {
            start: v.start,
            end:   v.end,
            flags: {
                let mut f = PF_R;
                if v.writable   { f |= PF_W; }
                if v.executable { f |= PF_X; }
                f
            },
        }).collect();
        let exe = p.exe_path.clone().unwrap_or_else(|| "unknown".into());
        (snaps, exe)
    }).unwrap_or_else(|| (Vec::new(), String::from("unknown")));

    // ── Build note segment ───────────────────────────────────────────────────
    let mut notes: Vec<u8> = Vec::new();
    write_note(&mut notes, b"CORE\0", NT_PRSTATUS, &prstatus_note(pid, signo));
    write_note(&mut notes, b"CORE\0", NT_PRPSINFO, &prpsinfo_note(pid, &exe_path));

    // ── Apply RLIMIT_CORE: drop trailing VMAs that would exceed the limit ─────
    //
    // Truncating the raw buffer mid-segment (the old approach) produces a
    // structurally invalid ELF.  Instead we compute the total size up-front
    // and drop whole VMAs from the end until the projected size fits within
    // max_bytes.  This preserves a valid ELF structure and matches what Linux
    // does (fs/coredump.c: dump_skip / dump_truncate logic).
    //
    // Header sizes:
    //   ELF ehdr:  64 bytes
    //   PT_NOTE phdr: 56 bytes  (1 always present)
    //   PT_LOAD phdr: 56 bytes × N  (one per included VMA)
    //   Note data: notes.len() bytes
    //   VMA data:  sum of (vma.end - vma.start) for included VMAs

    let ehdr_size   = 64usize;
    let phdr_size   = 56usize;
    let note_size   = notes.len();

    // Determine how many VMAs we can include within max_bytes.
    let mut included_vmas = 0usize;
    {
        // Fixed overhead: ehdr + PT_NOTE phdr + note data
        let fixed: u64 = (ehdr_size + phdr_size + note_size) as u64;
        let mut running = fixed;
        for vma in &vmas {
            let segment_bytes = (phdr_size + (vma.end - vma.start)) as u64;
            match running.checked_add(segment_bytes) {
                Some(new) if new <= max_bytes => {
                    running = new;
                    included_vmas += 1;
                }
                _ => break,
            }
        }
    }
    let vmas = &vmas[..included_vmas];

    // ── Layout calculation ───────────────────────────────────────────────────
    let phnum    = 1 + vmas.len(); // PT_NOTE + PT_LOAD × N
    let phdrs_end = ehdr_size + phdr_size * phnum;
    let note_off  = phdrs_end;
    let mut data_off = note_off + note_size;

    // ── Assemble ELF image ───────────────────────────────────────────────────
    let mut buf: Vec<u8> = Vec::new();

    // ELF header
    write_elf_header(&mut buf, phnum as u16);

    // PT_NOTE phdr
    write_phdr(&mut buf, PT_NOTE, 0,
        note_off as u64, 0, note_size as u64, note_size as u64, 4);

    // PT_LOAD phdrs
    for vma in vmas {
        let size = vma.end - vma.start;
        write_phdr(&mut buf, PT_LOAD, vma.flags,
            data_off as u64, vma.start as u64,
            size as u64, size as u64, 0x1000);
        data_off += size;
    }

    // Note data
    buf.extend_from_slice(&notes);

    // VMA data — copied safely through the fault-tolerant helper.
    // Unreadable pages (swapped out, CoW-frozen, not present) are zeroed
    // rather than causing a kernel panic from a fault in kernel context.
    for vma in vmas {
        let size = vma.end - vma.start;
        copy_user_range(&mut buf, vma.start, size);
    }

    // ── Write to VFS ─────────────────────────────────────────────────────────
    let core_path = with_proc(pid, |p| {
        let cwd = p.cwd().unwrap_or_else(|| "/".into());
        alloc::format!("{}/core", cwd)
    }).unwrap_or_else(|| "/core".into());

    match crate::fs::vfs_ops::vfs_write_bytes(&core_path, &buf) {
        Ok(_)  => buf.len() as isize,
        Err(e) => e,
    }
}

/// Returns `true` if the given signal should produce a core dump and
/// `RLIMIT_CORE` allows it.
pub fn should_dump(signo: u32) -> bool {
    // Signals that produce a core on Linux (see signal(7)):
    //   SIGQUIT(3), SIGILL(4), SIGTRAP(5), SIGABRT(6), SIGBUS(7),
    //   SIGFPE(8), SIGSEGV(11), SIGSYS(12/31), SIGXCPU(24), SIGXFSZ(25)
    const CORE_SIGS: &[u32] = &[3, 4, 5, 6, 7, 8, 11, 12, 24, 25, 31];
    if !CORE_SIGS.contains(&signo) { return false; }
    let pid = current_pid();
    let (soft, _) = with_proc(pid, |p| p.rlimits.get(RLIMIT_CORE))
        .unwrap_or((0, 0));
    soft != 0
}
