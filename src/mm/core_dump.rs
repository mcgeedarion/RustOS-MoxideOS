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
//! The file is written to the process's current working directory as `core`
//! (or `core.<pid>` — configurable via `/proc/sys/kernel/core_pattern` on
//! Linux; we always use `core` for simplicity).
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

const ELFMAG:   [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8    = 2;
const ELFDATA2LSB: u8   = 1;
const ET_CORE:  u16     = 4;
const EM_X86_64: u16    = 62;
const PT_LOAD:  u32     = 1;
const PT_NOTE:  u32     = 4;
const PF_R:     u32     = 4;
const PF_W:     u32     = 2;
const PF_X:     u32     = 1;

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
    // e_ident
    buf.extend_from_slice(&ELFMAG);
    buf.push(ELFCLASS64);   // EI_CLASS
    buf.push(ELFDATA2LSB);  // EI_DATA
    buf.push(1);            // EI_VERSION = EV_CURRENT
    buf.push(0);            // EI_OSABI = ELFOSABI_NONE
    push_zeros(buf, 8);     // EI_ABIVERSION + padding
    push_u16(buf, ET_CORE); // e_type
    push_u16(buf, EM_X86_64); // e_machine
    push_u32(buf, 1);       // e_version
    push_u64(buf, 0);       // e_entry
    push_u64(buf, 64);      // e_phoff — phdrs start right after ehdr
    push_u64(buf, 0);       // e_shoff
    push_u32(buf, 0);       // e_flags
    push_u16(buf, 64);      // e_ehsize
    push_u16(buf, 56);      // e_phentsize
    push_u16(buf, phnum);   // e_phnum
    push_u16(buf, 64);      // e_shentsize
    push_u16(buf, 0);       // e_shnum
    push_u16(buf, 0);       // e_shstrndx
    // total: 64 bytes
}

// ── ELF Phdr ─────────────────────────────────────────────────────────────────

fn write_phdr(
    buf: &mut Vec<u8>,
    p_type:  u32,
    p_flags: u32,
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
    push_u64(buf, 0);        // p_paddr (physical; irrelevant for core)
    push_u64(buf, p_filesz);
    push_u64(buf, p_memsz);
    push_u64(buf, p_align);
    // total: 56 bytes
}

// ── ELF Note ──────────────────────────────────────────────────────────────────

fn write_note(buf: &mut Vec<u8>, name: &[u8], typ: u32, desc: &[u8]) {
    // namesz includes NUL; descsz is the raw byte count.
    let namesz = name.len() as u32;
    let descsz = desc.len() as u32;
    push_u32(buf, namesz);
    push_u32(buf, descsz);
    push_u32(buf, typ);
    buf.extend_from_slice(name);
    push_zeros(buf, align4(name.len()) - name.len());
    buf.extend_from_slice(desc);
    push_zeros(buf, align4(desc.len()) - desc.len());
}

// ── NT_PRSTATUS (simplified — registers zeroed) ───────────────────────────────

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
    // pr_reg: 27 × 8 bytes (x86_64 general-purpose registers, zeroed)
    push_zeros(&mut n, 27 * 8);
    push_u32(&mut n, 0);             // pr_fpvalid
    n
}

// ── NT_PRPSINFO ───────────────────────────────────────────────────────────────

fn prpsinfo_note(pid: usize, exe: &str) -> Vec<u8> {
    let mut n = Vec::with_capacity(124);
    n.push(0u8); // pr_state
    n.push(b' '); // pr_sname
    n.push(0u8); // pr_zomb
    n.push(0u8); // pr_nice
    push_u64(&mut n, 0); // pr_flag
    push_u32(&mut n, 0); // pr_uid
    push_u32(&mut n, 0); // pr_gid
    push_u32(&mut n, pid as u32); // pr_pid
    push_u32(&mut n, 0); // pr_ppid
    push_u32(&mut n, 0); // pr_pgrp
    push_u32(&mut n, 0); // pr_sid
    // pr_fname: 16 bytes
    let name_bytes = exe.as_bytes();
    let fname_len  = name_bytes.len().min(15);
    n.extend_from_slice(&name_bytes[..fname_len]);
    push_zeros(&mut n, 16 - fname_len);
    // pr_psargs: 80 bytes
    let args_len = name_bytes.len().min(79);
    n.extend_from_slice(&name_bytes[..args_len]);
    push_zeros(&mut n, 80 - args_len);
    n
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

    // ── Layout calculation ───────────────────────────────────────────────────
    // phnum = 1 (PT_NOTE) + vmas.len() (PT_LOAD)
    let phnum     = 1 + vmas.len();
    let ehdr_size = 64usize;
    let phdr_size = 56usize;
    let phdrs_end = ehdr_size + phdr_size * phnum;
    let note_off  = phdrs_end;
    let note_size = notes.len();
    // data segments follow the note
    let mut data_off = note_off + note_size;

    // ── Write ELF header ─────────────────────────────────────────────────────
    let mut buf: Vec<u8> = Vec::new();
    write_elf_header(&mut buf, phnum as u16);

    // ── PT_NOTE phdr ─────────────────────────────────────────────────────────
    write_phdr(&mut buf, PT_NOTE, 0,
        note_off as u64, 0, note_size as u64, note_size as u64, 4);

    // ── PT_LOAD phdrs ────────────────────────────────────────────────────────
    let mut load_offsets: Vec<usize> = Vec::with_capacity(vmas.len());
    for vma in &vmas {
        let size = vma.end - vma.start;
        load_offsets.push(data_off);
        write_phdr(&mut buf, PT_LOAD, vma.flags,
            data_off as u64, vma.start as u64,
            size as u64, size as u64, 0x1000);
        data_off += size;
    }

    // ── Note data ────────────────────────────────────────────────────────────
    buf.extend_from_slice(&notes);

    // ── VMA data ─────────────────────────────────────────────────────────────
    for (vma, _off) in vmas.iter().zip(load_offsets.iter()) {
        let size = vma.end - vma.start;
        // Safety: user-space pages; if unmapped we just emit zeros.
        let slice = unsafe {
            core::slice::from_raw_parts(vma.start as *const u8, size)
        };
        buf.extend_from_slice(slice);
    }

    // ── Enforce RLIMIT_CORE byte ceiling ─────────────────────────────────────
    if buf.len() as u64 > max_bytes {
        buf.truncate(max_bytes as usize);
    }

    // ── Write to VFS ─────────────────────────────────────────────────────────
    // Build path: cwd + "/core"
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
    // Signals that produce core on Linux:
    const CORE_SIGS: &[u32] = &[3,4,5,6,7,8,11,12,31]; // SIGQUIT,ILL,TRAP,ABRT,BUS,FPE,SEGV,SYS,SIGSYS
    if !CORE_SIGS.contains(&signo) { return false; }
    let pid = current_pid();
    let (soft, _) = with_proc(pid, |p| p.rlimits.get(RLIMIT_CORE))
        .unwrap_or((0, 0));
    soft != 0
}
