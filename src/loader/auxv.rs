//! Auxiliary vector (auxv) builder.
//!
//! The auxv is placed on the initial user stack by execve, above envp.
//! musl's __init_tls and dynamic linker use several of these entries to
//! bootstrap — the critical ones are AT_PHDR, AT_PHNUM, AT_PHENT,
//! AT_ENTRY, AT_PAGESZ, AT_RANDOM, and AT_SECURE.
//!
//! ## Stack layout built by execve (top = high addr, grows down)
//!   [stack top]
//!   ... (128-byte red zone guard)
//!   auxv pairs: { AT_*, value } × N, terminated by { AT_NULL, 0 }
//!   envp strings (null-terminated)
//!   envp[] pointer array (null-terminated)
//!   argv strings (null-terminated)
//!   argv[] pointer array (null-terminated)
//!   argc (u64)
//!   [RSP points here on entry]
//!
//! All values are 8-byte aligned.

extern crate alloc;
use alloc::vec::Vec;
use crate::loader::elf64::LoadedElf;

// ── AT_* type tags ────────────────────────────────────────────────────────

pub const AT_NULL:    usize = 0;
pub const AT_PHDR:    usize = 3;
pub const AT_PHENT:   usize = 4;
pub const AT_PHNUM:   usize = 5;
pub const AT_PAGESZ:  usize = 6;
pub const AT_BASE:    usize = 7;   // interpreter base (ld.so load addr)
pub const AT_FLAGS:   usize = 8;
pub const AT_ENTRY:   usize = 9;
pub const AT_UID:     usize = 11;
pub const AT_EUID:    usize = 12;
pub const AT_GID:     usize = 13;
pub const AT_EGID:    usize = 14;
pub const AT_HWCAP:   usize = 16;
pub const AT_CLKTCK:  usize = 17;
pub const AT_SECURE:  usize = 23;
pub const AT_RANDOM:  usize = 25;  // pointer to 16 random bytes
pub const AT_HWCAP2:  usize = 26;
pub const AT_EXECFN:  usize = 31;  // pointer to executable filename

// ── Builder ───────────────────────────────────────────────────────────────

/// One auxv entry (Elf64_auxv_t: a_type, a_val each u64).
#[derive(Clone, Copy)]
pub struct AuxvEntry {
    pub a_type: usize,
    pub a_val:  usize,
}

/// Build the auxv vector for a newly exec'd process.
///
/// `elf`      — result from elf64::load()
/// `phdr_va`  — virtual address of the ELF program header table in user space
/// `phnum`    — number of program headers
/// `phent`    — size of each program header (usually 56)
/// `execfn`   — pointer to the executable path string on the user stack
/// `random_va`— pointer to 16 random bytes on the user stack
pub fn build(
    elf:       &LoadedElf,
    phdr_va:   usize,
    phnum:     usize,
    phent:     usize,
    execfn:    usize,
    random_va: usize,
) -> Vec<AuxvEntry> {
    let mut v = Vec::new();
    macro_rules! push { ($t:expr, $v:expr) => { v.push(AuxvEntry { a_type: $t, a_val: $v }); } }

    push!(AT_PAGESZ,  4096);
    push!(AT_CLKTCK,  100);
    push!(AT_PHDR,    phdr_va);
    push!(AT_PHENT,   phent);
    push!(AT_PHNUM,   phnum);
    push!(AT_BASE,    elf.base);
    push!(AT_FLAGS,   0);
    push!(AT_ENTRY,   elf.entry);
    push!(AT_UID,     0);
    push!(AT_EUID,    0);
    push!(AT_GID,     0);
    push!(AT_EGID,    0);
    push!(AT_HWCAP,   0x078b_fbfd); // typical x86_64 HWCAP (FPU,VSE,DE,PSE...)
    push!(AT_HWCAP2,  0);
    push!(AT_SECURE,  0);
    push!(AT_RANDOM,  random_va);
    push!(AT_EXECFN,  execfn);
    push!(AT_NULL,    0);  // terminator
    v
}

/// Write the full initial stack (argc, argv, envp, auxv, strings) into
/// `stack_buf` (a mutable kernel-side slice of the user stack page).
/// Returns the user-space RSP to set on entry.
///
/// `stack_top_va` — the user virtual address of the *top* of the stack page.
/// `argv`         — argument strings (argv[0] = program name).
/// `envp`         — environment strings.
/// `elf`          — loaded ELF info for auxv.
/// `image`        — original ELF bytes (used to extract phdr info).
pub fn write_initial_stack(
    stack_buf:    &mut [u8],
    stack_top_va: usize,
    argv:         &[&str],
    envp:         &[&str],
    elf:          &LoadedElf,
    image:        &[u8],
) -> usize {
    // We build the stack bottom-up in a local Vec<u64> then copy.
    // Strategy: write strings at the bottom of the page, pointers above them.
    let page = 4096usize;
    let mut string_off: usize = 0; // offset from buf start, grows upward
    let mut ptrs: Vec<u64> = Vec::new(); // will be reversed

    // Helper: write a &str into buf, return its user VA.
    let mut write_str = |s: &str| -> usize {
        let bytes = s.as_bytes();
        let len   = bytes.len() + 1; // include null terminator
        let off   = string_off;
        stack_buf[off..off + bytes.len()].copy_from_slice(bytes);
        stack_buf[off + bytes.len()] = 0;
        string_off += len;
        // VA: stack_top_va - page + off  (buf[0] = lowest addr in page)
        stack_top_va - page + off
    };

    // Write 16 cryptographically-seeded random bytes for AT_RANDOM.
    // glibc uses these as its stack-canary seed and pointer-encryption key —
    // they must be unique per process per boot, never a fixed constant.
    let random_bytes: [u8; 16] = {
        let a = crate::rand::next_u64().to_le_bytes();
        let b = crate::rand::next_u64().to_le_bytes();
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&a);
        buf[8..].copy_from_slice(&b);
        buf
    };
    // Write the bytes as a raw blob (not a NUL-terminated string) so that
    // bytes with value 0 are preserved verbatim.
    let random_va = {
        let off = string_off;
        stack_buf[off..off + 16].copy_from_slice(&random_bytes);
        string_off += 16;
        stack_top_va - page + off
    };

    // Write execfn (argv[0]).
    let execfn_va = if argv.is_empty() {
        write_str("(unknown)")
    } else {
        write_str(argv[0])
    };

    // Write all argv strings.
    let argv_vas: Vec<usize> = argv.iter().map(|s| write_str(s)).collect();
    // Write all envp strings.
    let envp_vas: Vec<usize> = envp.iter().map(|s| write_str(s)).collect();

    // ── Now build the pointer/value area from the top of the page down ──
    // We'll write into a separate aligned buffer, then place it.
    // Round string_off up to 8-byte alignment for the pointer area.
    string_off = (string_off + 7) & !7;

    // Extract phdr info from ELF image.
    let (phdr_offset, phnum, phent) = if image.len() >= 0x40 {
        let ehdr = unsafe { &*(image.as_ptr() as *const crate::loader::elf64_phdr_info) };
        // Parse manually to avoid importing the struct:
        let phoff  = u64::from_le_bytes(image[0x20..0x28].try_into().unwrap_or([0;8])) as usize;
        let phnum  = u16::from_le_bytes(image[0x38..0x3A].try_into().unwrap_or([0;2])) as usize;
        let phent  = u16::from_le_bytes(image[0x36..0x38].try_into().unwrap_or([0;2])) as usize;
        (phoff, phnum, phent)
    } else {
        (0, 0, 56)
    };

    // phdr VA: elf.base + phdr_offset
    let phdr_va = elf.base + phdr_offset;

    let auxv = build(elf, phdr_va, phnum, phent, execfn_va, random_va);

    // Build pointer table area (we'll place it starting at string_off).
    // Layout (from low to high in stack_buf, i.e. low VA to high VA):
    //   argc (u64)
    //   argv[0..n] (u64 each), 0-terminated
    //   envp[0..m] (u64 each), 0-terminated
    //   auxv[0..k] (two u64 each), AT_NULL-terminated
    // RSP points at argc.

    let ptr_base_off = string_off; // offset in stack_buf where pointers start
    let ptr_base_va  = stack_top_va - page + ptr_base_off;

    let mut write_u64 = |val: u64, off: &mut usize| {
        let b = val.to_le_bytes();
        stack_buf[*off..*off+8].copy_from_slice(&b);
        *off += 8;
    };

    let mut off = ptr_base_off;
    write_u64(argv.len() as u64, &mut off);       // argc
    for va in &argv_vas { write_u64(*va as u64, &mut off); }  // argv[]
    write_u64(0, &mut off);                       // argv null
    for va in &envp_vas { write_u64(*va as u64, &mut off); }  // envp[]
    write_u64(0, &mut off);                       // envp null
    for e in &auxv {
        write_u64(e.a_type as u64, &mut off);
        write_u64(e.a_val  as u64, &mut off);
    }

    // RSP = VA of argc
    ptr_base_va
}
