//! Build the initial user stack (argv / envp / auxv) for a new process.
//!
//! Called by kernel_main (boot path) and proc::exec (execve path) after the
//! ELF has been loaded and the stack pages have been allocated.
//!
//! Layout (grows downward, RSP points at argc):
//!
//!   [strings + 16-byte AT_RANDOM value]
//!   [argv pointers, NULL terminator]
//!   [envp pointers, NULL terminator]
//!   [auxv key/value pairs, AT_NULL terminator]
//!   <- initial RSP (16-byte aligned)
//!
//! ## Error handling
//!
//! Returns `Some(initial_rsp)` on success.  Returns `None` if the combined
//! argv/envp/auxv data does not fit within `stack_buf`.  The caller must
//! not launch the process on `None`; it should report ENOMEM / SIGKILL
//! instead.  Silent truncation is not acceptable — a partial stack causes
//! undefined behaviour in the C runtime.

extern crate alloc;
use alloc::vec::Vec;

// AT_* tags needed by musl/glibc startup.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;

const PAGE: usize = 4096;

/// Build the initial stack for a newly exec'd process.
///
/// - `stack_buf`:   a mutable slice of the top stack page (writable kernel VA).
/// - `stack_top`:   the highest user VA of the stack (exclusive).
/// - `argv`:        argument strings (argv[0] = program path).
/// - `envp`:        environment strings.
/// - `entry`:       ELF entry point (AT_ENTRY).
/// - `phdr_va`:     virtual address of the PHDR table (AT_PHDR).
/// - `phdr_count`:  number of program headers (AT_PHNUM).
/// - `phdr_size`:   size of one phdr in bytes (AT_PHENT).
///
/// Returns `Some(initial_rsp)` (user VA, 16-byte aligned) on success,
/// or `None` if argv/envp/auxv do not fit within `stack_buf`.
pub fn build_stack(
    stack_buf: &mut [u8],
    stack_top: usize,
    argv: &[&str],
    envp: &[&str],
    entry: usize,
    phdr_va: usize,
    phdr_count: usize,
    phdr_size: usize,
) -> Option<usize> {
    // --- pack strings + AT_RANDOM into stack_buf from the top down ----------
    let buf_va_base = stack_top - stack_buf.len(); // user VA of stack_buf[0]

    let mut string_bytes: Vec<u8> = Vec::new();
    let mut argv_offsets: Vec<usize> = Vec::new();
    let mut envp_offsets: Vec<usize> = Vec::new();

    for s in argv {
        argv_offsets.push(string_bytes.len());
        string_bytes.extend_from_slice(s.as_bytes());
        string_bytes.push(0);
    }
    for s in envp {
        envp_offsets.push(string_bytes.len());
        string_bytes.extend_from_slice(s.as_bytes());
        string_bytes.push(0);
    }
    // 16-byte AT_RANDOM value placed right after the strings.
    let random_offset = string_bytes.len();
    let rand_a = crate::rand::next_u64().to_le_bytes();
    let rand_b = crate::rand::next_u64().to_le_bytes();
    string_bytes.extend_from_slice(&rand_a);
    string_bytes.extend_from_slice(&rand_b);

    // Align string block to 16 bytes.
    let str_total = (string_bytes.len() + 15) & !15;

    // Overflow check: string block must fit below stack_top.
    let string_va_base = stack_top.checked_sub(str_total)?;
    let random_va = string_va_base + random_offset;

    // String block must lie within stack_buf.
    let buf_string_off = string_va_base.checked_sub(buf_va_base)?;
    if buf_string_off + string_bytes.len() > stack_buf.len() {
        return None;
    }
    stack_buf[buf_string_off..buf_string_off + string_bytes.len()].copy_from_slice(&string_bytes);

    // --- build pointer table below string block ------------------------------
    let auxv: &[(u64, u64)] = &[
        (AT_PHDR, phdr_va as u64),
        (AT_PHENT, phdr_size as u64),
        (AT_PHNUM, phdr_count as u64),
        (AT_PAGESZ, PAGE as u64),
        (AT_ENTRY, entry as u64),
        (AT_BASE, 0_u64),
        (AT_FLAGS, 0_u64),
        (AT_RANDOM, random_va as u64),
        (AT_NULL, 0_u64),
    ];

    let argc = argv.len();
    let ptrtable_words = 1 + (argc + 1) + (envp.len() + 1) + auxv.len() * 2;
    let ptrtable_bytes = ptrtable_words * 8;

    // Overflow check: pointer table must fit below the string block.
    let rsp_raw = string_va_base.checked_sub(ptrtable_bytes)?;
    let initial_rsp = rsp_raw & !0xF_usize;

    // Pointer table must lie within stack_buf.
    let table_buf_off = initial_rsp.checked_sub(buf_va_base)?;
    if table_buf_off + ptrtable_bytes > stack_buf.len() {
        return None;
    }

    // Write pointer table into stack_buf.
    let mut off = table_buf_off;

    macro_rules! write64 {
        ($val:expr) => {{
            let end = off + 8;
            // Bounds guard: each write64! checked independently so that
            // a miscalculation in ptrtable_bytes does not go undetected.
            if end > stack_buf.len() {
                return None;
            }
            stack_buf[off..end].copy_from_slice(&($val as u64).to_ne_bytes());
            off = end;
        }};
    }

    write64!(argc);
    for ao in &argv_offsets {
        write64!(string_va_base + ao);
    }
    write64!(0u64); // argv null terminator
    for eo in &envp_offsets {
        write64!(string_va_base + eo);
    }
    write64!(0u64); // envp null terminator
    for (atype, aval) in auxv {
        write64!(atype);
        write64!(aval);
    }

    Some(initial_rsp)
}
