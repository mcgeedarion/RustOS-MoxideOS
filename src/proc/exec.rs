//! execve implementation.
//!
//! ## do_execve flow
//!
//!   1.  vfs::open(path) → fd; read entire file → Vec<u8>; vfs::close
//!   2.  elf::parse_elf_header + elf::parse_phdrs_with_hdr
//!   3.  alloc fresh address space (new_cr3) — old space untouched until step 8
//!   4.  elf::load_elf_into(new_cr3, data, &hdr, &phdrs) → entry VA
//!   5.  elf::end_of_bss(phdrs, bias) → set_brk_base_compute
//!   6.  If PT_INTERP present: load_interpreter → interp_entry
//!   7.  Alloc user stack pages into new_cr3
//!   8.  clear_vmas / free_old_address_space / load_cr3(new_cr3)
//!   9.  build_initial_stack → initial_rsp
//!  10.  PCB update: user_satp/pc/sp/signal_handlers/vfork_parent/exe_path
//!  11.  wake_pid(vfork_parent) if set
//!  12.  Patch SyscallFrame (x86_64) or enqueue new PCB (riscv64)
//!
//! ## spawn_user_process_from_bytes
//!
//!   Used by kernel_main to launch pid 1 (/init) directly from the in-memory
//!   CPIO slice without going through the VFS.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

// NOTE: elf lives at crate root (src/elf.rs), not src/fs/elf.rs.
use crate::elf;
use crate::fs::vfs;
use crate::mm::{mmap, pmm};
use crate::mm::mmap::{Vma, VmaKind, MAP_ANON, MAP_GROWSDOWN, PROT_READ, PROT_WRITE, PAGE};
use crate::proc::{scheduler, thread};
use crate::proc::fork::SignalHandlers;
use crate::proc::rlimit::RLIM_INFINITY;
use crate::security::CapSet;
use crate::mm::kstack::alloc_kstack;
use crate::uaccess::copy_from_user;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::SyscallFrame;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::update_rsp0;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::paging;

const STACK_TOP:   usize = 0x0000_7FFF_FF00_0000;
const INTERP_BASE: usize = 0x0060_0000;

const STACK_MAX:          usize = 64 * 1024 * 1024;
const STACK_MIN:          usize = PAGE;
const DEFAULT_STACK_BYTES:usize = 8  * 1024 * 1024;
const ELF_DYN_BIAS:       usize = elf::ELF_DYN_BIAS;

const AT_NULL:   u64 =  0;
const AT_PHDR:   u64 =  3;
const AT_PHENT:  u64 =  4;
const AT_PHNUM:  u64 =  5;
const AT_PAGESZ: u64 =  6;
const AT_BASE:   u64 =  7;
const AT_ENTRY:  u64 =  9;
const AT_RANDOM: u64 = 25;

const USER_HALF_END: usize = 0x0000_8000_0000_0000;
const ADDR_MASK:     u64   = 0x000F_FFFF_FFFF_F000;
const PRESENT:       u64   = 1;

const MAX_CSTR_LEN:   usize = 4096;
const MAX_CSTR_ARRAY: usize = 1024;

// ── stack size helper ─────────────────────────────────────────────────────────

fn stack_bytes_for_pid(pid: usize) -> usize {
    let soft = scheduler::with_proc(pid, |p| p.rlimits.stack_soft())
        .unwrap_or(DEFAULT_STACK_BYTES as u64);
    let raw = if soft == RLIM_INFINITY {
        DEFAULT_STACK_BYTES
    } else {
        (soft as usize).min(STACK_MAX)
    };
    ((raw + PAGE - 1) & !(PAGE - 1)).max(STACK_MIN)
}

fn stack_bytes_default() -> usize { DEFAULT_STACK_BYTES }

// ── free_old_address_space ────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn free_old_address_space(cr3: usize) {
    let pml4 = cr3 as *const u64;
    for pml4i in 0..256usize {
        let pml4e = unsafe { *pml4.add(pml4i) };
        if pml4e & PRESENT == 0 { continue; }
        let pdpt = (pml4e & ADDR_MASK) as usize as *const u64;
        for pdpti in 0..512usize {
            let pdpte = unsafe { *pdpt.add(pdpti) };
            if pdpte & PRESENT == 0 { continue; }
            if pdpte & (1 << 7) != 0 { continue; }
            let pd = (pdpte & ADDR_MASK) as usize as *const u64;
            for pdi in 0..512usize {
                let pde = unsafe { *pd.add(pdi) };
                if pde & PRESENT == 0 { continue; }
                if pde & (1 << 7) != 0 { continue; }
                let pt = (pde & ADDR_MASK) as usize as *const u64;
                for pti in 0..512usize {
                    let pte = unsafe { *pt.add(pti) };
                    if pte & PRESENT == 0 { continue; }
                    let page_pa = (pte & ADDR_MASK) as usize;
                    let va = (pml4i<<39)|(pdpti<<30)|(pdi<<21)|(pti<<12);
                    if va < USER_HALF_END { pmm::free_page(page_pa); }
                }
                pmm::free_page((pde & ADDR_MASK) as usize);
            }
            pmm::free_page((pdpte & ADDR_MASK) as usize);
        }
        pmm::free_page((pml4e & ADDR_MASK) as usize);
    }
    pmm::free_page(cr3);
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn free_child_address_space(cr3: usize) {
    unsafe { free_old_address_space(cr3); }
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn free_child_address_space(_cr3: usize) {}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn free_old_address_space(_cr3: usize) {}

// ── new_user_address_space ────────────────────────────────────────────────────

fn new_user_address_space() -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        let pa = crate::mm::pmm::alloc_page()?;
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
        // Copy kernel half of current PML4 into new PML4.
        let cur_cr3: usize;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cur_cr3); }
        let src = cur_cr3 as *const u64;
        let dst = pa     as *mut   u64;
        for i in 256..512usize {
            unsafe { *dst.add(i) = *src.add(i); }
        }
        Some(pa)
    }
    #[cfg(target_arch = "riscv64")]
    {
        let pa = crate::mm::pmm::alloc_page()?;
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
        Some(pa)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    { None }
}

fn load_cr3(cr3: usize) {
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3); }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let satp = (8usize << 60) | (cr3 >> 12);
        core::arch::asm!("csrw satp, {}", in(reg) satp);
        core::arch::asm!("sfence.vma");
    }
}

// ── spawn_user_process (open via VFS) ─────────────────────────────────────────

pub fn spawn_user_process(path: &str, argv: &[&str], envp: &[&str]) -> bool {
    let fd = match vfs::open(path, vfs::O_RDONLY) {
        Ok(fd) => fd, Err(_) => return false,
    };
    let file_size = vfs::fstat(fd).unwrap_or(0);
    const MAX_ELF: usize = 64 * 1024 * 1024;
    if file_size == 0 || file_size > MAX_ELF { vfs::close(fd); return false; }
    let mut buf = alloc::vec![0u8; file_size];
    let n = vfs::pread(fd, buf.as_mut_ptr(), buf.len(), 0);
    vfs::close(fd);
    if n <= 0 { return false; }
    spawn_user_process_from_bytes(&buf[..n as usize], path, argv, envp)
}

/// Launch a new process from an in-memory ELF image (e.g. from initramfs).
///
/// Used by kernel_main to spawn pid 1 (/init) directly from the CPIO slice.
pub fn spawn_user_process_from_bytes(
    data: &[u8],
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> bool {
    let hdr = match elf::parse_elf_header(data) {
        Ok(h)  => h,
        Err(_) => return false,
    };
    let phdrs = match elf::parse_phdrs_with_hdr(data, &hdr) {
        Some(p) => p,
        None    => return false,
    };

    let new_cr3 = match new_user_address_space() {
        Some(c) => c,
        None    => return false,
    };

    let program_entry = match elf::load_elf_into(new_cr3, data, &hdr, &phdrs) {
        Ok(e)  => e,
        Err(_) => { unsafe { free_old_address_space(new_cr3); } return false; }
    };

    let elf_bias = if hdr.e_type == elf::ET_DYN { ELF_DYN_BIAS } else { 0 };
    let bss_end  = elf::end_of_bss(&phdrs, elf_bias);

    let phdr_va = phdrs.iter()
        .find(|ph| ph.p_type == elf::PT_PHDR)
        .map_or(0, |ph| ph.p_vaddr as usize + elf_bias);
    let phdr_count = phdrs.len();
    let phdr_size  = core::mem::size_of::<elf::Elf64Phdr>();

    let (entry_va, interp_base_val) =
        if let Some(interp_path) = elf::find_interp(data, &phdrs) {
            match load_interpreter(new_cr3, interp_path) {
                Ok(e)  => (e, INTERP_BASE),
                Err(_) => (program_entry, 0),
            }
        } else {
            (program_entry, 0)
        };

    let stack_bottom = match mmap::alloc_user_stack(new_cr3, STACK_TOP, stack_bytes_default()) {
        Ok(b)  => b,
        Err(_) => { unsafe { free_old_address_space(new_cr3); } return false; }
    };

    load_cr3(new_cr3);

    let argv_strings: Vec<String> = argv.iter().map(|s| String::from(*s)).collect();
    let envp_strings: Vec<String> = envp.iter().map(|s| String::from(*s)).collect();

    let initial_rsp = match build_initial_stack(
        STACK_TOP, &argv_strings, &envp_strings,
        &hdr, &phdrs, phdr_va, entry_va, interp_base_val,
    ) {
        Ok(rsp) => rsp,
        Err(_)  => { unsafe { free_old_address_space(new_cr3); } return false; }
    };

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None    => { unsafe { free_old_address_space(new_cr3); } return false; }
    };

    let pid  = scheduler::next_pid();
    let ppid = scheduler::current_pid();
    let heap_base = mmap::set_brk_base_compute(bss_end);

    let mut ctx = crate::proc::context::Context::zero();
    ctx.rsp = kstack_top;
    #[cfg(target_arch = "x86_64")]
    { ctx.rip = crate::arch::x86_64::syscall::sysret_trampoline as usize; }
    #[cfg(target_arch = "riscv64")]
    { ctx.ra  = crate::arch::riscv64::trap::sret_trampoline as usize; }

    let mut pcb = crate::proc::process::Pcb {
        pid,
        ppid,
        tgid:                pid,
        state:               crate::proc::process::State::Ready,
        exit_code:           0,
        caps:                CapSet::empty(),
        pc:                  entry_va,
        sp:                  initial_rsp,
        user_satp:           new_cr3,
        kstack_top,
        ctx,
        vmas:                alloc::vec![],
        next_va:             crate::proc::process::Pcb::INITIAL_NEXT_VA,
        brk_base:            heap_base,
        brk:                 heap_base,
        child_tid_va:        0,
        child_tid_val:       0,
        clear_child_tid_va:  0,
        exit_signal:         17,
        vfork_parent:        0,
        signal_handlers:     SignalHandlers::default(),
        exe_path:            Some(String::from(path)),
    };

    let stack_vma = Vma {
        start: stack_bottom, end: STACK_TOP,
        prot: PROT_READ | PROT_WRITE,
        flags: MAP_ANON | MAP_GROWSDOWN,
        kind: VmaKind::Stack,
        file_offset: 0,
    };
    let idx = pcb.vmas
        .binary_search_by_key(&stack_vma.start, |v| v.start)
        .unwrap_or_else(|i| i);
    pcb.vmas.insert(idx, stack_vma);

    scheduler::enqueue(pcb);
    true
}

pub fn sys_execve_from_path(path: &str) -> bool {
    spawn_user_process(path, &[path], &[])
}

// ── sys_execve — x86_64 ───────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn sys_execve(
    path_va: usize,
    argv_va: usize,
    envp_va: usize,
    frame:   &mut SyscallFrame,
) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    let argv = match collect_cstr_array(argv_va) { Ok(v) => v, Err(e) => return e as isize };
    let envp = match collect_cstr_array(envp_va) { Ok(v) => v, Err(e) => return e as isize };
    match do_execve(&path, &argv, &envp, frame) {
        Ok(_)  => 0,
        Err(e) => e as isize,
    }
}

// ── sys_execve — RISC-V ───────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub fn sys_execve(path_va: usize, argv_va: usize, envp_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    let argv = match collect_cstr_array(argv_va) { Ok(v) => v, Err(e) => return e as isize };
    let envp = match collect_cstr_array(envp_va) { Ok(v) => v, Err(e) => return e as isize };
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
    if spawn_user_process(&path, &argv_refs, &envp_refs) { 0 } else { -8 }
}

// ── do_execve (x86_64 only) ───────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn do_execve(
    path:  &str,
    argv:  &[String],
    envp:  &[String],
    frame: &mut SyscallFrame,
) -> Result<(), i32> {
    let pid = scheduler::current_pid();

    let fd = vfs::open(path, vfs::O_RDONLY).map_err(|e| e)?;
    let file_size = vfs::fstat(fd).unwrap_or(0);
    const MAX_ELF: usize = 64 * 1024 * 1024;
    if file_size == 0 || file_size > MAX_ELF { vfs::close(fd); return Err(-8); }
    let mut buf = alloc::vec![0u8; file_size];
    let n = vfs::pread(fd, buf.as_mut_ptr(), buf.len(), 0);
    vfs::close(fd);
    if n <= 0 { return Err(-8); }
    let data = &buf[..n as usize];

    let hdr   = elf::parse_elf_header(data)?;
    let phdrs = elf::parse_phdrs_with_hdr(data, &hdr).ok_or(-8i32)?;

    let new_cr3 = new_user_address_space().ok_or(-12i32)?;

    let program_entry = elf::load_elf_into(new_cr3, data, &hdr, &phdrs)
        .map_err(|e| { unsafe { free_old_address_space(new_cr3); } e })?;

    let elf_bias  = if hdr.e_type == elf::ET_DYN { ELF_DYN_BIAS } else { 0 };
    let bss_end   = elf::end_of_bss(&phdrs, elf_bias);
    let heap_base = mmap::set_brk_base_compute(bss_end);

    let phdr_va = phdrs.iter()
        .find(|ph| ph.p_type == elf::PT_PHDR)
        .map_or(0, |ph| ph.p_vaddr as usize + elf_bias);

    let (entry_va, interp_base_val) =
        if let Some(interp_path) = elf::find_interp(data, &phdrs) {
            match load_interpreter(new_cr3, interp_path) {
                Ok(e)  => (e, INTERP_BASE),
                Err(_) => (program_entry, 0),
            }
        } else {
            (program_entry, 0)
        };

    let s_bytes = stack_bytes_for_pid(pid);
    let stack_bottom = mmap::alloc_user_stack(new_cr3, STACK_TOP, s_bytes)
        .map_err(|e| { unsafe { free_old_address_space(new_cr3); } e })?;

    let old_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    mmap::clear_vmas_pub(pid);
    if old_cr3 != 0 && old_cr3 != new_cr3 {
        unsafe { free_old_address_space(old_cr3); }
    }
    load_cr3(new_cr3);

    let initial_rsp = build_initial_stack(
        STACK_TOP, argv, envp,
        &hdr, &phdrs, phdr_va, entry_va, interp_base_val,
    )?;

    let vfork_parent = scheduler::with_proc_mut(pid, |p| {
        p.user_satp       = new_cr3;
        p.pc              = entry_va;
        p.sp              = initial_rsp;
        p.signal_handlers = SignalHandlers::default();
        p.vmas            = alloc::vec![];
        p.next_va         = crate::proc::process::Pcb::INITIAL_NEXT_VA;
        p.brk_base        = heap_base;
        p.brk             = heap_base;
        p.exe_path        = Some(String::from(path));
        let vfp           = p.vfork_parent;
        p.vfork_parent    = 0;

        let sv = Vma {
            start: stack_bottom, end: STACK_TOP,
            prot: PROT_READ | PROT_WRITE,
            flags: MAP_ANON | MAP_GROWSDOWN,
            kind: VmaKind::Stack,
            file_offset: 0,
        };
        let idx = p.vmas
            .binary_search_by_key(&sv.start, |v| v.start)
            .unwrap_or_else(|i| i);
        p.vmas.insert(idx, sv);
        vfp
    }).unwrap_or(0);

    let kst = scheduler::with_proc(pid, |p| p.kstack_top).unwrap_or(0);
    if kst != 0 { update_rsp0(kst); }
    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }

    frame.rcx = entry_va;
    frame.rip = entry_va;
    frame.rsp = initial_rsp;
    frame.rax = 0;
    frame.r11 = 0x202;

    Ok(())
}

// ── build_initial_stack ───────────────────────────────────────────────────────

fn build_initial_stack(
    stack_top:   usize,
    argv:        &[String],
    envp:        &[String],
    hdr:         &elf::Elf64Hdr,
    phdrs:       &[elf::Elf64Phdr],
    phdr_va:     usize,
    entry_va:    usize,
    interp_base: usize,
) -> Result<usize, i32> {
    let mut string_buf:   Vec<u8>    = Vec::new();
    let mut argv_offsets: Vec<usize> = Vec::new();
    let mut envp_offsets: Vec<usize> = Vec::new();

    for s in argv {
        argv_offsets.push(string_buf.len());
        string_buf.extend_from_slice(s.as_bytes());
        string_buf.push(0);
    }
    for s in envp {
        envp_offsets.push(string_buf.len());
        string_buf.extend_from_slice(s.as_bytes());
        string_buf.push(0);
    }
    let random_offset = string_buf.len();
    string_buf.extend_from_slice(&crate::rand::next_u64().to_le_bytes());
    string_buf.extend_from_slice(&crate::rand::next_u64().to_le_bytes());

    let str_total      = (string_buf.len() + 15) & !15;
    let string_va_base = stack_top - str_total;
    let random_va      = string_va_base + random_offset;

    let phdr_count = phdrs.len();
    let phdr_size  = core::mem::size_of::<elf::Elf64Phdr>();

    let auxv: &[(u64, u64)] = &[
        (AT_PHDR,   phdr_va     as u64),
        (AT_PHENT,  phdr_size   as u64),
        (AT_PHNUM,  phdr_count  as u64),
        (AT_PAGESZ, PAGE        as u64),
        (AT_ENTRY,  entry_va    as u64),
        (AT_RANDOM, random_va   as u64),
        (AT_BASE,   interp_base as u64),
        (AT_NULL,   0),
    ];

    let argc           = argv.len();
    let ptrtable_words = 1 + (argc + 1) + (envp.len() + 1) + auxv.len() * 2;
    let ptrtable_bytes = ptrtable_words * 8;
    let initial_rsp    = (string_va_base - ptrtable_bytes) & !0xF;

    // Write string block into user VA (CR3 already switched).
    unsafe {
        core::ptr::copy_nonoverlapping(
            string_buf.as_ptr(),
            string_va_base as *mut u8,
            string_buf.len(),
        );
    }

    // Write pointer table.
    let mut wp = initial_rsp as *mut u64;
    unsafe {
        wp.write(argc as u64); wp = wp.add(1);
        for off in &argv_offsets { wp.write((string_va_base + off) as u64); wp = wp.add(1); }
        wp.write(0); wp = wp.add(1);
        for off in &envp_offsets { wp.write((string_va_base + off) as u64); wp = wp.add(1); }
        wp.write(0); wp = wp.add(1);
        for (atype, aval) in auxv { wp.write(*atype); wp = wp.add(1); wp.write(*aval); wp = wp.add(1); }
    }

    Ok(initial_rsp)
}

// ── load_interpreter ─────────────────────────────────────────────────────────

fn load_interpreter(cr3: usize, interp_path: &str) -> Result<usize, i32> {
    let fd  = vfs::open(interp_path, vfs::O_RDONLY).map_err(|e| e)?;
    let sz  = vfs::fstat(fd).unwrap_or(0);
    let mut buf = alloc::vec![0u8; sz.max(1)];
    let n   = vfs::pread(fd, buf.as_mut_ptr(), buf.len(), 0);
    vfs::close(fd);
    if n <= 0 { return Err(-8); }
    let idata  = &buf[..n as usize];
    let ihdr   = elf::parse_elf_header(idata)?;
    let iphdrs = elf::parse_phdrs_with_hdr(idata, &ihdr).ok_or(-8i32)?;
    elf::load_elf_into(cr3, idata, &ihdr, &iphdrs)
}

// ── string helpers ────────────────────────────────────────────────────────────

pub fn read_cstr_safe(va: usize) -> Option<String> {
    if va < 0x1000 || va > 0x0000_7FFF_FFFF_F000 { return None; }
    let mut buf = [0u8; MAX_CSTR_LEN];
    copy_from_user(&mut buf, va).ok()?;
    let nul = buf.iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..nul].to_vec()).ok()
}

pub fn collect_cstr_array(array_va: usize) -> Result<Vec<String>, i32> {
    let mut out = Vec::new();
    if array_va < 0x1000 { return Ok(out); }
    for i in 0..=MAX_CSTR_ARRAY {
        if i == MAX_CSTR_ARRAY { return Err(-7); }
        let slot_va = array_va + i * core::mem::size_of::<usize>();
        let mut ptr_bytes = [0u8; 8];
        if copy_from_user(&mut ptr_bytes, slot_va).is_err() { break; }
        let ptr = usize::from_ne_bytes(ptr_bytes);
        if ptr == 0 { break; }
        if let Some(s) = read_cstr_safe(ptr) { out.push(s); }
    }
    Ok(out)
}

pub fn clear_vmas(pid_key: u32) {
    mmap::clear_vmas_pub(pid_key as usize);
}
