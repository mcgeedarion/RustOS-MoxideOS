//! execve implementation.
//!
//! ## do_execve flow
//!
//!   1.  vfs::open(path) → fd; read entire file → Vec<u8>; vfs::close
//!   2.  parse_elf_header + parse_phdrs
//!   3.  alloc fresh address space (new_cr3) — old space untouched until step 8
//!   4.  load_elf_into(new_cr3, data, phdrs) → program_entry
//!   5.  If PT_INTERP present: load_interpreter → interp_entry;
//!       entry_va = interp_entry, AT_BASE = INTERP_BASE
//!   6.  Alloc user stack (STACK_PAGES × 4096) in new_cr3
//!   7.  build_initial_stack → initial_rsp
//!   8.  mmap::clear_vmas(old pid_key) — unmaps + frees old anonymous pages
//!   9.  Arch::load_cr3(new_cr3)
//!  10.  PCB: user_satp=new_cr3, pc=entry_va, sp=initial_rsp,
//!            signal_handlers reset, vfork_parent cleared
//!  11.  wake_pid(vfork_parent) if CLONE_VFORK parent is waiting
//!  12.  Patch SyscallFrame for SYSRETQ / SRET delivery

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

use crate::arch::{Arch, api::{Paging, PageFlags, ContextSwitch}};
use crate::fs::{elf, vfs};
use crate::mm::{mmap, pmm};
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::proc::{scheduler, thread};
use crate::proc::process::{Pcb, State};
use crate::proc::context::Context;
use crate::proc::fork::SignalHandlers;
use crate::security::CapSet;
use crate::mm::kstack::alloc_kstack;
use crate::arch::x86_64::gdt::update_rsp0;

const PAGE_SIZE:    usize = 4096;
const STACK_PAGES:  usize = 8;
const STACK_TOP:    usize = 0x0000_7FFF_FF00_0000;
const INTERP_BASE:  usize = 0x0060_0000;

const AT_NULL:   u64 =  0;
const AT_PHDR:   u64 =  3;
const AT_PHENT:  u64 =  4;
const AT_PHNUM:  u64 =  5;
const AT_PAGESZ: u64 =  6;
const AT_BASE:   u64 =  7;
const AT_ENTRY:  u64 =  9;
const AT_RANDOM: u64 = 25;

// ── spawn_user_process ───────────────────────────────────────────────────

pub fn spawn_user_process(path: &str, argv: &[&str], envp: &[&str]) -> bool {
    let fd = match vfs::open(path, vfs::O_RDONLY) {
        Ok(fd) => fd,
        Err(_) => return false,
    };
    let file_size = vfs::fstat(fd).unwrap_or(0);
    if file_size == 0 { vfs::close(fd); return false; }
    let mut data_buf = alloc::vec![0u8; file_size];
    let n = vfs::pread(fd, data_buf.as_mut_ptr(), data_buf.len(), 0);
    vfs::close(fd);
    if n <= 0 { return false; }
    let data = &data_buf[..n as usize];

    let hdr = match elf::parse_elf_header(data) {
        Ok(h) => h, Err(_) => return false,
    };
    let phdrs = elf::parse_phdrs(data, &hdr);

    // Allocate a fresh user address space (kernel half pre-populated).
    let new_cr3 = match <Arch as Paging>::new_user_address_space() {
        Some(c) => c,
        None    => return false,
    };

    let program_entry = match elf::load_elf_into(new_cr3, data, &hdr, &phdrs) {
        Ok(e) => e,
        Err(_) => { pmm::free_page(new_cr3); return false; }
    };

    let phdr_va = phdrs.iter()
        .find(|ph| ph.p_type == elf::PT_PHDR)
        .map_or(0, |ph| ph.p_vaddr as usize);

    let (entry_va, interp_base_val) =
        if let Some(interp_path) = elf::find_interp(data, &phdrs) {
            match load_interpreter(new_cr3, interp_path) {
                Ok(e) => (e, INTERP_BASE),
                Err(_) => (program_entry, 0),
            }
        } else {
            (program_entry, 0)
        };

    let stack_bottom = STACK_TOP - STACK_PAGES * PAGE_SIZE;
    for i in 0..STACK_PAGES {
        let va = stack_bottom + i * PAGE_SIZE;
        let pa = match pmm::alloc_page() {
            Some(p) => p,
            None    => { pmm::free_page(new_cr3); return false; }
        };
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        <Arch as Paging>::map_page(
            new_cr3, va, pa,
            PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX,
        );
    }

    let argv_strings: Vec<String> = argv.iter().map(|s| String::from(*s)).collect();
    let envp_strings: Vec<String> = envp.iter().map(|s| String::from(*s)).collect();

    let initial_rsp = match build_initial_stack(
        new_cr3, STACK_TOP, &argv_strings, &envp_strings,
        &hdr, &phdrs, phdr_va, entry_va, interp_base_val,
    ) {
        Ok(rsp) => rsp,
        Err(_)  => { pmm::free_page(new_cr3); return false; }
    };

    let kstack_top = alloc_kstack();
    let pid  = scheduler::next_pid();
    let ppid = scheduler::current_pid();

    let mut ctx = Context::zero();
    ctx.rsp = kstack_top;
    ctx.rip = crate::arch::x86_64::syscall::sysret_trampoline as usize;

    let pcb = Pcb {
        pid, ppid,
        state:          State::Ready,
        exit_code:      0,
        caps:           CapSet::empty(),
        pc:             entry_va,
        sp:             initial_rsp,
        user_satp:      new_cr3,
        kernel_satp:    0,
        trapframe_pa:   0,
        kstack_top,
        ctx,
        owned_pages:         alloc::vec![],
        child_tid_va:        0,
        child_tid_val:       0,
        clear_child_tid_va:  0,
        exit_signal:         17,
        vfork_parent:        0,
        signal_handlers:     SignalHandlers::default(),
    };

    scheduler::enqueue(pcb);
    true
}

pub fn sys_execve_from_path(path: &str) -> bool {
    spawn_user_process(path, &[path], &[])
}

// ── sys_execve [NR 59] ───────────────────────────────────────────────────

pub fn sys_execve(path_va: usize, argv_va: usize, envp_va: usize,
                  frame: &mut SyscallFrame) -> isize
{
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    let argv = collect_cstr_array(argv_va);
    let envp = collect_cstr_array(envp_va);
    match do_execve(&path, &argv, &envp, frame) {
        Ok(_) => 0, Err(e) => e as isize,
    }
}

// ── do_execve ─────────────────────────────────────────────────────────────

pub fn do_execve(path: &str, argv: &[String], envp: &[String],
                 frame: &mut SyscallFrame) -> Result<(), i32>
{
    let pid = scheduler::current_pid();

    let fd = vfs::open(path, vfs::O_RDONLY).map_err(|e| e)?;
    let file_size = vfs::fstat(fd).unwrap_or(0);
    let mut data_buf = alloc::vec![0u8; file_size.max(1)];
    let n = vfs::pread(fd, data_buf.as_mut_ptr(), data_buf.len(), 0);
    vfs::close(fd);
    if n <= 0 { return Err(-8); }
    let data = &data_buf[..n as usize];

    let hdr   = elf::parse_elf_header(data)?;
    let phdrs = elf::parse_phdrs(data, &hdr);

    let new_cr3 = <Arch as Paging>::new_user_address_space().ok_or(-12i32)?;

    let program_entry = elf::load_elf_into(new_cr3, data, &hdr, &phdrs)
        .map_err(|e| { pmm::free_page(new_cr3); e })?;

    let phdr_va = phdrs.iter()
        .find(|ph| ph.p_type == elf::PT_PHDR)
        .map_or(0, |ph| ph.p_vaddr as usize);

    let (entry_va, interp_base_val) =
        if let Some(interp_path) = elf::find_interp(data, &phdrs) {
            match load_interpreter(new_cr3, interp_path) {
                Ok(ientry) => (ientry, INTERP_BASE),
                Err(_)     => (program_entry, 0),
            }
        } else { (program_entry, 0) };

    let stack_bottom = STACK_TOP - STACK_PAGES * PAGE_SIZE;
    for i in 0..STACK_PAGES {
        let va = stack_bottom + i * PAGE_SIZE;
        let pa = pmm::alloc_page().ok_or(-12i32)?;
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        <Arch as Paging>::map_page(
            new_cr3, va, pa,
            PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX,
        );
    }

    let initial_rsp = build_initial_stack(
        new_cr3, STACK_TOP, argv, envp,
        &hdr, &phdrs, phdr_va, entry_va, interp_base_val,
    )?;

    let pid_key = thread::vma_pid(pid);
    mmap::clear_vmas(pid_key);

    <Arch as Paging>::load_cr3(new_cr3);

    let vfork_parent = {
        let procs = scheduler::procs_lock();
        let vfp = if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.user_satp       = new_cr3;
            p.pc              = entry_va;
            p.sp              = initial_rsp;
            p.signal_handlers = SignalHandlers::default();
            let vfp = p.vfork_parent;
            p.vfork_parent    = 0;
            vfp
        } else { 0 };
        scheduler::procs_unlock();
        vfp
    };

    {
        let procs = scheduler::procs_lock();
        let kst = procs.iter().find(|p| p.pid == pid)
            .map_or(0, |p| p.kstack_top);
        scheduler::procs_unlock();
        if kst != 0 { update_rsp0(kst); }
    }

    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }

    frame.rcx = entry_va;
    frame.rip = entry_va;
    frame.rsp = initial_rsp;
    frame.rax = 0;
    frame.r11 = 0x202;

    Ok(())
}

// ── build_initial_stack ───────────────────────────────────────────────────

fn build_initial_stack(
    _cr3:        usize,
    stack_top:   usize,
    argv:        &[String],
    envp:        &[String],
    hdr:         &elf::Elf64Hdr,
    phdrs:       &[elf::Elf64Phdr],
    phdr_va:     usize,
    entry_va:    usize,
    interp_base: usize,
) -> Result<usize, i32>
{
    let mut string_buf: Vec<u8>      = Vec::new();
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
    string_buf.extend_from_slice(&[0u8; 16]);

    let str_total      = (string_buf.len() + 15) & !15;
    let string_va_base = stack_top - str_total;
    let random_va      = string_va_base + random_offset;

    let pt_load_count = phdrs.iter().filter(|p| p.p_type == elf::PT_LOAD).count();
    let auxv: &[(u64, u64)] = &[
        (AT_PHDR,   phdr_va as u64),
        (AT_PHENT,  core::mem::size_of::<elf::Elf64Phdr>() as u64),
        (AT_PHNUM,  pt_load_count as u64),
        (AT_PAGESZ, PAGE_SIZE as u64),
        (AT_ENTRY,  entry_va as u64),
        (AT_RANDOM, random_va as u64),
        (AT_BASE,   interp_base as u64),
        (AT_NULL,   0),
    ];

    let argc           = argv.len();
    let ptrtable_words = 1 + (argc + 1) + (envp.len() + 1) + auxv.len() * 2;
    let ptrtable_bytes = ptrtable_words * 8;
    let rsp_raw        = string_va_base - ptrtable_bytes;
    let initial_rsp    = rsp_raw & !0xF;

    unsafe {
        core::ptr::copy_nonoverlapping(
            string_buf.as_ptr(),
            string_va_base as *mut u8,
            string_buf.len(),
        );
    }

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

// ── load_interpreter ──────────────────────────────────────────────────────

fn load_interpreter(cr3: usize, interp_path: &str) -> Result<usize, i32> {
    let fd  = vfs::open(interp_path, vfs::O_RDONLY).map_err(|e| e)?;
    let sz  = vfs::fstat(fd).unwrap_or(0);
    let mut buf = alloc::vec![0u8; sz.max(1)];
    let n   = vfs::pread(fd, buf.as_mut_ptr(), buf.len(), 0);
    vfs::close(fd);
    if n <= 0 { return Err(-8); }
    let idata  = &buf[..n as usize];
    let ihdr   = elf::parse_elf_header(idata)?;
    let iphdrs = elf::parse_phdrs(idata, &ihdr);
    elf::load_elf_into(cr3, idata, &ihdr, &iphdrs)
}

// ── string helpers ────────────────────────────────────────────────────────

pub fn read_cstr_safe(va: usize) -> Option<String> {
    if va < 0x1000 || va > 0x0000_7FFF_FFFF_F000 { return None; }
    let mut s = String::new();
    let mut p = va as *const u8;
    for _ in 0..4096 {
        let c = unsafe { p.read_volatile() };
        if c == 0 { return Some(s); }
        s.push(c as char);
        p = unsafe { p.add(1) };
    }
    None
}

fn collect_cstr_array(array_va: usize) -> Vec<String> {
    let mut out = Vec::new();
    if array_va < 0x1000 { return out; }
    let mut pp = array_va as *const usize;
    for _ in 0..1024 {
        let ptr = unsafe { pp.read_volatile() };
        if ptr == 0 { break; }
        if let Some(s) = read_cstr_safe(ptr) { out.push(s); }
        pp = unsafe { pp.add(1) };
    }
    out
}
