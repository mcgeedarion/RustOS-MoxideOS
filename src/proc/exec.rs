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

// ── stack size helper ─────────────────────────────────────────────────────────────────

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

// ── free_old_address_space ─────────────────────────────────────────────────────────────

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

// ── new_user_address_space ───────────────────────────────────────────────────────────

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

// ── spawn_user_process (open via VFS) ─────────────────────────────────────────────

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
    // Allocate stdin/stdout/stderr (fds 0, 1, 2) for the new process.
    crate::fs::process_fd::proc_fd_alloc(pid, 0, 1, 2);
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
        brk_current:         heap_base,
        signal_handlers:     SignalHandlers::default(),
        ..crate::proc::process::Pcb::zeroed()
    };
    pcb.exe_path = String::from(path);

    scheduler::enqueue(pcb);
    true
}

/// Convenience wrapper: launch a process by path with no argv/envp.
pub fn spawn_process(path: &str) -> bool {
    spawn_user_process(path, &[path], &[])
}

// ── sys_execve [NR 59] ──────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn sys_execve(
    path_va:  usize,
    argv_va:  usize,
    envp_va:  usize,
    frame:    &mut SyscallFrame,
) -> isize {
    let mut path = alloc::vec![0u8; MAX_CSTR_LEN];
    let n = copy_from_user(path_va, &mut path);
    if n <= 0 { return -14; }
    let path = match core::str::from_utf8(&path[..n as usize]).ok()
        .and_then(|s| Some(s.trim_end_matches('\0'))) {
        Some(s) => s.to_string(),
        None    => return -14,
    };

    let argv = read_cstr_array(argv_va);
    let envp = read_cstr_array(envp_va);
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();

    match do_execve(&path, &argv_refs, &envp_refs, frame) {
        Ok(_)  => 0,
        Err(e) => e,
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn sys_execve_noframe(path_va: usize, argv_va: usize, envp_va: usize) -> isize {
    let mut path = alloc::vec![0u8; MAX_CSTR_LEN];
    let n = copy_from_user(path_va, &mut path);
    if n <= 0 { return -14; }
    let path = match core::str::from_utf8(&path[..n as usize]).ok()
        .and_then(|s| Some(s.trim_end_matches('\0'))) {
        Some(s) => s.to_string(),
        None    => return -14,
    };
    let argv = read_cstr_array(argv_va);
    let envp = read_cstr_array(envp_va);
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
    if spawn_user_process(&path, &argv_refs, &envp_refs) { 0 } else { -8 }
}

// ── do_execve (x86_64 only) ───────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub fn do_execve(
    path: &str,
    argv: &[&str],
    envp: &[&str],
    frame: &mut SyscallFrame,
) -> Result<(), isize> {
    let pid = scheduler::current_pid();
    // Close all O_CLOEXEC fds before loading the new image.
    // POSIX requires this to happen before the new image is mapped.
    crate::fs::process_fd::proc_fd_close_on_exec(pid);

    let fd = vfs::open(path, vfs::O_RDONLY).map_err(|_| -8isize)?;
    let file_size = vfs::fstat(fd).unwrap_or(0);
    const MAX_ELF: usize = 64 * 1024 * 1024;
    if file_size == 0 || file_size > MAX_ELF { vfs::close(fd); return Err(-8); }
    let mut data: Vec<u8> = alloc::vec![0u8; file_size];
    let n = vfs::pread(fd, data.as_mut_ptr(), file_size, 0);
    vfs::close(fd);
    if n <= 0 { return Err(-8); }
    let data = &data[..n as usize];

    let hdr   = elf::parse_elf_header(data).map_err(|_| -8isize)?;
    let phdrs = elf::parse_phdrs_with_hdr(data, &hdr).ok_or(-8isize)?;

    let new_cr3 = new_user_address_space().ok_or(-12isize)?;

    let program_entry = elf::load_elf_into(new_cr3, data, &hdr, &phdrs)
        .map_err(|e| { unsafe { free_old_address_space(new_cr3); } e })?;

    let elf_bias = if hdr.e_type == elf::ET_DYN { ELF_DYN_BIAS } else { 0 };
    let bss_end  = elf::end_of_bss(&phdrs, elf_bias);

    let phdr_va = phdrs.iter()
        .find(|ph| ph.p_type == elf::PT_PHDR)
        .map_or(0, |ph| ph.p_vaddr as usize + elf_bias);
    let phdr_count = phdrs.len();
    let phdr_size  = core::mem::size_of::<elf::Elf64Phdr>();

    let (entry_va, interp_base_val) =
        if let Some(interp_path) = elf::find_interp(data, &phdrs) {
            let e = load_interpreter(new_cr3, interp_path)
                .map_err(|e| { unsafe { free_old_address_space(new_cr3); } e })?;
            (e, INTERP_BASE)
        } else {
            (program_entry, 0)
        };

    let stack_sz = stack_bytes_for_pid(pid);
    mmap::alloc_user_stack(new_cr3, STACK_TOP, stack_sz)
        .map_err(|e| { unsafe { free_old_address_space(new_cr3); } e })?;

    let argv_strings: Vec<String> = argv.iter().map(|s| String::from(*s)).collect();
    let envp_strings: Vec<String> = envp.iter().map(|s| String::from(*s)).collect();

    let initial_rsp = build_initial_stack(
        STACK_TOP, &argv_strings, &envp_strings,
        &hdr, &phdrs, phdr_va, entry_va, interp_base_val,
    ).map_err(|e| { unsafe { free_old_address_space(new_cr3); } e })?;

    let old_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    mmap::clear_vmas_pub(pid);
    if old_cr3 != 0 {
        unsafe { free_old_address_space(old_cr3); }
    }
    load_cr3(new_cr3);
    update_rsp0(scheduler::with_proc(pid, |p| p.kstack_top).unwrap_or(0));

    let heap_base = mmap::set_brk_base_compute(bss_end);

    scheduler::with_proc_mut(pid, |p| {
        p.user_satp      = new_cr3;
        p.pc             = entry_va;
        p.sp             = initial_rsp;
        p.signal_handlers = SignalHandlers::default();
        let vfork_parent = p.vfork_parent;
        p.vfork_parent   = 0;
        p.exe_path       = String::from(path);
        p.brk_base       = heap_base;
        p.brk_current    = heap_base;
        vfork_parent
    });
    let vfork_parent = scheduler::with_proc(pid, |p| p.vfork_parent).unwrap_or(0);
    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }

    // Patch the saved SyscallFrame so sysret returns to the new image.
    frame.rip = entry_va;
    frame.rsp = initial_rsp;
    frame.rflags = 0x202;

    Ok(())
}

// ── read_cstr_array ────────────────────────────────────────────────────────────────

fn read_cstr_array(ptr_array_va: usize) -> Vec<String> {
    if ptr_array_va == 0 { return Vec::new(); }
    let mut result = Vec::new();
    let mut i = 0usize;
    loop {
        if i >= MAX_CSTR_ARRAY { break; }
        let ptr_va = ptr_array_va + i * 8;
        let mut ptr_buf = [0u8; 8];
        if copy_from_user(ptr_va, &mut ptr_buf) != 8 { break; }
        let ptr = usize::from_ne_bytes(ptr_buf);
        if ptr == 0 { break; }
        let mut buf = alloc::vec![0u8; MAX_CSTR_LEN];
        let n = copy_from_user(ptr, &mut buf);
        if n <= 0 { break; }
        let s = core::str::from_utf8(&buf[..n as usize]).unwrap_or("").trim_end_matches('\0');
        result.push(String::from(s));
        i += 1;
    }
    result
}

// ── build_initial_stack ───────────────────────────────────────────────────────────────

fn build_initial_stack(
    stack_top: usize,
    argv: &[String],
    envp: &[String],
    hdr: &elf::ElfHeader,
    phdrs: &[elf::Elf64Phdr],
    phdr_va: usize,
    entry_va: usize,
    interp_base: usize,
) -> Result<usize, isize> {
    use core::ptr;

    let mut sp = stack_top;

    macro_rules! push_bytes {
        ($bytes:expr) => {{
            let b: &[u8] = $bytes;
            sp -= b.len();
            sp &= !0xf;
            let dst = sp as *mut u8;
            unsafe { ptr::copy_nonoverlapping(b.as_ptr(), dst, b.len()); }
        }};
    }
    macro_rules! push_usize {
        ($val:expr) => {{
            sp -= 8;
            unsafe { (sp as *mut usize).write($val); }
        }};
    }

    // 1. Write string data (env strings, then arg strings)
    let mut env_ptrs: Vec<usize> = Vec::new();
    for e in envp.iter().rev() {
        let b = e.as_bytes();
        push_bytes!(b);
        sp -= 1; // null terminator
        unsafe { *(sp as *mut u8) = 0; }
        env_ptrs.push(sp);
    }
    env_ptrs.reverse();

    let mut arg_ptrs: Vec<usize> = Vec::new();
    for a in argv.iter().rev() {
        let b = a.as_bytes();
        push_bytes!(b);
        sp -= 1;
        unsafe { *(sp as *mut u8) = 0; }
        arg_ptrs.push(sp);
    }
    arg_ptrs.reverse();

    // 2. Random bytes for AT_RANDOM (16 bytes)
    sp -= 16;
    sp &= !0xf;
    let random_va = sp;
    let rand_bytes = [0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                      0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef];
    unsafe { ptr::copy_nonoverlapping(rand_bytes.as_ptr(), sp as *mut u8, 16); }

    // 3. Align to 16 bytes
    sp &= !0xf;

    // 4. Auxvec (NULL-terminated)
    let phdr_count = phdrs.len();
    let phdr_size  = core::mem::size_of::<elf::Elf64Phdr>();
    let auxv: &[(u64,u64)] = &[
        (AT_PHDR,   phdr_va      as u64),
        (AT_PHENT,  phdr_size    as u64),
        (AT_PHNUM,  phdr_count   as u64),
        (AT_PAGESZ, PAGE         as u64),
        (AT_BASE,   interp_base  as u64),
        (AT_ENTRY,  entry_va     as u64),
        (AT_RANDOM, random_va    as u64),
        (AT_NULL,   0),
    ];
    for &(t, v) in auxv.iter().rev() {
        push_usize!(v as usize);
        push_usize!(t as usize);
    }

    // 5. envp NULL, then envp pointers (reversed)
    push_usize!(0);
    for &p in env_ptrs.iter().rev() { push_usize!(p); }

    // 6. argv NULL, then argv pointers (reversed)
    push_usize!(0);
    for &p in arg_ptrs.iter().rev() { push_usize!(p); }

    // 7. argc
    push_usize!(argv.len());

    // 8. Final 16-byte alignment
    sp &= !0xf;

    Ok(sp)
}

// ── load_interpreter ───────────────────────────────────────────────────────────────────

fn load_interpreter(cr3: usize, path: &str) -> Result<usize, isize> {
    let fd = vfs::open(path, vfs::O_RDONLY).map_err(|_| -8isize)?;
    let file_size = vfs::fstat(fd).unwrap_or(0);
    const MAX_INTERP: usize = 4 * 1024 * 1024;
    if file_size == 0 || file_size > MAX_INTERP {
        vfs::close(fd);
        return Err(-8);
    }
    let mut idata: Vec<u8> = alloc::vec![0u8; file_size];
    let n = vfs::pread(fd, idata.as_mut_ptr(), file_size, 0);
    vfs::close(fd);
    if n <= 0 { return Err(-8); }
    let idata = &idata[..n as usize];

    let ihdr   = elf::parse_elf_header(idata).map_err(|_| -8isize)?;
    let iphdrs = elf::parse_phdrs_with_hdr(idata, &ihdr).ok_or(-8isize)?;
    elf::load_elf_into(cr3, idata, &ihdr, &iphdrs)
}

// ── clear_vmas wrapper (called from fork_syscall) ─────────────────────────────────

pub fn clear_vmas(pid_key: u32) {
    mmap::clear_vmas_pub(pid_key as usize);
}
