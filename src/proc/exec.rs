//! execve implementation.
//!
//! ## do_execve flow
//!
//!   1.  vfs::open(path) → fd; read entire file → Vec<u8>; vfs::close
//!   2.  elf::parse_elf_header + elf::parse_phdrs_with_hdr
//!   2b. binfmt_misc probe — if machine type != native arch AND a matching
//!       binfmt_misc entry exists, re-exec under the registered interpreter.
//!   3.  alloc fresh address space (new_cr3) — old space untouched until step 8
//!   4.  elf::load_elf_into(new_cr3, data, &hdr, &phdrs) → entry VA
//!   5.  elf::end_of_bss(phdrs, bias) → set_brk_base_compute
//!   6.  If PT_INTERP present: load_interpreter → interp_entry
//!   7.  Alloc user stack pages into new_cr3
//!   8.  clear_vmas / free_old_address_space / load_cr3(new_cr3)
//!   9.  build_initial_stack → initial_rsp
//!  10.  PCB update: user_satp/pc/sp/signal_handlers/vfork_parent/exe_path
//!       signal_handlers: SIG_IGN dispositions survive; user VAs reset to SIG_DFL.
//!       pending signals and sigmask are cleared (they don't survive exec).
//!  11.  wake_pid(vfork_parent) if set
//!  12.  Patch SyscallFrame (x86_64) OR rebuild TrapFrame on kstack (riscv64)
//!
//! ## TaskRunState after exec
//!
//!   `exec` replaces the address space of a `Live` task.  The existing
//!   `Pcb::ctx` becomes stale (it encodes the kernel-stack return address from
//!   the *old* binary's syscall entry).  Both `do_execve` and `do_execve_riscv`
//!   now reset `task.run_state` to `TaskRunState::Cold { pc, sp }` after
//!   rebuilding the kernel-stack TrapFrame / SyscallFrame.  This ensures that
//!   the next `schedule()` invocation enters via `context::restore()` rather
//!   than `context::switch()`, which would chase the stale ctx and fault.
//!
//! ## RISC-V in-place exec (do_execve_riscv)
//!
//!   On RISC-V execve arrives through the ecall/trap path. By the time
//!   `sys_execve_noframe` is called the current task's TrapFrame is already
//!   at `kstack_top - TRAP_FRAME_SIZE`. We overwrite it in-place via
//!   `rebuild_trap_frame_riscv`, then update the Context so that the next
//!   context switch (or the eventual trap_return at the end of this trap
//!   handler invocation) enters the new program correctly.
//!
//! ## Post-S2 locking
//!
//!   Both `do_execve` and `do_execve_riscv` update the PCB through
//!   `with_proc_mut(pid, |p, _pl| { … })`. Neither changes `p.state`
//!   so `_pl` is unused.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

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
#[cfg(target_arch = "riscv64")]
use crate::arch::riscv64::trampoline::TRAPFRAME_VADDR;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::SyscallFrame;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::update_rsp0;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::paging;

const STACK_TOP:   usize = 0x0000_7FFF_FF00_0000;
const INTERP_BASE: usize = 0x0060_0000;
const STACK_MAX:   usize = 64 * 1024 * 1024;
const STACK_MIN:   usize = PAGE;

// ── Native machine type constant ────────────────────────────────────────────
#[cfg(target_arch = "x86_64")]
const NATIVE_EM: u16 = 62;  // EM_X86_64
#[cfg(target_arch = "riscv64")]
const NATIVE_EM: u16 = 243; // EM_RISCV
#[cfg(target_arch = "aarch64")]
const NATIVE_EM: u16 = 183; // EM_AARCH64

const BINFMT_PROBE_BYTES: usize = 256;

// Called from kernel_main to bootstrap PID 1.
pub fn spawn_user_process(path: &str, argv: &[&str], envp: &[&str]) -> bool {
    let fd = match vfs::open(path, 0, 0) {
        fd if fd >= 0 => fd as usize,
        _             => return false,
    };
    let size = vfs::fsize(fd).unwrap_or(0);
    if size == 0 { vfs::close(fd); return false; }
    let mut data = Vec::with_capacity(size);
    data.resize(size, 0u8);
    if vfs::read(fd, &mut data) != size as isize { vfs::close(fd); return false; }
    vfs::close(fd);

    spawn_user_process_from_bytes(path, &data, argv, envp)
}

pub fn spawn_user_process_from_bytes(
    path: &str,
    data: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> bool {
    use crate::proc::process::{Pcb, State};
    use crate::proc::context::Context;
    use crate::proc::pid::alloc_pid;

    let hdr   = match elf::parse_elf_header(data)          { Some(h) => h, None => return false };
    let phdrs = match elf::parse_phdrs_with_hdr(data, &hdr) { Some(p) => p, None => return false };

    #[cfg(target_arch = "x86_64")]
    let new_cr3 = paging::alloc_root_page_table();
    #[cfg(target_arch = "riscv64")]
    let new_cr3 = crate::arch::riscv64::paging::alloc_root_page_table();

    let entry_va = match elf::load_elf_into(new_cr3, data, &hdr, &phdrs) {
        Some(e) => e,
        None    => { pmm::free_page_table(new_cr3); return false; }
    };
    let brk_base = elf::end_of_bss(&phdrs, 0);

    let (final_entry, interp_bias) =
        if let Some(interp_path) = crate::proc::dynlink::find_interp(data) {
            match crate::proc::dynlink::load_interp(&interp_path) {
                Ok((ie, bias)) => (ie, bias),
                Err(_)         => { pmm::free_page_table(new_cr3); return false; }
            }
        } else {
            (entry_va, 0)
        };

    #[cfg(target_arch = "x86_64")]
    let user_sp_top = alloc_map_stack(new_cr3, STACK_TOP);
    #[cfg(target_arch = "riscv64")]
    let user_sp_top = match crate::arch::riscv64::uentry::alloc_user_stack(new_cr3 >> 12) {
        Some(sp) => sp,
        None     => { pmm::free_page_table(new_cr3); return false; }
    };

    let (initial_sp, vmas) = crate::auxv::build_stack(
        new_cr3, user_sp_top, argv, envp,
        &hdr, &phdrs, entry_va, interp_bias, brk_base,
    );

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None    => { pmm::free_page_table(new_cr3); return false; }
    };

    #[cfg(target_arch = "x86_64")]
    let ctx = {
        use crate::arch::x86_64::syscall::push_syscall_frame;
        push_syscall_frame(kstack_top, final_entry, 0x202, initial_sp);
        Context {
            rip: crate::proc::context::task_entry_trampoline as usize,
            rsp: kstack_top - 17 * 8,
            ..Context::zero()
        }
    };

    #[cfg(target_arch = "riscv64")]
    let (ctx, trapframe_pa) = {
        use crate::arch::riscv64::trap::{rebuild_trap_frame_riscv, TRAP_FRAME_SIZE};
        rebuild_trap_frame_riscv(kstack_top, final_entry, initial_sp, 0);
        let trapframe_pa = kstack_top - TRAP_FRAME_SIZE;
        let ctx = Context {
            ra:  crate::proc::context::task_entry_trampoline as usize,
            sp:  trapframe_pa,
            s0:  0,
            ..Context::zero()
        };
        (ctx, trapframe_pa)
    };

    let pid = alloc_pid();

    let mut pcb = Pcb::zeroed();
    pcb.pid        = pid;
    pcb.ppid       = 0;
    pcb.tgid       = pid;
    pcb.pgid       = pid;
    pcb.sid        = pid;
    pcb.state      = State::Ready;
    pcb.pc         = final_entry;
    pcb.sp         = initial_sp;
    pcb.user_satp  = new_cr3;
    pcb.kstack_top = kstack_top;
    pcb.ctx        = ctx;
    pcb.vmas       = vmas;
    pcb.brk_base   = brk_base;
    pcb.brk        = brk_base;
    pcb.exe_path   = Some(String::from(path));
    pcb.caps       = CapSet::full();
    #[cfg(target_arch = "riscv64")]
    {
        pcb.trapframe_pa   = trapframe_pa;
        pcb.trapframe_virt = TRAPFRAME_VADDR;
    }

    scheduler::enqueue(pcb);
    true
}

// ── binfmt_misc redispatch helper ───────────────────────────────────────────

fn binfmt_dispatch_needed(e_machine: u16) -> bool {
    e_machine != NATIVE_EM
}

/// Build a new argv with `interp` prepended.
/// If `open_binary` is true, open the binary, append `"--"` and the fd number,
/// and mark the fd close-on-exec via `crate::fs::fcntl::set_cloexec`.
fn prepend_interpreter(
    interp:       &str,
    orig_argv:    &[String],
    open_binary:  bool,
    bin_path:     &str,
) -> Vec<String> {
    let mut new_argv: Vec<String> = Vec::new();
    new_argv.push(String::from(interp));
    if open_binary {
        let fd = crate::fs::vfs::open(bin_path, 0, 0);
        if fd >= 0 {
            // Mark close-on-exec so grandchildren don't inherit the fd.
            crate::fs::fcntl::set_cloexec(fd as usize, true);
            new_argv.push(String::from("--"));
            new_argv.push(alloc::format!("{}", fd as usize));
        }
    }
    new_argv.extend_from_slice(orig_argv);
    new_argv
}

#[cfg(target_arch = "x86_64")]
pub fn do_execve(
    pid:     usize,
    path_va: usize,
    argv_va: usize,
    envp_va: usize,
) -> isize {
    let path = match copy_cstr_from_user(path_va) { Some(s) => s, None => return -14 };
    let argv = copy_strvec_from_user(argv_va);
    let envp = copy_strvec_from_user(envp_va);

    let fd = match vfs::open(&path, 0, 0) { fd if fd >= 0 => fd as usize, e => return e };
    let size = match vfs::fsize(fd) { Some(s) => s, None => { vfs::close(fd); return -2; } };
    let mut data = Vec::with_capacity(size);
    data.resize(size, 0u8);
    if vfs::read(fd, &mut data) != size as isize { vfs::close(fd); return -5; }
    vfs::close(fd);

    // ── binfmt_misc probe ──────────────────────────────────────────────────
    {
        let probe_len = data.len().min(BINFMT_PROBE_BYTES);
        let hdr_bytes = &data[..probe_len];

        let is_native_elf = data.len() >= 20
            && &data[0..4] == b"\x7fELF"
            && u16::from_le_bytes([data[18], data[19]]) == NATIVE_EM;

        if !is_native_elf && crate::fs::procfs_binfmt::is_globally_enabled() {
            if let Some((interp_path, flags)) = crate::fs::binfmt_misc::probe_header(hdr_bytes) {
                let open_bin = flags & crate::fs::binfmt_misc::FLAG_OPEN_BINARY != 0;
                let new_argv = prepend_interpreter(&interp_path, &argv, open_bin, &path);
                let new_argv_refs: Vec<&str> = new_argv.iter().map(|s| s.as_str()).collect();
                let envp_refs:     Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
                return do_execve_from_vecs(pid, &interp_path, &new_argv_refs, &envp_refs);
            }
        }
    }
    // ── end binfmt_misc probe ──────────────────────────────────────────────

    let hdr   = match elf::parse_elf_header(&data)          { Some(h) => h, None => return -8 };
    let phdrs = match elf::parse_phdrs_with_hdr(&data, &hdr) { Some(p) => p, None => return -8 };

    let new_cr3  = paging::alloc_root_page_table();
    let entry_va = match elf::load_elf_into(new_cr3, &data, &hdr, &phdrs) {
        Some(e) => e,
        None    => { pmm::free_page_table(new_cr3); return -12; }
    };
    let brk_base = elf::end_of_bss(&phdrs, 0);

    let (final_entry, interp_bias) =
        if let Some(interp_path) = crate::proc::dynlink::find_interp(&data) {
            match crate::proc::dynlink::load_interp(&interp_path) {
                Ok((ie, bias)) => (ie, bias),
                Err(e)         => { pmm::free_page_table(new_cr3); return e; }
            }
        } else {
            (entry_va, 0)
        };

    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();

    let user_sp_top = alloc_map_stack(new_cr3, STACK_TOP);
    let (initial_rsp, new_vmas) = crate::auxv::build_stack(
        new_cr3, user_sp_top, &argv_refs, &envp_refs,
        &hdr, &phdrs, entry_va, interp_bias, brk_base,
    );

    let kstack_top = scheduler::with_proc(pid, |p| p.kstack_top).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        mmap::clear_vmas(p);
        unsafe { paging::free_user_page_table(p.user_satp); }
        unsafe { paging::load_cr3(new_cr3); }
        update_rsp0(p.kstack_top);
    });

    use crate::arch::x86_64::syscall::patch_syscall_frame;
    patch_syscall_frame(kstack_top, final_entry, 0x202, initial_rsp);

    let new_ctx = crate::proc::context::Context {
        rip: crate::proc::context::task_entry_trampoline as usize,
        rsp: kstack_top - 17 * 8,
        ..crate::proc::context::Context::zero()
    };

    let old_handlers = scheduler::with_proc(pid, |p| p.signal_handlers.lock().clone()).unwrap();
    let vfork_parent = scheduler::with_proc(pid, |p| p.vfork_parent).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        p.user_satp       = new_cr3;
        p.pc              = final_entry;
        p.sp              = initial_rsp;
        p.ctx             = new_ctx;
        p.brk_base        = brk_base;
        p.brk             = brk_base;
        p.vmas            = new_vmas;
        p.exe_path        = Some(path.clone());
        p.signal_handlers = alloc::sync::Arc::new(spin::Mutex::new(old_handlers.exec_reset()));
        p.pending_signals.clear();
        p.vfork_parent    = 0;
    });

    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }

    thread::set_run_state_cold(pid, final_entry, initial_rsp);
    0
}

#[cfg(target_arch = "x86_64")]
fn do_execve_from_vecs(
    pid:   usize,
    path:  &str,
    argv:  &[&str],
    envp:  &[&str],
) -> isize {
    let fd = match vfs::open(path, 0, 0) { fd if fd >= 0 => fd as usize, e => return e };
    let size = match vfs::fsize(fd) { Some(s) => s, None => { vfs::close(fd); return -2; } };
    let mut data = Vec::with_capacity(size);
    data.resize(size, 0u8);
    if vfs::read(fd, &mut data) != size as isize { vfs::close(fd); return -5; }
    vfs::close(fd);

    let hdr   = match elf::parse_elf_header(&data)          { Some(h) => h, None => return -8 };
    let phdrs = match elf::parse_phdrs_with_hdr(&data, &hdr) { Some(p) => p, None => return -8 };

    let new_cr3  = paging::alloc_root_page_table();
    let entry_va = match elf::load_elf_into(new_cr3, &data, &hdr, &phdrs) {
        Some(e) => e,
        None    => { pmm::free_page_table(new_cr3); return -12; }
    };
    let brk_base = elf::end_of_bss(&phdrs, 0);

    let (final_entry, interp_bias) =
        if let Some(interp_path) = crate::proc::dynlink::find_interp(&data) {
            match crate::proc::dynlink::load_interp(&interp_path) {
                Ok((ie, bias)) => (ie, bias),
                Err(e)         => { pmm::free_page_table(new_cr3); return e; }
            }
        } else {
            (entry_va, 0)
        };

    let user_sp_top = alloc_map_stack(new_cr3, STACK_TOP);
    let (initial_rsp, new_vmas) = crate::auxv::build_stack(
        new_cr3, user_sp_top, argv, envp,
        &hdr, &phdrs, entry_va, interp_bias, brk_base,
    );

    let kstack_top = scheduler::with_proc(pid, |p| p.kstack_top).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        mmap::clear_vmas(p);
        unsafe { paging::free_user_page_table(p.user_satp); }
        unsafe { paging::load_cr3(new_cr3); }
        update_rsp0(p.kstack_top);
    });

    use crate::arch::x86_64::syscall::patch_syscall_frame;
    patch_syscall_frame(kstack_top, final_entry, 0x202, initial_rsp);

    let new_ctx = crate::proc::context::Context {
        rip: crate::proc::context::task_entry_trampoline as usize,
        rsp: kstack_top - 17 * 8,
        ..crate::proc::context::Context::zero()
    };

    let old_handlers = scheduler::with_proc(pid, |p| p.signal_handlers.lock().clone()).unwrap();
    let vfork_parent = scheduler::with_proc(pid, |p| p.vfork_parent).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        p.user_satp       = new_cr3;
        p.pc              = final_entry;
        p.sp              = initial_rsp;
        p.ctx             = new_ctx;
        p.brk_base        = brk_base;
        p.brk             = brk_base;
        p.vmas            = new_vmas;
        p.exe_path        = Some(String::from(path));
        p.signal_handlers = alloc::sync::Arc::new(spin::Mutex::new(old_handlers.exec_reset()));
        p.pending_signals.clear();
        p.vfork_parent    = 0;
    });

    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }
    thread::set_run_state_cold(pid, final_entry, initial_rsp);
    0
}

#[cfg(target_arch = "riscv64")]
pub fn do_execve_riscv(
    pid:     usize,
    path_va: usize,
    argv_va: usize,
    envp_va: usize,
) -> isize {
    use crate::arch::riscv64::trap::{rebuild_trap_frame_riscv, TRAP_FRAME_SIZE};
    use crate::arch::riscv64::paging::alloc_root_page_table;
    use crate::arch::riscv64::uentry::alloc_user_stack;

    let path = match copy_cstr_from_user(path_va) { Some(s) => s, None => return -14 };
    let argv = copy_strvec_from_user(argv_va);
    let envp = copy_strvec_from_user(envp_va);

    let fd = match vfs::open(&path, 0, 0) { fd if fd >= 0 => fd as usize, e => return e };
    let size = match vfs::fsize(fd) { Some(s) => s, None => { vfs::close(fd); return -2; } };
    let mut data = Vec::with_capacity(size);
    data.resize(size, 0u8);
    if vfs::read(fd, &mut data) != size as isize { vfs::close(fd); return -5; }
    vfs::close(fd);

    // ── binfmt_misc probe ──────────────────────────────────────────────────
    {
        let probe_len = data.len().min(BINFMT_PROBE_BYTES);
        let hdr_bytes = &data[..probe_len];

        let is_native_elf = data.len() >= 20
            && &data[0..4] == b"\x7fELF"
            && u16::from_le_bytes([data[18], data[19]]) == NATIVE_EM;

        if !is_native_elf && crate::fs::procfs_binfmt::is_globally_enabled() {
            if let Some((interp_path, flags)) = crate::fs::binfmt_misc::probe_header(hdr_bytes) {
                let open_bin = flags & crate::fs::binfmt_misc::FLAG_OPEN_BINARY != 0;
                let new_argv = prepend_interpreter(&interp_path, &argv, open_bin, &path);
                let new_argv_refs: Vec<&str> = new_argv.iter().map(|s| s.as_str()).collect();
                let envp_refs:     Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
                return do_execve_riscv_from_vecs(pid, &interp_path, &new_argv_refs, &envp_refs);
            }
        }
    }
    // ── end binfmt_misc probe ──────────────────────────────────────────────

    let hdr   = match elf::parse_elf_header(&data)          { Some(h) => h, None => return -8 };
    let phdrs = match elf::parse_phdrs_with_hdr(&data, &hdr) { Some(p) => p, None => return -8 };

    let new_root_ppn = alloc_root_page_table() >> 12;
    let new_cr3      = new_root_ppn << 12;

    let entry_va = match elf::load_elf_into(new_cr3, &data, &hdr, &phdrs) {
        Some(e) => e,
        None    => { pmm::free_page_table(new_cr3); return -12; }
    };
    let brk_base = elf::end_of_bss(&phdrs, 0);

    let (final_entry, interp_bias) =
        if let Some(interp_path) = crate::proc::dynlink::find_interp(&data) {
            match crate::proc::dynlink::load_interp(&interp_path) {
                Ok((ie, bias)) => (ie, bias),
                Err(e)         => { pmm::free_page_table(new_cr3); return e; }
            }
        } else {
            (entry_va, 0)
        };

    let user_sp_top = match alloc_user_stack(new_root_ppn) {
        Some(sp) => sp,
        None     => { pmm::free_page_table(new_cr3); return -12; }
    };

    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();

    let (initial_sp, new_vmas) = crate::auxv::build_stack(
        new_cr3, user_sp_top, &argv_refs, &envp_refs,
        &hdr, &phdrs, entry_va, interp_bias, brk_base,
    );

    let kstack_top = scheduler::with_proc(pid, |p| p.kstack_top).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        mmap::clear_vmas(p);
        crate::arch::riscv64::paging::free_user_page_table(p.user_satp);
    });

    rebuild_trap_frame_riscv(kstack_top, final_entry, initial_sp, 0);
    let trapframe_pa = kstack_top - TRAP_FRAME_SIZE;

    let new_ctx = crate::proc::context::Context {
        ra:  crate::proc::context::task_entry_trampoline as usize,
        sp:  trapframe_pa,
        s0:  0,
        ..crate::proc::context::Context::zero()
    };

    let old_handlers = scheduler::with_proc(pid, |p| p.signal_handlers.lock().clone()).unwrap();
    let vfork_parent = scheduler::with_proc(pid, |p| p.vfork_parent).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        p.user_satp       = new_cr3;
        p.pc              = final_entry;
        p.sp              = initial_sp;
        p.ctx             = new_ctx;
        p.trapframe_pa    = trapframe_pa;
        p.trapframe_virt  = TRAPFRAME_VADDR;
        p.brk_base        = brk_base;
        p.brk             = brk_base;
        p.vmas            = new_vmas;
        p.exe_path        = Some(path.clone());
        p.signal_handlers = alloc::sync::Arc::new(spin::Mutex::new(old_handlers.exec_reset()));
        p.pending_signals.clear();
        p.vfork_parent    = 0;
    });

    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }

    thread::set_run_state_cold(pid, final_entry, initial_sp);
    0
}

#[cfg(target_arch = "riscv64")]
fn do_execve_riscv_from_vecs(
    pid:   usize,
    path:  &str,
    argv:  &[&str],
    envp:  &[&str],
) -> isize {
    use crate::arch::riscv64::trap::{rebuild_trap_frame_riscv, TRAP_FRAME_SIZE};
    use crate::arch::riscv64::paging::alloc_root_page_table;
    use crate::arch::riscv64::uentry::alloc_user_stack;

    let fd = match vfs::open(path, 0, 0) { fd if fd >= 0 => fd as usize, e => return e };
    let size = match vfs::fsize(fd) { Some(s) => s, None => { vfs::close(fd); return -2; } };
    let mut data = Vec::with_capacity(size);
    data.resize(size, 0u8);
    if vfs::read(fd, &mut data) != size as isize { vfs::close(fd); return -5; }
    vfs::close(fd);

    let hdr   = match elf::parse_elf_header(&data)          { Some(h) => h, None => return -8 };
    let phdrs = match elf::parse_phdrs_with_hdr(&data, &hdr) { Some(p) => p, None => return -8 };

    let new_root_ppn = alloc_root_page_table() >> 12;
    let new_cr3      = new_root_ppn << 12;

    let entry_va = match elf::load_elf_into(new_cr3, &data, &hdr, &phdrs) {
        Some(e) => e,
        None    => { pmm::free_page_table(new_cr3); return -12; }
    };
    let brk_base = elf::end_of_bss(&phdrs, 0);

    let (final_entry, interp_bias) =
        if let Some(interp_path) = crate::proc::dynlink::find_interp(&data) {
            match crate::proc::dynlink::load_interp(&interp_path) {
                Ok((ie, bias)) => (ie, bias),
                Err(e)         => { pmm::free_page_table(new_cr3); return e; }
            }
        } else {
            (entry_va, 0)
        };

    let user_sp_top = match alloc_user_stack(new_root_ppn) {
        Some(sp) => sp,
        None     => { pmm::free_page_table(new_cr3); return -12; }
    };

    let (initial_sp, new_vmas) = crate::auxv::build_stack(
        new_cr3, user_sp_top, argv, envp,
        &hdr, &phdrs, entry_va, interp_bias, brk_base,
    );

    let kstack_top = scheduler::with_proc(pid, |p| p.kstack_top).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        mmap::clear_vmas(p);
        crate::arch::riscv64::paging::free_user_page_table(p.user_satp);
    });

    rebuild_trap_frame_riscv(kstack_top, final_entry, initial_sp, 0);
    let trapframe_pa = kstack_top - TRAP_FRAME_SIZE;

    let new_ctx = crate::proc::context::Context {
        ra:  crate::proc::context::task_entry_trampoline as usize,
        sp:  trapframe_pa,
        s0:  0,
        ..crate::proc::context::Context::zero()
    };

    let old_handlers = scheduler::with_proc(pid, |p| p.signal_handlers.lock().clone()).unwrap();
    let vfork_parent = scheduler::with_proc(pid, |p| p.vfork_parent).unwrap_or(0);

    scheduler::with_proc_mut(pid, |p, _pl| {
        p.user_satp       = new_cr3;
        p.pc              = final_entry;
        p.sp              = initial_sp;
        p.ctx             = new_ctx;
        p.trapframe_pa    = trapframe_pa;
        p.trapframe_virt  = TRAPFRAME_VADDR;
        p.brk_base        = brk_base;
        p.brk             = brk_base;
        p.vmas            = new_vmas;
        p.exe_path        = Some(String::from(path));
        p.signal_handlers = alloc::sync::Arc::new(spin::Mutex::new(old_handlers.exec_reset()));
        p.pending_signals.clear();
        p.vfork_parent    = 0;
    });

    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }
    thread::set_run_state_cold(pid, final_entry, initial_sp);
    0
}

pub fn sys_execve(path_va: usize, argv_va: usize, envp_va: usize) -> isize {
    let pid = scheduler::current_pid();
    #[cfg(target_arch = "x86_64")]
    { do_execve(pid, path_va, argv_va, envp_va) }
    #[cfg(target_arch = "riscv64")]
    { do_execve_riscv(pid, path_va, argv_va, envp_va) }
}

fn copy_cstr_from_user(va: usize) -> Option<String> {
    let mut buf = [0u8; 4096];
    copy_from_user(va, &mut buf).ok()?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).ok().map(String::from)
}

/// Public, safe variant of [`copy_cstr_from_user`] used by fs syscalls
/// that want to keep a single name across the tree.
pub fn read_cstr_safe(va: usize) -> Option<String> {
    copy_cstr_from_user(va)
}

fn copy_strvec_from_user(vec_va: usize) -> Vec<String> {
    let mut out = Vec::new();
    if vec_va == 0 { return out; }
    let mut ptr_va = vec_va;
    loop {
        let mut slot = [0u8; 8];
        if copy_from_user(ptr_va, &mut slot).is_err() { break; }
        let p = usize::from_ne_bytes(slot.try_into().unwrap());
        if p == 0 { break; }
        if let Some(s) = copy_cstr_from_user(p) { out.push(s); }
        ptr_va += 8;
    }
    out
}

#[cfg(target_arch = "x86_64")]
fn alloc_map_stack(_cr3: usize, _stack_top: usize) -> usize {
    // GUESS: temporary stub so the parser reaches EOF; real body written in a later commit.
    unimplemented!("alloc_map_stack pending design - see sweep step 5")
}
