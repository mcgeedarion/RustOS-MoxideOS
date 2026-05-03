//! x86-64 SYSCALL/SYSRET entry and per-task first-run hooks.

use crate::proc::scheduler;

/// Registers pushed onto the kernel stack by the SYSCALL entry stub.
#[repr(C)]
pub struct SyscallFrame {
    pub r15: usize, pub r14: usize, pub r13: usize, pub r12: usize,
    pub rbp: usize, pub rbx: usize,
    pub rax: usize,
    pub rdi: usize, pub rsi: usize, pub rdx: usize,
    pub r10: usize, pub r8:  usize, pub r9:  usize,
    pub rcx: usize,  // user RIP (set by SYSCALL hardware)
    pub r11: usize,  // user RFLAGS (set by SYSCALL hardware)
    pub rsp: usize,  // user stack pointer
    pub rip: usize,  // = rcx copy, patched by execve
}

/// Called by sysret_trampoline on a child's very first SYSRETQ.
/// Implements CLONE_CHILD_SETTID and CLONE_SETTLS (FS.base restore).
#[no_mangle]
pub extern "C" fn child_first_run_hook() {
    let pid = scheduler::current_pid();
    if pid == 0 { return; }

    let (tid_va, tid_val, fs_base) = {
        let procs = scheduler::procs_lock();
        let pcb = match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => { scheduler::procs_unlock(); return; }
        };
        let r = (pcb.child_tid_va, pcb.child_tid_val, pcb.ctx.fs_base);
        if pcb.child_tid_va != 0 { pcb.child_tid_va = 0; }
        r
    };
    scheduler::procs_unlock();

    if tid_va > 0x1000 && tid_va < 0x0000_7FFF_FFFF_F000 {
        unsafe { (tid_va as *mut u32).write_volatile(tid_val); }
    }

    if fs_base != 0 {
        unsafe {
            core::arch::asm!(
                "mov rax, {0}",
                "mov rdx, {0}",
                "shr rdx, 32",
                "mov rcx, 0xC0000100",
                "wrmsr",
                in(reg) fs_base,
                out("rax") _, out("rcx") _, out("rdx") _,
                options(nostack, nomem)
            );
        }
    }
}

/// Entry point for newly-forked child tasks.
/// do_fork / sys_clone3 sets `child.ctx.rip = sysret_trampoline as usize`.
#[naked]
pub unsafe extern "C" fn sysret_trampoline() {
    core::arch::asm!(
        "sub rsp, 8",
        "call child_first_run_hook",
        "add rsp, 8",
        "mov r15, [rsp + 0*8]",
        "mov r14, [rsp + 1*8]",
        "mov r13, [rsp + 2*8]",
        "mov r12, [rsp + 3*8]",
        "mov rbp, [rsp + 4*8]",
        "mov rbx, [rsp + 5*8]",
        "mov rax, [rsp + 6*8]",
        "mov rdi, [rsp + 7*8]",
        "mov rsi, [rsp + 8*8]",
        "mov rdx, [rsp + 9*8]",
        "mov r10, [rsp + 10*8]",
        "mov r8,  [rsp + 11*8]",
        "mov r9,  [rsp + 12*8]",
        "mov rcx, [rsp + 13*8]",
        "mov r11, [rsp + 14*8]",
        "mov rsp, [rsp + 15*8]",
        "swapgs",
        "sysretq",
        options(noreturn)
    );
}

/// set_tid_address(tidptr_va) -> current TID  [NR 218]
pub fn sys_set_tid_address(tidptr_va: usize) -> isize {
    let pid = scheduler::current_pid();
    if pid == 0 { return -3; }
    let procs = scheduler::procs_lock();
    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
        p.clear_child_tid_va = tidptr_va;
    }
    scheduler::procs_unlock();
    pid as isize
}

/// Called from exit / exit_group for `pid`.
/// Zeroes the clear_child_tid_va word + futex_wake(addr, 1).
pub fn exit_clear_child_tid(pid: usize) {
    let va = {
        let procs = scheduler::procs_lock();
        let v = procs.iter().find(|p| p.pid == pid)
                     .map_or(0, |p| p.clear_child_tid_va);
        scheduler::procs_unlock();
        v
    };
    if va == 0 { return; }
    if va > 0x1000 && va < 0x0000_7FFF_FFFF_F000 {
        unsafe { (va as *mut u32).write_volatile(0); }
    }
    crate::proc::futex::futex_wake_addr(va, 1);
}

// ── SYSCALL entry ─────────────────────────────────────────────────────────

/// Called from syscall_asm_entry with a pointer to the SyscallFrame.
/// Dispatches to the appropriate handler, then runs check_pending_signal.
///
/// NR 15 (rt_sigreturn): restores frame in-place; skip check_pending.
/// NR 59 (execve):       patches frame in-place for new entry point;
///                       on success skip check_pending (new process is clean).
#[no_mangle]
pub extern "C" fn syscall_rust_entry(frame: *mut SyscallFrame) {
    let frame = unsafe { &mut *frame };
    let nr = frame.rax;
    let a  = frame.rdi;
    let b  = frame.rsi;
    let c  = frame.rdx;
    let d  = frame.r10;
    let e  = frame.r8;
    let f  = frame.r9;

    if nr == 15 {
        let ret = crate::proc::signal::sys_rt_sigreturn(frame);
        frame.rax = ret as usize;
        return;
    }

    if nr == 59 {
        // execve: needs frame pointer to patch rip/rsp in-place for SYSRETQ
        let ret = crate::proc::exec::sys_execve(a, b, c, frame);
        frame.rax = ret as usize;
        // On success frame.rip/rsp/rax already set by do_execve; skip check_pending
        // (the new process starts clean — no inherited signals on exec boundary).
        if ret == 0 { return; }
        crate::proc::signal::check_pending_signal(frame);
        return;
    }

    let ret = crate::syscall::dispatch(nr, a, b, c, d, e, f);
    frame.rax = ret as usize;

    crate::proc::signal::check_pending_signal(frame);
}

/// Write the MSRs that configure the SYSCALL/SYSRET instruction pair.
pub fn syscall_setup() {
    use crate::arch::x86_64::cpu::{wrmsr, rdmsr, MSR_EFER, MSR_STAR, MSR_LSTAR, MSR_FMASK};
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | 1);
        wrmsr(MSR_STAR, 0x001B_0008u64 << 32);
        wrmsr(MSR_LSTAR, syscall_asm_entry as u64);
        wrmsr(MSR_FMASK, 0x200);
    }
}

/// Naked SYSCALL entry — address loaded into LSTAR by syscall_setup().
#[naked]
#[no_mangle]
pub unsafe extern "C" fn syscall_asm_entry() {
    core::arch::asm!(
        "swapgs",
        "mov [gs:8], rsp",
        "mov rsp, [gs:0]",
        "sub rsp, {frame_size}",
        "mov [rsp + 0*8],  r15",
        "mov [rsp + 1*8],  r14",
        "mov [rsp + 2*8],  r13",
        "mov [rsp + 3*8],  r12",
        "mov [rsp + 4*8],  rbp",
        "mov [rsp + 5*8],  rbx",
        "mov [rsp + 6*8],  rax",
        "mov [rsp + 7*8],  rdi",
        "mov [rsp + 8*8],  rsi",
        "mov [rsp + 9*8],  rdx",
        "mov [rsp + 10*8], r10",
        "mov [rsp + 11*8], r8",
        "mov [rsp + 12*8], r9",
        "mov [rsp + 13*8], rcx",
        "mov [rsp + 14*8], r11",
        "mov rax, [gs:8]",
        "mov [rsp + 15*8], rax",
        "mov [rsp + 16*8], rcx",
        "mov rdi, rsp",
        "call syscall_rust_entry",
        "mov r15, [rsp + 0*8]",
        "mov r14, [rsp + 1*8]",
        "mov r13, [rsp + 2*8]",
        "mov r12, [rsp + 3*8]",
        "mov rbp, [rsp + 4*8]",
        "mov rbx, [rsp + 5*8]",
        "mov rax, [rsp + 6*8]",
        "mov rdi, [rsp + 7*8]",
        "mov rsi, [rsp + 8*8]",
        "mov rdx, [rsp + 9*8]",
        "mov r10, [rsp + 10*8]",
        "mov r8,  [rsp + 11*8]",
        "mov r9,  [rsp + 12*8]",
        "mov rcx, [rsp + 13*8]",
        "mov r11, [rsp + 14*8]",
        "mov rsp, [rsp + 15*8]",
        "swapgs",
        "sysretq",
        frame_size = const core::mem::size_of::<SyscallFrame>(),
        options(noreturn)
    );
}
