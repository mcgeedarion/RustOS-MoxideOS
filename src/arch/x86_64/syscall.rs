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
                "mov ecx, 0xC0000100",
                "mov eax, {lo:e}",
                "mov edx, {hi:e}",
                "wrmsr",
                lo = in(reg) fs_base as u32,
                hi = in(reg) (fs_base >> 32) as u32,
                options(nostack)
            );
        }
    }
}

/// syscall_setup: configure SYSCALL/SYSRET MSRs.
/// MSR_STAR[47:32] = kernel CS selector (0x08)
/// MSR_STAR[63:48] = SYSRET CS base (0x18; +3 = user CS 0x1B, +8+3 = user SS 0x23)
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

/// sys_set_tid_address(tidptr_va)  [NR 218]
pub fn sys_set_tid_address(tidptr_va: usize) -> isize {
    let pid = scheduler::current_pid();
    let procs = scheduler::procs_lock();
    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
        p.clear_child_tid_va = tidptr_va;
    }
    scheduler::procs_unlock();
    pid as isize
}

/// sys_arch_prctl(code, addr)  [NR 158]
/// Handles ARCH_SET_FS (0x1002) and ARCH_GET_FS (0x1003).
/// ARCH_SET_FS is the very first syscall musl makes to set up TLS.
pub fn sys_arch_prctl(code: i32, addr: usize) -> isize {
    const ARCH_SET_GS: i32 = 0x1001;
    const ARCH_SET_FS: i32 = 0x1002;
    const ARCH_GET_FS: i32 = 0x1003;
    const ARCH_GET_GS: i32 = 0x1004;

    match code {
        ARCH_SET_FS => {
            // Write IA32_FS_BASE MSR (0xC000_0100).
            unsafe {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0100u32,
                    in("eax") addr as u32,
                    in("edx") (addr >> 32) as u32,
                    options(nostack)
                );
            }
            // Also update saved fs_base in PCB so context switch preserves it.
            let pid = scheduler::current_pid();
            let procs = scheduler::procs_lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.ctx.fs_base = addr;
            }
            scheduler::procs_unlock();
            0
        }
        ARCH_GET_FS => {
            if addr < 0x1000 { return -14; } // EFAULT
            let pid = scheduler::current_pid();
            let procs = scheduler::procs_lock();
            let fs = procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.ctx.fs_base);
            scheduler::procs_unlock();
            unsafe { (addr as *mut usize).write_volatile(fs); }
            0
        }
        ARCH_SET_GS => {
            // Set IA32_GS_BASE. Rare but accepted.
            unsafe {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0101u32,
                    in("eax") addr as u32,
                    in("edx") (addr >> 32) as u32,
                    options(nostack)
                );
            }
            0
        }
        ARCH_GET_GS => -22, // EINVAL — not tracked
        _           => -22, // EINVAL
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
        "mov [rsp + 13*8], rcx",  // user RIP
        "mov [rsp + 14*8], r11",  // user RFLAGS
        "mov rax, [gs:8]",
        "mov [rsp + 15*8], rax",  // user RSP
        "mov [rsp + 16*8], rcx",  // rip copy
        "mov rdi, rsp",
        "call syscall_rust_entry",
        "mov r11, [rsp + 14*8]",
        "mov rcx, [rsp + 13*8]",
        "mov rsp, [rsp + 15*8]",
        "swapgs",
        "sysretq",
        frame_size = const core::mem::size_of::<SyscallFrame>(),
        options(noreturn)
    );
}

/// Rust-side syscall dispatcher — called from syscall_asm_entry.
#[no_mangle]
pub extern "C" fn syscall_rust_entry(frame: &mut SyscallFrame) {
    let nr = frame.rax;

    // NR 59: execve — needs mutable frame pointer for patching.
    if nr == 59 {
        let ret = crate::proc::exec::sys_execve(
            frame.rdi, frame.rsi, frame.rdx, frame);
        frame.rax = ret as usize;
        crate::proc::signal::check_pending_signal(frame);
        return;
    }

    // NR 15: rt_sigreturn — restores full register state from signal stack.
    if nr == 15 {
        crate::proc::signal::sys_rt_sigreturn(frame);
        return;
    }

    let ret = crate::syscall::dispatch(
        nr,
        frame.rdi, frame.rsi, frame.rdx,
        frame.r10, frame.r8,  frame.r9,
    );
    frame.rax = ret as usize;
    crate::proc::signal::check_pending_signal(frame);
}

/// Naked trampoline used as the initial RIP for newly created tasks.
/// On first schedule the context switch jumps here; we call
/// child_first_run_hook (CLONE_CHILD_SETTID / FS.base) then SYSRETQ.
#[naked]
#[no_mangle]
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
