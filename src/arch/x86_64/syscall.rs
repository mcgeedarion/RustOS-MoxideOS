//! x86-64 SYSCALL/SYSRET entry and per-task first-run hooks.

use crate::proc::scheduler;
use crate::uaccess::{copy_to_user, validate_user_ptr};

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

    let (tid_va, tid_val, fs_base) = scheduler::with_procs(|procs| {
        match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => {
                let r = (p.child_tid_va, p.child_tid_val, p.ctx.fs_base);
                p.child_tid_va = 0; // consume: only write once
                r
            }
            None => (0, 0, 0),
        }
    });

    // CLONE_CHILD_SETTID: write the child's own pid into the tid word.
    if tid_va != 0 {
        let _ = copy_to_user(tid_va, &tid_val.to_ne_bytes());
    }

    // CLONE_SETTLS: restore FS.base for TLS.
    if fs_base != 0 {
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") 0xC000_0100u32,
                in("eax") fs_base as u32,
                in("edx") (fs_base >> 32) as u32,
                options(nostack)
            );
        }
    }
}

/// syscall_setup: configure SYSCALL/SYSRET MSRs.
pub fn syscall_setup() {
    use crate::arch::x86_64::cpu::{wrmsr, rdmsr, MSR_EFER, MSR_STAR, MSR_LSTAR, MSR_FMASK};
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | 1);
        wrmsr(MSR_STAR, 0x001B_0008u64 << 32);
        wrmsr(MSR_LSTAR, syscall_asm_entry as u64);
        // FMASK: clear IF (bit 9), TF (bit 8), DF (bit 10), and AC (bit 18)
        // on SYSCALL entry so the kernel cannot be single-stepped from user
        // mode and alignment-check traps don't fire in kernel context.
        // This matches Linux's value of 0x47700.
        //
        // Bit breakdown:
        //   0x00200 = IF  (interrupt flag)     — must be cleared
        //   0x00100 = TF  (trap/single-step)   — prevent user single-step of kernel
        //   0x00400 = DF  (direction flag)      — kernel assumes DF=0 (ABI)
        //   0x40000 = AC  (alignment check)    — avoid #AC in kernel
        //   0x04000 = NT  (nested task flag)    — should not be set in syscall
        //   0x03000 = IOPL bits                 — prevent IOPL escalation
        wrmsr(MSR_FMASK, 0x47700);
    }
}

/// sys_set_tid_address(tidptr_va)  [NR 218]
pub fn sys_set_tid_address(tidptr_va: usize) -> isize {
    let pid = scheduler::current_pid();
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.clear_child_tid_va = tidptr_va;
        }
    });
    pid as isize
}

// Provided by the assembly stub in arch/x86_64/entry.S (or global_asm! block).
extern "C" { pub fn syscall_asm_entry(); }
