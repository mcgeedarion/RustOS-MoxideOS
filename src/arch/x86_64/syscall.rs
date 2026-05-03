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
/// Must be extern "C" #[no_mangle] — invoked directly from naked asm.
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
        // Zero the guard inside the lock: fire-once semantics.
        if pcb.child_tid_va != 0 { pcb.child_tid_va = 0; }
        r
    };
    scheduler::procs_unlock();

    // CLONE_CHILD_SETTID: write child PID into child's userspace.
    // SAFETY: tid_va validated at clone3 call-site; child CR3 is live.
    if tid_va > 0x1000 && tid_va < 0x0000_7FFF_FFFF_F000 {
        unsafe { (tid_va as *mut u32).write_volatile(tid_val); }
    }

    // CLONE_SETTLS: re-apply FS.base via WRMSR(IA32_FS_BASE = 0xC000_0100).
    // switch_to handles this on context switches, but a child that was
    // enqueued and never switched still needs it applied on first run.
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
///
/// do_fork / sys_clone3 sets `child.ctx.rip = sysret_trampoline as usize`.
/// The scheduler's switch_to jmps here on the child's first run.
/// RSP points at the base of the SyscallFrame (17 x 8 = 136 bytes).
///
/// Calls child_first_run_hook BEFORE any register pops so the hook
/// can safely read the frame and access the child's page tables.
#[naked]
pub unsafe extern "C" fn sysret_trampoline() {
    core::arch::asm!(
        // Align RSP to 16 bytes for the System V ABI before the call.
        // Frame = 136 bytes => RSP % 16 == 8; subtract 8 to align.
        "sub rsp, 8",
        "call child_first_run_hook",
        "add rsp, 8",
        // Pop SyscallFrame in push order (r15 was pushed first = lowest addr)
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop rax",      // 0: child return value written by do_fork
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop r10",
        "pop r8",
        "pop r9",
        "pop rcx",      // user RIP  -> RCX for SYSRETQ
        "pop r11",      // user RFLAGS -> R11 for SYSRETQ
        "pop rsp",      // restore user RSP
        "swapgs",
        "sysretq",
        options(noreturn)
    );
}

/// set_tid_address(tidptr_va) -> current TID  [NR 218]
///
/// Stores tidptr_va in pcb.clear_child_tid_va.  On exit the kernel
/// zeroes that word and futex_wakes it so pthread_join unblocks.
pub fn sys_set_tid_address(tidptr_va: usize) -> isize {
    let pid = scheduler::current_pid();
    if pid == 0 { return -3; } // ESRCH
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
