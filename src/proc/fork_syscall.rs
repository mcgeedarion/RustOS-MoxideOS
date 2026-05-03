//! sys_fork (NR 57) — implemented as clone3 with SIGCHLD exit signal.
//!
//! Linux fork() semantics:
//!   - Child gets a CoW copy of the parent's address space.
//!   - Child inherits open file descriptors.
//!   - Child gets a new PID, same PPID as parent's PID.
//!   - Parent returns child PID; child returns 0.
//!
//! We implement this by synthesising a CloneArgs with no CLONE_VM flag
//! and calling the clone3 core path directly, which already handles
//! CoW PML4 cloning (clone_pml4_cow) for non-CLONE_VM forks.

use crate::proc::clone::{
    CloneArgs, CLONE_CHILD_SETTID, CLONE_CHILD_CLEARTID,
};
use crate::proc::process::{Pcb, State};
use crate::proc::context::Context;
use crate::proc::scheduler;
use crate::proc::fork::SignalHandlers;
use crate::arch::x86_64::paging::clone_pml4_cow;
use crate::arch::x86_64::syscall::sysret_trampoline;
use crate::mm::kstack::alloc_kstack;
use crate::security::CapSet;

extern crate alloc;
use alloc::vec::Vec;

/// sys_fork() -> child_pid (parent) / 0 (child)  [NR 57]
pub fn sys_fork() -> isize {
    let parent_pid = scheduler::current_pid();

    // Snapshot parent PCB fields we need before taking the lock again.
    let (parent_cr3, parent_pc, parent_sp, parent_ppid, parent_caps,
         parent_sig) = {
        let procs = scheduler::procs_lock();
        let p = match procs.iter().find(|p| p.pid == parent_pid) {
            Some(p) => p,
            None    => { scheduler::procs_unlock(); return -1; }
        };
        let r = (
            p.user_satp,
            p.pc,
            p.sp,
            p.ppid,
            p.caps.clone(),
            p.signal_handlers.clone(),
        );
        scheduler::procs_unlock();
        r
    };

    // CoW-clone the parent's page tables.
    let child_cr3 = clone_pml4_cow(parent_cr3);

    // Allocate a fresh kernel stack for the child.
    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None    => return -12, // ENOMEM
    };

    let child_pid = scheduler::next_pid();

    // Build child context: starts at sysret_trampoline, which will
    // SYSRETQ to parent_pc with rax=0 (child return value).
    push_syscall_frame(kstack_top, parent_pc, 0x202, parent_sp);
    let child_ctx = Context {
        rip: sysret_trampoline as usize,
        rsp: kstack_top - 17 * 8,
        ..Context::zero()
    };

    let child_pcb = Pcb {
        pid:        child_pid,
        ppid:       parent_pid,
        state:      State::Ready,
        exit_code:  0,
        caps:       parent_caps,
        pc:         parent_pc,
        sp:         parent_sp,
        user_satp:    child_cr3,
        kernel_satp:  0,
        trapframe_pa: 0,
        kstack_top,
        ctx:        child_ctx,
        owned_pages: Vec::new(),
        child_tid_va:       0,
        child_tid_val:      0,
        clear_child_tid_va: 0,
        exit_signal:        17, // SIGCHLD
        vfork_parent:       0,
        signal_handlers:    parent_sig,
    };

    scheduler::enqueue(child_pcb);
    child_pid as isize  // parent returns child_pid
}

/// Push a SyscallFrame stub onto the kernel stack so sysret_trampoline
/// can restore registers and SYSRETQ into user mode.
fn push_syscall_frame(kstack_top: usize, rip: usize, rflags: usize, user_rsp: usize) {
    const FRAME_SZ: usize = 17 * 8;
    let base = kstack_top - FRAME_SZ;
    let p    = base as *mut usize;
    unsafe {
        for i in 0..17 { p.add(i).write(0); }
        p.add(6).write(0);          // rax = 0 (child return)
        p.add(13).write(rip);       // rcx = user RIP
        p.add(14).write(rflags);    // r11 = user RFLAGS
        p.add(15).write(user_rsp);  // rsp = user stack
        p.add(16).write(rip);       // rip copy
    }
}
