//! sys_fork (NR 57) — implemented using clone_for_fork (CoW + VMA clone).
//!
//! Linux fork() semantics:
//!   - Child gets a CoW copy of the parent's address space.
//!   - Child inherits open file descriptors.
//!   - Child gets a new PID, ppid = parent's PID.
//!   - Parent returns child_pid; child returns 0.

use crate::proc::process::{Pcb, State};
use crate::proc::context::Context;
use crate::proc::scheduler;
use crate::proc::fork::SignalHandlers;
// Use clone_for_fork: clones PML4 CoW + mirrors VMA list under child pid.
use crate::proc::cow_fault::clone_for_fork;
use crate::arch::x86_64::syscall::sysret_trampoline;
use crate::mm::kstack::alloc_kstack;
use crate::security::CapSet;

extern crate alloc;
use alloc::vec::Vec;

/// sys_fork() -> child_pid (parent) / 0 (child)  [NR 57]
pub fn sys_fork() -> isize {
    let parent_pid = scheduler::current_pid();

    let (parent_cr3, parent_pc, parent_sp, parent_caps, parent_sig) = {
        let procs = scheduler::procs_lock();
        let p = match procs.iter().find(|p| p.pid == parent_pid) {
            Some(p) => p,
            None    => { scheduler::procs_unlock(); return -1; }
        };
        let r = (
            p.user_satp,
            p.pc,
            p.sp,
            p.caps.clone(),
            p.signal_handlers.clone(),
        );
        scheduler::procs_unlock();
        r
    };

    let child_pid = scheduler::next_pid();

    // CoW-clone PML4 AND mirror VMA list to child_pid.
    // clone_for_fork marks parent's writable pages read-only with COW_BIT;
    // the first write in either process triggers handle_cow_fault.
    let child_cr3 = clone_for_fork(parent_pid, child_pid, parent_cr3);

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None    => return -12,
    };

    // Build child context: sysret_trampoline → SYSRETQ to parent_pc, rax=0.
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
        child_tid_val:      child_pid as u32,
        clear_child_tid_va: 0,
        exit_signal:        17, // SIGCHLD
        vfork_parent:       0,
        signal_handlers:    parent_sig,
    };

    scheduler::enqueue(child_pcb);
    child_pid as isize
}

fn push_syscall_frame(kstack_top: usize, rip: usize, rflags: usize, user_rsp: usize) {
    const FRAME_SZ: usize = 17 * 8;
    let base = kstack_top - FRAME_SZ;
    let p    = base as *mut usize;
    unsafe {
        for i in 0..17 { p.add(i).write(0); }
        p.add(6).write(0);          // rax = 0 (child returns 0)
        p.add(13).write(rip);       // rcx = user RIP
        p.add(14).write(rflags);    // r11 = RFLAGS
        p.add(15).write(user_rsp);  // user RSP
        p.add(16).write(rip);
    }
}
