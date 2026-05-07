//! sys_fork (NR 57) — implemented using clone_for_fork (CoW + VMA clone).

extern crate alloc;
use alloc::vec::Vec;
use crate::mm::kstack::alloc_kstack;
use crate::proc::context::Context;
use crate::proc::cow_fault::clone_for_fork;
use crate::proc::fork::SignalHandlers;
use crate::proc::process::{Pcb, State};
use crate::proc::scheduler;
use crate::security::CapSet;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::sysret_trampoline;

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
fn sysret_trampoline() {}

/// sys_fork() -> child_pid (parent) / 0 (child)  [NR 57]
pub fn sys_fork() -> isize {
    let parent_pid = scheduler::current_pid();

    let (parent_cr3, parent_pc, parent_sp, parent_caps, parent_sig, parent_vmas,
         parent_next_va, parent_brk, parent_exe) =
        scheduler::with_proc(parent_pid, |p| (
            p.user_satp,
            p.pc,
            p.sp,
            p.caps.clone(),
            p.signal_handlers.clone(),
            p.vmas.clone(),
            p.next_va,
            p.brk,
            p.exe_path.clone(),
        )).unwrap_or((
            0, 0, 0,
            CapSet::empty(),
            SignalHandlers::default(),
            Vec::new(),
            Pcb::INITIAL_NEXT_VA,
            Pcb::INITIAL_BRK,
            None,
        ));

    if parent_cr3 == 0 { return -1; }

    let child_pid = scheduler::next_pid();
    let child_cr3 = clone_for_fork(parent_pid, child_pid, parent_cr3);

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None => {
            // Free the child page table that clone_for_fork already allocated
            // to prevent a permanent physical memory leak on OOM.
            if child_cr3 != 0 {
                unsafe { crate::proc::exec::free_child_address_space(child_cr3); }
            }
            return -12;
        }
    };

    push_syscall_frame(kstack_top, parent_pc, 0x202, parent_sp);
    let child_ctx = Context {
        rip: sysret_trampoline as usize,
        rsp: kstack_top - 17 * 8,
        ..Context::zero()
    };

    let child_pcb = Pcb {
        pid:   child_pid,
        ppid:  parent_pid,
        tgid:  child_pid,
        state: State::Ready,
        exit_code:  0,
        caps:       parent_caps,
        pc:         parent_pc,
        sp:         parent_sp,
        user_satp:  child_cr3,
        vmas:       parent_vmas,
        next_va:    parent_next_va,
        brk:        parent_brk,
        kstack_top,
        ctx:        child_ctx,
        child_tid_va:       0,
        child_tid_val:      child_pid as u32,
        clear_child_tid_va: 0,
        exit_signal:        17,
        vfork_parent:       0,
        signal_handlers:    parent_sig,
        exe_path:           parent_exe,
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
        p.add(6).write(0);         // rax = 0  (child returns 0 from fork)
        p.add(13).write(rip);      // rcx = user RIP
        p.add(14).write(rflags);   // r11 = RFLAGS
        p.add(15).write(user_rsp); // user RSP
        p.add(16).write(rip);
    }
}
