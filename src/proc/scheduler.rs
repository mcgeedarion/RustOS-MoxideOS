//! Round-robin run queue and voluntary context-switch scheduler.
//! Single-CPU. All mutations go through a spin-locked SchedState.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::proc::process::{Pcb, State};
use crate::proc::context::switch_to;

struct SchedState { procs: Vec<Pcb>, current: usize, next_pid: usize }
static mut SCHED: SchedState = SchedState { procs: Vec::new(), current: 0, next_pid: 1 };
static SCHED_LOCK: AtomicUsize = AtomicUsize::new(0);

fn sched_lock()   { while SCHED_LOCK.compare_exchange(0,1,Ordering::Acquire,Ordering::Relaxed).is_err() { core::hint::spin_loop(); } }
fn sched_unlock() { SCHED_LOCK.store(0, Ordering::Release); }

pub fn current_pid() -> usize {
    sched_lock();
    let p = unsafe { if SCHED.procs.is_empty() { 0 } else { SCHED.procs[SCHED.current].pid } };
    sched_unlock(); p
}

pub fn next_pid() -> usize {
    sched_lock();
    let p = unsafe { let n = SCHED.next_pid; SCHED.next_pid += 1; n };
    sched_unlock(); p
}

pub fn enqueue(pcb: Pcb) {
    sched_lock();
    unsafe { SCHED.procs.push(pcb); }
    sched_unlock();
}

/// Borrow the run-queue for reading/patching. Caller MUST call procs_unlock.
pub fn procs_lock() -> &'static mut Vec<Pcb> {
    sched_lock();
    unsafe { &mut SCHED.procs }
}

pub fn procs_unlock() { sched_unlock(); }

/// Block current process and yield to the next ready task (CLONE_VFORK).
pub fn suspend_current_until_child_exec(_child_pid: usize) {
    sched_lock();
    unsafe { SCHED.procs[SCHED.current].state = State::Blocked; }
    sched_unlock();
    schedule();
}

/// Mark pid Ready (called by vfork child on exec/exit).
pub fn wake_pid(pid: usize) {
    sched_lock();
    unsafe {
        if let Some(p) = SCHED.procs.iter_mut().find(|p| p.pid == pid) {
            if p.state == State::Blocked { p.state = State::Ready; }
        }
    }
    sched_unlock();
}

/// Round-robin: save current context and switch to next Ready task.
pub fn schedule() {
    sched_lock();
    let len = unsafe { SCHED.procs.len() };
    if len == 0 { sched_unlock(); return; }
    let cur = unsafe { SCHED.current };
    let mut nxt = (cur + 1) % len;
    let mut found = false;
    for _ in 0..len {
        if unsafe { SCHED.procs[nxt].state == State::Ready } { found = true; break; }
        nxt = (nxt + 1) % len;
    }
    if !found || nxt == cur { sched_unlock(); return; }
    unsafe {
        if SCHED.procs[cur].state == State::Running { SCHED.procs[cur].state = State::Ready; }
        SCHED.procs[nxt].state = State::Running;
        SCHED.current = nxt;
    }
    let old_ctx = unsafe { &mut SCHED.procs[cur].ctx as *mut _ };
    let new_ctx = unsafe { &    SCHED.procs[nxt].ctx as *const _ };
    let new_cr3 = unsafe { SCHED.procs[nxt].user_satp };
    sched_unlock();
    if new_cr3 != 0 {
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) new_cr3, options(nostack)); }
    }
    unsafe { switch_to(old_ctx, new_ctx); }
}
