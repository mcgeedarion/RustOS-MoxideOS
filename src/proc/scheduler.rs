//! Round-robin run queue and voluntary context-switch scheduler.
//! Single-CPU. All mutations go through a SpinMutex<SchedState>.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::arch::{Arch, api::{Paging, Cpu}};
use crate::proc::process::{Pcb, State};
use crate::proc::context::switch_to;

// ── State ─────────────────────────────────────────────────────────────────

struct SchedState {
    procs:    Vec<Pcb>,
    current:  usize,
    next_pid: usize,
}

static SCHED: Mutex<SchedState> = Mutex::new(SchedState {
    procs:    Vec::new(),
    current:  0,
    next_pid: 1,
});

// ── Simple queries ────────────────────────────────────────────────────────

pub fn current_pid() -> usize {
    let s = SCHED.lock();
    if s.procs.is_empty() { 0 } else { s.procs[s.current].pid }
}

pub fn next_pid() -> usize {
    let mut s = SCHED.lock();
    let n = s.next_pid;
    s.next_pid += 1;
    n
}

pub fn ppid_of(pid: usize) -> usize {
    let s = SCHED.lock();
    s.procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.ppid)
}

// ── Queue management ──────────────────────────────────────────────────────

pub fn enqueue(pcb: Pcb) {
    SCHED.lock().procs.push(pcb);
}

/// Run `f` with exclusive access to the process list.
/// Replaces the old procs_lock() / procs_unlock() pair with a scoped
/// RAII guard so callers can never forget to release the lock.
pub fn with_procs<R>(f: impl FnOnce(&mut Vec<Pcb>) -> R) -> R {
    f(&mut SCHED.lock().procs)
}

// ── State transitions ─────────────────────────────────────────────────────

pub fn suspend_current_until_child_exec(_child_pid: usize) {
    {
        let mut s = SCHED.lock();
        let cur = s.current;
        if !s.procs.is_empty() {
            s.procs[cur].state = State::Blocked;
        }
    }
    schedule();
}

pub fn wake_pid(pid: usize) {
    let mut s = SCHED.lock();
    if let Some(p) = s.procs.iter_mut().find(|p| p.pid == pid) {
        if p.state == State::Blocked {
            p.state = State::Ready;
        }
    }
}

pub fn fix_current_after_remove(removed_idx: usize) {
    let mut s = SCHED.lock();
    let len = s.procs.len();
    if len == 0 { s.current = 0; return; }
    if removed_idx < s.current { s.current -= 1; }
    if s.current >= len        { s.current  = len - 1; }
}

// ── Scheduler ─────────────────────────────────────────────────────────────

/// Round-robin: find the next Ready task, switch context to it.
/// Does nothing if there is only one runnable task or no tasks.
pub fn schedule() {
    // Phase 1: under the lock, decide who to switch to and capture raw
    // pointers to the two Context objects.  Raw ptrs are valid for the
    // lifetime of SCHED (static), so using them after dropping the guard
    // is sound as long as we hold no other reference into SCHED.procs.
    let (old_ctx, new_ctx, new_cr3) = {
        let mut s = SCHED.lock();
        let len = s.procs.len();
        if len == 0 { return; }

        let cur = s.current;
        let mut nxt = (cur + 1) % len;
        let mut found = false;

        for _ in 0..len {
            if s.procs[nxt].state == State::Ready {
                found = true;
                break;
            }
            nxt = (nxt + 1) % len;
        }

        if !found || nxt == cur { return; }

        if s.procs[cur].state == State::Running {
            s.procs[cur].state = State::Ready;
        }
        s.procs[nxt].state = State::Running;
        s.current = nxt;

        let old_ctx = &mut s.procs[cur].ctx as *mut _;
        let new_ctx = &    s.procs[nxt].ctx as *const _;
        let new_cr3 = s.procs[nxt].user_satp;
        (old_ctx, new_ctx, new_cr3)
    }; // lock released here

    // Phase 2: address-space switch + context switch (no lock held).
    let cur_cr3 = <Arch as Paging>::kernel_cr3();
    if new_cr3 != 0 && new_cr3 != cur_cr3 {
        <Arch as Paging>::load_cr3(new_cr3);
    }
    unsafe { switch_to(old_ctx, new_ctx); }
}
