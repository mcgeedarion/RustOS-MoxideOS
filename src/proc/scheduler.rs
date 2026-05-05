//! Round-robin run queue and voluntary context-switch scheduler.
//! Single-CPU. All mutations go through a SpinMutex<SchedState>.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::arch::{Arch, api::{Cpu, Paging}};
use crate::proc::context::switch_to;
use crate::proc::process::{Pcb, State};

// ── State ───────────────────────────────────────────────────────────────────────────────

struct SchedState {
    procs:    Vec<Pcb>,
    /// O(log n) pid → Vec index.  Must stay in sync with `procs`.
    pid_idx:  BTreeMap<usize, usize>,
    current:  usize,
    next_pid: usize,
}

static SCHED: Mutex<SchedState> = Mutex::new(SchedState {
    procs:    Vec::new(),
    pid_idx:  BTreeMap::new(),
    current:  0,
    next_pid: 1,
});

// ── Simple queries ───────────────────────────────────────────────────────────────────

pub fn current_pid() -> usize {
    let s = SCHED.lock();
    if s.procs.is_empty() { 0 } else { s.procs[s.current].pid }
}

/// Fast path for getppid (NR 110): reads procs[current].ppid directly
/// without a BTreeMap lookup, saving one O(log n) indirection per syscall.
pub fn current_ppid() -> usize {
    let s = SCHED.lock();
    if s.procs.is_empty() { 0 } else { s.procs[s.current].ppid }
}

pub fn next_pid() -> usize {
    let mut s = SCHED.lock();
    let n = s.next_pid;
    s.next_pid += 1;
    n
}

pub fn ppid_of(pid: usize) -> usize {
    let s = SCHED.lock();
    s.pid_idx.get(&pid)
        .and_then(|&i| s.procs.get(i))
        .map_or(0, |p| p.ppid)
}

/// Return the thread-group ID (tgid) for `pid`.
/// Previously lived in thread.rs and called with_proc, causing a
/// redundant lock acquire. Now a direct BTreeMap-indexed read.
pub fn tgid_of(pid: usize) -> usize {
    let s = SCHED.lock();
    s.pid_idx.get(&pid)
        .and_then(|&i| s.procs.get(i))
        .map_or(pid, |p| p.tgid)
}

/// Number of processes currently in the Ready state. Used for diagnostics.
pub fn ready_count() -> usize {
    let s = SCHED.lock();
    s.procs.iter().filter(|p| p.state == State::Ready).count()
}

// ── Queue management ───────────────────────────────────────────────────────────────────

pub fn enqueue(pcb: Pcb) {
    let mut s = SCHED.lock();
    let pid = pcb.pid;
    let idx = s.procs.len();
    s.procs.push(pcb);
    s.pid_idx.insert(pid, idx);
}

/// Run `f` with exclusive access to the process list.
/// Prefer with_proc / with_proc_mut for single-process operations to
/// keep pid_idx in sync. Use this only when iterating all processes.
pub fn with_procs<R>(f: impl FnOnce(&mut Vec<Pcb>) -> R) -> R {
    f(&mut SCHED.lock().procs)
}

/// Immutable variant: iterate all processes without risk of breaking
/// pid_idx by accidentally mutating the list.
pub fn with_procs_ro<R>(f: impl FnOnce(&[Pcb]) -> R) -> R {
    f(&SCHED.lock().procs)
}

/// Run `f` with a shared reference to the PCB for `pid`. Returns `None` if
/// `pid` is not found.
pub fn with_proc<R>(pid: usize, f: impl FnOnce(&Pcb) -> R) -> Option<R> {
    let s = SCHED.lock();
    let &idx = s.pid_idx.get(&pid)?;
    Some(f(&s.procs[idx]))
}

/// Run `f` with an exclusive reference to the PCB for `pid`. Returns `None`
/// if `pid` is not found.
pub fn with_proc_mut<R>(pid: usize, f: impl FnOnce(&mut Pcb) -> R) -> Option<R> {
    let mut s = SCHED.lock();
    let &idx = s.pid_idx.get(&pid)?;
    Some(f(&mut s.procs[idx]))
}

// ── State transitions ───────────────────────────────────────────────────────────────────

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
    if let Some(&idx) = s.pid_idx.get(&pid) {
        let p = &mut s.procs[idx];
        if p.state == State::Blocked {
            p.state = State::Ready;
        }
    }
}

pub fn fix_current_after_remove(removed_idx: usize) {
    let mut s = SCHED.lock();
    let len = s.procs.len();
    if len == 0 {
        s.current = 0;
        s.pid_idx.clear();
        return;
    }
    if removed_idx < len {
        let moved_pid = s.procs[removed_idx].pid;
        s.pid_idx.insert(moved_pid, removed_idx);
    }
    if removed_idx < s.current {
        s.current -= 1;
    }
    if s.current >= len {
        s.current = len - 1;
    }
}

/// Remove a process by pid, maintaining pid_idx consistency.
/// Returns the removed Pcb if found.
pub fn remove_pid(pid: usize) -> Option<Pcb> {
    let mut s = SCHED.lock();
    let &idx = s.pid_idx.get(&pid)?;
    s.pid_idx.remove(&pid);
    let removed = s.procs.swap_remove(idx);
    let len = s.procs.len();
    if len == 0 {
        s.current = 0;
    } else {
        if idx < len {
            let moved_pid = s.procs[idx].pid;
            s.pid_idx.insert(moved_pid, idx);
        }
        if idx < s.current {
            s.current -= 1;
        }
        if s.current >= len {
            s.current = len - 1;
        }
    }
    Some(removed)
}

// ── Scheduler ────────────────────────────────────────────────────────────────────────────

/// Round-robin: find the next Ready task, switch context to it.
/// Does nothing if there is only one runnable task or no tasks.
pub fn schedule() {
    // Phase 1: under the lock, decide who to switch to and capture raw
    // pointers to the two Context objects. Raw ptrs are valid for the
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

        // No ready task, or the only ready task is already current.
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
