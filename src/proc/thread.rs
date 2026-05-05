//! Thread group (TGID) tracking and gettid.
//!
//! TGID is now stored directly on `Pcb.tgid`, so there is no separate
//! global table — all lookups go through the scheduler's process list.
//!
//! A process created by fork() has tgid == pid.
//! Threads created by clone3(CLONE_THREAD) share the parent's tgid.

use crate::proc::scheduler;

/// Register a new thread: sets Pcb.tgid for the given pid.
/// Called by sys_clone3 after enqueueing the child PCB.
pub fn register_thread(pid: usize, tgid: usize) {
    scheduler::with_proc_mut(pid, |p| p.tgid = tgid);
}

/// Remove a thread from its group (called by do_exit before zombify).
/// The PCB stays in the run list as a Zombie until waitpid reaps it.
pub fn unregister_thread(_pid: usize) {
    // Nothing to do — tgid stays on the PCB; it is correct until reap.
    // Kept as a hook for future thread-group accounting.
}

/// Look up the TGID for a pid. Falls back to pid itself (main thread).
/// Delegates to scheduler::tgid_of — no extra lock acquire.
pub fn tgid_of(pid: usize) -> usize {
    scheduler::tgid_of(pid)
}

/// VMA namespace key: threads in the same group share the parent's tgid.
pub fn vma_pid(pid: usize) -> u32 { tgid_of(pid) as u32 }

/// sys_gettid() [NR 186] — returns the calling thread's pid.
pub fn sys_gettid() -> isize {
    scheduler::current_pid() as isize
}
