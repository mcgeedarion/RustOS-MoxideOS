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
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.tgid = tgid;
        }
    });
}

/// Remove a thread from its group (called by do_exit before zombify).
/// The PCB stays in the run list as a Zombie until waitpid reaps it.
pub fn unregister_thread(pid: usize) {
    // Nothing to do — tgid stays on the PCB; it is correct until reap.
    // This function is kept as a hook for future thread-group accounting
    // (e.g. decrementing a group thread count for SIGKILL propagation).
    let _ = pid;
}

/// Look up the TGID for a pid. Falls back to pid itself (main thread).
pub fn tgid_of(pid: usize) -> usize {
    scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).map_or(pid, |p| p.tgid)
    })
}

/// VMA namespace key: threads in the same group share the parent's tgid.
pub fn vma_pid(pid: usize) -> u32 { tgid_of(pid) as u32 }

/// sys_gettid() [NR 186] — returns the calling thread's pid.
pub fn sys_gettid() -> isize {
    scheduler::current_pid() as isize
}
