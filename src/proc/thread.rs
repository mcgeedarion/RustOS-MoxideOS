//! Thread group (TGID) tracking, gettid, tkill.
//!
//! TGID is stored directly on `Pcb.tgid`, so there is no separate
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
}

/// Look up the TGID for a pid. Falls back to pid itself (main thread).
/// Delegates to scheduler::tgid_of — no extra lock acquire.
pub fn tgid_of(pid: usize) -> usize {
    scheduler::tgid_of(pid)
}

/// Collect all live thread pids that share `tgid` (including tgid itself).
/// Used by FUTEX_FLAG_TSYNC in seccomp and by tgkill validation.
pub fn threads_of(tgid: usize) -> alloc::vec::Vec<usize> {
    scheduler::with_procs_ro(|procs| {
        procs.iter()
            .filter(|p| p.tgid == tgid)
            .map(|p| p.pid)
            .collect()
    })
}

/// VMA namespace key: threads in the same group share the parent's tgid.
pub fn vma_pid(pid: usize) -> u32 { tgid_of(pid) as u32 }

/// sys_gettid() [NR 186] — returns the calling thread's TID (== Pcb.pid).
pub fn sys_gettid() -> isize {
    scheduler::current_pid() as isize
}

/// sys_tkill(tid, sig) [NR 200]
///
/// Send signal `sig` to thread `tid`.  Unlike kill(2), the target is a
/// specific thread rather than any thread in the process group.
/// NPTL uses this internally; tgkill(2) is the preferred form.
pub fn sys_tkill(tid: usize, sig: u32) -> isize {
    if sig == 0 {
        // Signal 0 is a validity probe: just check the tid exists.
        return match scheduler::with_proc(tid, |_| ()) {
            Some(_) => 0,
            None    => -3, // ESRCH
        };
    }
    if sig > 64 { return -22; } // EINVAL
    crate::proc::signal::send_signal(tid, sig as i32)
}

/// sys_tgkill(tgid, tid, sig) [NR 234]
///
/// Like tkill but validates that `tid` belongs to `tgid`.  This prevents
/// accidentally hitting a recycled TID after a thread exits.
pub fn sys_tgkill(tgid: usize, tid: usize, sig: u32) -> isize {
    if sig > 64 { return -22; } // EINVAL
    // Verify (tgid, tid) pairing.
    let real_tgid = scheduler::tgid_of(tid);
    if real_tgid == 0 || real_tgid != tgid { return -3; } // ESRCH
    if sig == 0 { return 0; } // probe only
    crate::proc::signal::send_signal(tid, sig as i32)
}
