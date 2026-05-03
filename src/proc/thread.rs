//! Thread group (TGID) tracking and gettid.
//!
//! A process created by fork() has tgid == pid.
//! Threads created by clone3(CLONE_THREAD) share the parent's tgid.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

struct TidEntry { pid: usize, tgid: usize }

static TID_TABLE: Mutex<Vec<TidEntry>> = Mutex::new(Vec::new());

/// Register a new thread in group `tgid`.
pub fn register_thread(pid: usize, tgid: usize) {
    let mut t = TID_TABLE.lock();
    // Remove any stale entry.
    t.retain(|e| e.pid != pid);
    t.push(TidEntry { pid, tgid });
}

/// Look up the TGID for a pid. Falls back to pid itself (main thread).
pub fn tgid_of(pid: usize) -> usize {
    let t = TID_TABLE.lock();
    t.iter().find(|e| e.pid == pid).map_or(pid, |e| e.tgid)
}

/// VMA namespace key: threads share the parent's tgid as the VMA key.
pub fn vma_pid(pid: usize) -> u32 { tgid_of(pid) as u32 }

/// sys_gettid() [NR 186] — returns the calling thread's PID.
pub fn sys_gettid() -> isize {
    crate::proc::scheduler::current_pid() as isize
}
