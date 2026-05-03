//! Thread-group management for CLONE_VM threads.
//!
//! THREAD_GROUP maps every non-leader thread pid -> tgid.
//! Processes not in this map use their own pid as the VMA key.
//!
//! vma_pid(pid) is the single call site used by mmap / munmap / brk /
//! find_vma to route all address-space operations to the shared VMA
//! namespace for the whole thread group.

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;

/// Maps thread_pid -> tgid.  Not present means the pid is its own leader.
static THREAD_GROUP: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

/// Register `thread_pid` as a member of `tgid`'s thread group.
pub fn register_thread(thread_pid: usize, tgid: usize) {
    THREAD_GROUP.lock().insert(thread_pid, tgid);
}

/// Unregister `thread_pid` on thread exit.
pub fn unregister_thread(thread_pid: usize) {
    THREAD_GROUP.lock().remove(&thread_pid);
}

/// Resolve the VMA namespace key for `pid`.
/// Threads return their tgid; standalone processes return their own pid.
/// Cast to u32 matches the BTreeMap<u32, Vec<Vma>> key type in mmap.rs.
pub fn vma_pid(pid: usize) -> u32 {
    THREAD_GROUP.lock().get(&pid).copied().unwrap_or(pid) as u32
}

/// Return the tgid of `pid` (pid itself if it is a group leader).
pub fn tgid_of(pid: usize) -> usize {
    THREAD_GROUP.lock().get(&pid).copied().unwrap_or(pid)
}

/// True if `pid` is a non-leader thread.
pub fn is_thread(pid: usize) -> bool {
    THREAD_GROUP.lock().contains_key(&pid)
}
