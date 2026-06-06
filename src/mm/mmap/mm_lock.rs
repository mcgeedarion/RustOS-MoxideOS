extern crate alloc;
use crate::proc::scheduler;
use alloc::sync::Arc;

/// Acquire the process's `mm_lock` for writing, then call `f` with a
/// mutable borrow of the PCB.  Blocks any concurrent `uaccess` reader
/// until the mutation (and the write guard) are complete.
///
/// ## Ordering
/// 1. Lock `ProcLock::inner` briefly to clone the `mm_lock` Arc.
/// 2. Release `inner`.
/// 3. Acquire `mm_lock` write (blocks until all readers finish).
/// 4. Re-acquire `inner` to pass `&mut Pcb` to `f`.
/// 5. Call `f`, then release `inner`, then release `mm_lock` write.
///
/// This two-step ensures the caller never holds `inner` while waiting
/// for `mm_lock` writers, which would deadlock against `uaccess`
/// (which acquires `mm_lock` read while NOT holding `inner`).
pub fn with_mm_write<T, F>(pid: usize, f: F) -> Option<T>
where
    F: FnOnce(&mut crate::proc::process::Pcb) -> T,
{
    let mm_arc: Arc<spin::RwLock<()>> = scheduler::with_proc(pid, |p| Arc::clone(&p.mm_lock))?;

    let _write_guard = mm_arc.write();

    scheduler::with_proc_mut(pid, |p, _pl| f(p))
}

pub fn current_as_bytes(pid: usize) -> usize {
    scheduler::with_proc(pid, |p| p.vmas.iter().map(|v| v.end - v.start).sum()).unwrap_or(0)
}

pub fn check_rlimit_as(pid: usize, extra: usize) -> isize {
    let over = scheduler::with_proc(pid, |p| p.rlimits.exceeds_as(current_as_bytes(pid), extra))
        .unwrap_or(false);
    if over {
        -12
    } else {
        0
    }
}
