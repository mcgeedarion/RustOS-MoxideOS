extern crate alloc;
use alloc::sync::Arc;
use crate::proc::scheduler;

pub fn with_mm_write<T, F>(pid: usize, f: F) -> Option<T>
where
    F: FnOnce(&mut crate::proc::process::Pcb) -> T,
{
    let mm_arc: Arc<spin::RwLock<()>> =
        scheduler::with_proc(pid, |p| Arc::clone(&p.mm_lock))?;
    let _write_guard = mm_arc.write();
    scheduler::with_proc_mut(pid, |p, _pl| f(p))
}

pub fn current_as_bytes(pid: usize) -> usize {
    scheduler::with_proc(pid, |p| {
        p.vmas.iter().map(|v| v.end - v.start).sum()
    }).unwrap_or(0)
}

pub fn check_rlimit_as(pid: usize, extra: usize) -> isize {
    let over = scheduler::with_proc(pid, |p| {
        p.rlimits.exceeds_as(current_as_bytes(pid), extra)
    }).unwrap_or(false);
    if over { -12 } else { 0 }
}
