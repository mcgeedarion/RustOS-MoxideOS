//! Compatibility shim for process CoW handlers.
//!
//! CoW fault handling and fork-time CoW cloning are owned by `mm::cow_fault`.
//! Keep this module as a thin forwarding layer so legacy call sites under
//! `proc::*` continue to compile while ownership lives in `mm`.

#[inline]
pub fn clone_for_fork(parent_pid: usize, child_pid: usize, parent_cr3: usize) -> usize {
    crate::mm::cow_fault::clone_for_fork(parent_pid, child_pid, parent_cr3)
}

#[inline]
pub fn handle_cow_fault(faulting_va: usize, error_code: u64) -> bool {
    crate::mm::cow_fault::handle_cow_fault(faulting_va, error_code)
}
