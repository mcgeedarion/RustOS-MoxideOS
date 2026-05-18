extern crate alloc;
use alloc::vec::Vec;
use crate::proc::scheduler;
use super::{Vma, VmaKind, PAGE};

pub fn page_align_up(v: usize) -> usize { (v + PAGE - 1) & !(PAGE - 1) }

pub fn insert_vma(pid: usize, vma: Vma) {
    scheduler::with_proc_mut(pid, |p, _| {
        p.vmas.push(vma);
        p.vmas.sort_by_key(|v| v.start);
    });
}

pub fn remove_vma(pid: usize, start: usize) {
    scheduler::with_proc_mut(pid, |p, _| {
        p.vmas.retain(|v| v.start != start);
    });
}

pub fn find_vma(pid: usize, addr: usize) -> Option<Vma> {
    scheduler::with_proc(pid, |p| {
        p.vmas.iter().find(|v| v.contains(addr)).cloned()
    }).flatten()
}

pub fn with_vmas<T, F: FnOnce(&[Vma]) -> T>(pid: usize, f: F) -> Option<T> {
    scheduler::with_proc(pid, |p| f(&p.vmas))
}

pub fn clone_vmas(src_pid: usize, dst_pid: usize) {
    let vmas: Vec<Vma> = scheduler::with_proc(src_pid, |p| p.vmas.clone()).unwrap_or_default();
    scheduler::with_proc_mut(dst_pid, |p, _| { p.vmas = vmas.clone(); });
}

pub fn clear_vmas_internal(pid: usize) {
    scheduler::with_proc_mut(pid, |p, _| p.vmas.clear());
}

pub fn vma_total_kb(pid: usize) -> usize {
    scheduler::with_proc(pid, |p| {
        p.vmas.iter().map(|v| (v.end - v.start) / 1024).sum()
    }).unwrap_or(0)
}

pub fn heap_kb(pid: usize) -> usize {
    scheduler::with_proc(pid, |p| {
        p.vmas.iter()
            .filter(|v| matches!(v.kind, VmaKind::Heap))
            .map(|v| (v.end - v.start) / 1024).sum()
    }).unwrap_or(0)
}

pub fn stack_kb(pid: usize) -> usize {
    scheduler::with_proc(pid, |p| {
        p.vmas.iter()
            .filter(|v| matches!(v.kind, VmaKind::Stack))
            .map(|v| (v.end - v.start) / 1024).sum()
    }).unwrap_or(0)
}

pub fn current_brk(pid: usize) -> usize {
    scheduler::with_proc(pid, |p| p.brk).unwrap_or(0)
}
