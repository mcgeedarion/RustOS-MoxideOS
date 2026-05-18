use alloc::vec::Vec;
use crate::proc::scheduler;
use super::{Vma, VmaKind, PAGE};
use super::mm_lock::with_mm_write;

pub fn insert_vma(pid: usize, vma: Vma) {
    with_mm_write(pid, |p| {
        let pos = p.vmas.partition_point(|v| v.start < vma.start);
        p.vmas.insert(pos, vma);
    });
}

pub fn remove_vma(pid: usize, addr: usize, len: usize) {
    let end = addr.saturating_add(len);
    with_mm_write(pid, |p| {
        p.vmas.retain(|v| v.end <= addr || v.start >= end);
    });
}

pub fn find_vma(pid: usize, addr: usize) -> Option<Vma> {
    scheduler::with_proc(pid, |p| {
        p.vmas.iter().find(|v| v.start <= addr && v.end > addr).cloned()
    }).flatten()
}

pub fn clone_vmas(src_pid: usize, dst_pid: usize) {
    let vmas = scheduler::with_proc(src_pid, |p| p.vmas.clone()).unwrap_or_default();
    with_mm_write(dst_pid, |p| p.vmas = vmas);
}

pub fn clear_vmas_internal(pid: usize) {
    scheduler::with_proc_mut(pid, |p, _| p.vmas.clear());
}

pub fn with_vmas<F: FnMut(&Vma)>(pid: u32, mut f: F) {
    scheduler::with_proc(pid as usize, |p| {
        for v in &p.vmas { f(v); }
    });
}

pub fn vma_total_kb(pid: u32) -> usize {
    scheduler::with_proc(pid as usize, |p| {
        p.vmas.iter().map(|v| (v.end - v.start) / 1024).sum()
    }).unwrap_or(0)
}

pub fn heap_kb(pid: u32) -> usize {
    scheduler::with_proc(pid as usize, |p| {
        p.vmas.iter()
            .filter(|v| matches!(v.kind, VmaKind::Heap))
            .map(|v| (v.end - v.start) / 1024)
            .sum()
    }).unwrap_or(0)
}

pub fn stack_kb(pid: u32) -> usize {
    scheduler::with_proc(pid as usize, |p| {
        p.vmas.iter()
            .filter(|v| matches!(v.kind, VmaKind::Stack))
            .map(|v| (v.end - v.start) / 1024)
            .sum()
    }).unwrap_or(0)
}

pub fn current_brk(pid: u32) -> usize {
    scheduler::with_proc(pid as usize, |p| {
        p.vmas.iter()
            .filter(|v| matches!(v.kind, VmaKind::Heap))
            .map(|v| v.end)
            .max()
            .unwrap_or(0)
    }).unwrap_or(0)
}

pub fn page_align_up(n: usize) -> usize { (n + PAGE - 1) & !(PAGE - 1) }