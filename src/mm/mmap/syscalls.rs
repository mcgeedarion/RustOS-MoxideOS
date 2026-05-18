extern crate alloc;
use crate::proc::scheduler;
use crate::arch::{Arch, api::Paging};
use super::{PAGE, Vma, VmaKind, PROT_WRITE};
use super::vma::{insert_vma, page_align_up};
use super::mm_lock::with_mm_write;
use super::mapping::remove_vma_inner;

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    if addr & (PAGE - 1) != 0 || length == 0 { return -22; }
    let pid      = scheduler::current_pid();
    let user_cr3 = match scheduler::with_proc(pid, |p| p.user_cr3).flatten() {
        Some(c) => c, None => return -22,
    };
    remove_vma_inner(pid, user_cr3, addr, addr + length);
    0
}

pub fn set_brk_base(pid: usize, base: usize) {
    scheduler::with_proc_mut(pid, |p, _| {
        p.brk      = base;
        p.brk_base = base;
    });
}

pub fn set_brk_base_compute(pid: usize) {
    let top = scheduler::with_proc(pid, |p| {
        p.vmas.iter()
            .filter(|v| matches!(v.kind, VmaKind::FileBacked { .. }))
            .map(|v| v.end)
            .max()
            .unwrap_or(0x4000_0000)
    }).unwrap_or(0x4000_0000);
    let base = page_align_up(top);
    set_brk_base(pid, base);
}

pub fn sys_brk(new_brk: usize) -> isize {
    let pid = scheduler::current_pid();
    let (brk_base, old_brk) = scheduler::with_proc(pid, |p|
        (p.brk_base, p.brk)
    ).unwrap_or((0, 0));

    if new_brk == 0 || new_brk < brk_base { return old_brk as isize; }

    let new_aligned = page_align_up(new_brk);
    let old_aligned = page_align_up(old_brk);

    if new_aligned == old_aligned {
        scheduler::with_proc_mut(pid, |p, _| p.brk = new_brk);
        return new_brk as isize;
    }

    let user_cr3 = match scheduler::with_proc(pid, |p| p.user_cr3).flatten() {
        Some(c) => c, None => return old_brk as isize,
    };

    if new_aligned > old_aligned {
        let mut va = old_aligned;
        while va < new_aligned {
            let phys = match crate::mm::pmm::alloc_frame() {
                Some(p) => p,
                None    => return old_brk as isize,
            };
            crate::arch::api::Paging::map_page(
                user_cr3, va, phys,
                crate::arch::api::PageFlags::USER | crate::arch::api::PageFlags::WRITE,
            );
            va += PAGE;
        }
        let heap_vma = Vma {
            start: old_aligned, end: new_aligned,
            prot: super::PROT_READ | PROT_WRITE,
            flags: super::MAP_PRIVATE | super::MAP_ANON,
            kind: VmaKind::Heap, offset: 0,
        };
        insert_vma(pid, heap_vma);
    } else {
        remove_vma_inner(pid, user_cr3, new_aligned, old_aligned);
    }
    scheduler::with_proc_mut(pid, |p, _| p.brk = new_brk);
    new_brk as isize
}
