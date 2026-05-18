use alloc::vec::Vec;
use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;
use super::{Vma, VmaKind, PAGE, MAP_ANON, PROT_READ, PROT_WRITE};
use super::mm_lock::with_mm_write;
use super::vma::{insert_vma, remove_vma, page_align_up};

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    if addr & (PAGE - 1) != 0 || length == 0 { return -22; }
    let len = page_align_up(length);
    let pid = scheduler::current_pid();
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 { return -14; }

    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
            <Arch as Paging>::unmap_page(page_va);
            let is_phys = scheduler::with_proc(pid, |p| {
                p.vmas.iter().any(|v| {
                    v.start <= page_va && v.end > page_va
                        && matches!(v.kind, VmaKind::PhysMap(_))
                })
            }).unwrap_or(false);
            if !is_phys { crate::mm::pmm::free_page(pa); }
        }
    }
    remove_vma(pid, addr, len);
    0
}

pub fn sys_brk(addr: usize) -> isize {
    let pid = scheduler::current_pid();
    let (brk_base, cur_brk) = scheduler::with_proc(pid, |p| {
        (p.brk_base, p.brk)
    }).unwrap_or((0, 0));

    if brk_base == 0 { return cur_brk as isize; }
    if addr == 0     { return cur_brk as isize; }
    if addr < brk_base { return cur_brk as isize; }

    let new_brk = page_align_up(addr);
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 { return cur_brk as isize; }

    if new_brk > cur_brk {
        let extra = new_brk - cur_brk;
        let over = scheduler::with_proc(pid, |p| {
            p.rlimits.exceeds_stack(extra)
        }).unwrap_or(false);
        if over { return cur_brk as isize; }

        let pte_flags = PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX;
        for page_va in (cur_brk..new_brk).step_by(PAGE) {
            if let Some(pa) = crate::mm::pmm::alloc_page() {
                <Arch as Paging>::map_page(user_cr3, page_va, pa, pte_flags);
            } else {
                scheduler::with_proc_mut(pid, |p, _| p.brk = page_va);
                super::anonymous::coalesce_or_insert_heap_vma(pid, brk_base, page_va);
                return page_va as isize;
            }
        }
        super::anonymous::coalesce_or_insert_heap_vma(pid, brk_base, new_brk);
    } else if new_brk < cur_brk {
        for page_va in (new_brk..cur_brk).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
                <Arch as Paging>::unmap_page(page_va);
                crate::mm::pmm::free_page(pa);
            }
        }
        super::anonymous::trim_heap_vma(pid, brk_base, new_brk);
    }

    scheduler::with_proc_mut(pid, |p, _| p.brk = new_brk);
    new_brk as isize
}

pub fn set_brk_base(pid: usize, end_of_bss: usize) {
    let base = set_brk_base_compute(end_of_bss);
    scheduler::with_proc_mut(pid, |p, _| {
        p.brk_base = base;
        p.brk      = base;
    });
}

pub fn set_brk_base_compute(end_of_bss: usize) -> usize {
    page_align_up(end_of_bss)
}