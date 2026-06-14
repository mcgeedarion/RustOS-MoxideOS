use super::mm_lock::with_mm_write;
use super::vma::{insert_vma, page_align_up, remove_vma};
use super::{Vma, VmaKind, MAP_ANON, PAGE, PROT_READ, PROT_WRITE};
use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};
use crate::proc::scheduler;
use alloc::vec::Vec;

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    if addr & (PAGE - 1) != 0 || length == 0 {
        return -22;
    }
    let len = page_align_up(length);
    let pid = scheduler::current_pid();
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 {
        return -14;
    }

    // Collect PhysMap ranges once to avoid repeated VMA scans (see bug #19).
    let phys_ranges: Vec<(usize, usize)> = scheduler::with_proc(pid, |p| {
        p.vmas
            .iter()
            .filter_map(|v| match v.kind {
                VmaKind::PhysMap(_) => Some((v.start, v.end)),
                _ => None,
            })
            .collect()
    })
    .unwrap_or_default();
    // Collect physical pages to free after TLB shootdown.
    let mut to_free: Vec<usize> = Vec::new();
    // Unmap each page in the range and decide whether to free it.
    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
            // Unmap the page in the target address space. Pass the user CR3 so the
            // correct page-table is manipulated.
            <Arch as Paging>::unmap_page(user_cr3, page_va);
            // Determine if this VA belongs to a PhysMap VMA. PhysMap frames must
            // remain mapped and are not freed.
            let is_phys = phys_ranges
                .iter()
                .any(|&(start, end)| page_va >= start && page_va < end);
            if !is_phys {
                to_free.push(pa);
            }
        }
    }
    // Issue a TLB shootdown for the unmapped range. Use ASID 0 (conservative)
    // for now; per bug #1/#22 this should ideally use the process's actual ASID.
    crate::smp::ipi::tlb_shootdown(addr as u64, (addr + len) as u64, 0);
    // Free collected pages after all CPUs have invalidated their TLB entries.
    for pa in to_free {
        crate::mm::pmm::free_page(pa);
    }
    // Remove the VMA records for the unmapped range.
    remove_vma(pid, addr, len);
    0
}

pub fn sys_brk(addr: usize) -> isize {
    let pid = scheduler::current_pid();
    let (brk_base, cur_brk) = scheduler::with_proc(pid, |p| (p.brk_base, p.brk)).unwrap_or((0, 0));

    if brk_base == 0 {
        return cur_brk as isize;
    }
    if addr == 0 {
        return cur_brk as isize;
    }
    if addr < brk_base {
        return cur_brk as isize;
    }

    let new_brk = page_align_up(addr);
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 {
        return cur_brk as isize;
    }

    if new_brk > cur_brk {
        let extra = new_brk - cur_brk;
        let over = scheduler::with_proc(pid, |p| p.rlimits.exceeds_stack(extra)).unwrap_or(false);
        if over {
            return cur_brk as isize;
        }

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
        // Shrinking the brk region: unmap pages and defer freeing until after TLB shootdown.
        let mut to_free: Vec<usize> = Vec::new();
        for page_va in (new_brk..cur_brk).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
                <Arch as Paging>::unmap_page(user_cr3, page_va);
                to_free.push(pa);
            }
        }
        // Shoot down TLB entries for the shrunk region before freeing frames.
        crate::smp::ipi::tlb_shootdown(new_brk as u64, cur_brk as u64, 0);
        for pa in to_free {
            crate::mm::pmm::free_page(pa);
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
        p.brk = base;
    });
}

pub fn set_brk_base_compute(end_of_bss: usize) -> usize {
    page_align_up(end_of_bss)
}
