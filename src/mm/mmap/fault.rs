use alloc::vec::Vec;
use crate::arch::{Arch, api::Paging};
use crate::proc::scheduler;
use super::{Vma, VmaKind, PAGE};
use super::mm_lock::with_mm_write;

pub fn free_address_space(pid: usize, user_cr3: usize) {
    if user_cr3 == 0 { return; }

    let vmas: Vec<Vma> = scheduler::with_proc(pid, |p| p.vmas.clone())
        .unwrap_or_default();

    for vma in &vmas {
        let is_phys = matches!(vma.kind, VmaKind::PhysMap(_));
        for va in (vma.start..vma.end).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, va) {
                <Arch as Paging>::unmap_page(va);
                if !is_phys {
                    crate::mm::pmm::free_page(pa);
                }
            }
        }
    }

    <Arch as Paging>::free_page_table(user_cr3);
    clear_vmas_internal(pid);
    with_mm_write(pid, |p| p.user_satp = 0);
}

fn clear_vmas_internal(pid: usize) {
    scheduler::with_proc_mut(pid, |p, _| p.vmas.clear());
}