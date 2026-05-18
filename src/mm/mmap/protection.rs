use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;
use super::{PAGE, PROT_WRITE, PROT_EXEC};
use super::mm_lock::with_mm_write;
use super::vma::page_align_up;

pub fn sys_mprotect(addr: usize, length: usize, prot: u32) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    if length == 0 { return 0; }
    let len = page_align_up(length);
    let pid = crate::proc::scheduler::current_pid();
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 { return -14; }

    with_mm_write(pid, |p| {
        for vma in p.vmas.iter_mut() {
            if vma.end <= addr || vma.start >= addr + len { continue; }
            vma.prot = prot;
        }
    });

    let new_flags = prot_to_flags(prot);
    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
            <Arch as Paging>::map_page(user_cr3, page_va, pa, new_flags);
        }
    }
    0
}

pub fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}