use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;
use super::{PAGE, PROT_WRITE, PROT_EXEC};
use super::mm_lock::with_mm_write;
use super::vma::page_align_up;

pub fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  != 0 { f |= PageFlags::EXEC;  }
    f
}

pub fn sys_mprotect(addr: usize, length: usize, prot: u32) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    let pid = crate::proc::scheduler::current_pid();
    let end = page_align_up(addr + length);
    with_mm_write(pid, |p| {
        if let Some(cr3) = p.user_cr3 {
            let flags = prot_to_flags(prot);
            let mut va = addr;
            while va < end {
                Paging::remap_page(cr3, va, flags);
                va += PAGE;
            }
        }
        for vma in p.vmas.iter_mut() {
            if vma.start >= addr && vma.end <= end {
                vma.prot = prot;
            }
        }
    });
    0
}
