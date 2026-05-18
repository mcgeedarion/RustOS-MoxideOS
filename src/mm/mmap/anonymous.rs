use crate::arch::{Arch, api::{PageFlags, Paging}};
use super::{PAGE, PROT_WRITE};
use super::mm_lock::with_mm_write;
use super::vma::clear_vmas_internal;

pub fn alloc_user_stack(pid: usize, user_cr3: usize,
    stack_top: usize, stack_size: usize) -> Option<usize>
{
    let pages = (stack_size + PAGE - 1) / PAGE;
    let base  = stack_top - pages * PAGE;
    for i in 0..pages {
        let va   = base + i * PAGE;
        let phys = crate::mm::pmm::alloc_frame()?;
        let flags = PageFlags::USER | PageFlags::WRITE;
        Paging::map_page(user_cr3, va, phys, flags);
    }
    Some(base)
}

pub fn clear_vmas_pub(pid: usize) {
    clear_vmas_internal(pid);
}
