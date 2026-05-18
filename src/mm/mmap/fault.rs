use alloc::vec::Vec;
use crate::arch::{Arch, api::Paging};
use crate::proc::scheduler;
use super::{Vma, VmaKind, PAGE};
use super::mm_lock::with_mm_write;

pub fn free_address_space(pid: usize, user_cr3: usize) {
    with_mm_write(pid, |p| {
        for vma in p.vmas.drain(..) {
            let mut addr = vma.start;
            while addr < vma.end {
                Paging::unmap_page(user_cr3, addr);
                addr += PAGE;
            }
        }
    });
}
