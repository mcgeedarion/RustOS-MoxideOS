use super::mm_lock::with_mm_write;
use super::vma::clear_vmas_internal;
use super::{PAGE, PROT_WRITE};
use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};

pub fn alloc_user_stack(cr3: usize, stack_top: usize, stack_bytes: usize) -> Result<usize, i32> {
    let stack_bottom = stack_top - stack_bytes;
    let pte_flags = PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX;
    let mut mapped = 0usize;

    for i in 0..stack_bytes / PAGE {
        let va = stack_bottom + i * PAGE;
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                <Arch as Paging>::map_page(cr3, va, pa, pte_flags);
                mapped += 1;
            },
            None => {
                for j in 0..mapped {
                    let rva = stack_bottom + j * PAGE;
                    if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, rva) {
                        <Arch as Paging>::unmap_page(rva);
                        crate::mm::pmm::free_page(pa);
                    }
                }
                return Err(-12);
            },
        }
    }
    Ok(stack_bottom)
}

pub fn clear_vmas_pub(pid: usize) {
    clear_vmas_internal(pid);
}

fn coalesce_or_insert_heap_vma(pid: usize, brk_base: usize, new_brk: usize) {
    let extended = with_mm_write(pid, |p| {
        if let Some(v) = p
            .vmas
            .iter_mut()
            .find(|v| v.is_heap() && v.start == brk_base)
        {
            v.end = new_brk;
            true
        } else {
            false
        }
    })
    .unwrap_or(false);

    if !extended {
        super::vma::insert_vma(
            pid,
            super::Vma {
                start: brk_base,
                end: new_brk,
                prot: super::PROT_READ | PROT_WRITE,
                flags: super::MAP_ANON,
                kind: super::VmaKind::Heap,
                file_offset: 0,
                locked: false,
            },
        );
    }
}

fn trim_heap_vma(pid: usize, brk_base: usize, new_brk: usize) {
    with_mm_write(pid, |p| {
        if let Some(v) = p
            .vmas
            .iter_mut()
            .find(|v| v.is_heap() && v.start == brk_base)
        {
            v.end = new_brk;
        }
    });
}
