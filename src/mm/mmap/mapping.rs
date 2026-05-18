extern crate alloc;
use alloc::vec::Vec;
use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;
use super::{Vma, VmaKind, PAGE, PROT_WRITE, PROT_EXEC,
            MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANON, MAP_GROWSDOWN};
use super::vma::{insert_vma, page_align_up};
use super::protection::prot_to_flags;
use super::mm_lock::{with_mm_write, check_rlimit_as};

pub fn remove_vma_inner(pid: usize, user_cr3: usize,
    start: usize, end: usize)
{
    let page_start = start & !(PAGE - 1);
    let page_end   = page_align_up(end);
    scheduler::with_proc_mut(pid, |p, _| {
        let mut new_vmas = Vec::new();
        for vma in p.vmas.drain(..) {
            if vma.end <= page_start || vma.start >= page_end {
                new_vmas.push(vma);
            } else {
                if vma.start < page_start {
                    new_vmas.push(Vma {
                        start: vma.start, end: page_start,
                        prot: vma.prot, flags: vma.flags,
                        kind: vma.kind.clone(), offset: vma.offset,
                    });
                }
                if vma.end > page_end {
                    let extra_off = (page_end - vma.start) as u64;
                    new_vmas.push(Vma {
                        start: page_end, end: vma.end,
                        prot: vma.prot, flags: vma.flags,
                        kind: vma.kind.clone(),
                        offset: vma.offset + extra_off,
                    });
                }
                let mut va = page_start.max(vma.start);
                while va < page_end.min(vma.end) {
                    Paging::unmap_page(user_cr3, va);
                    va += PAGE;
                }
            }
        }
        p.vmas = new_vmas;
    });
}

pub fn mmap_phys(user_cr3: usize, va: usize, phys: usize,
    length: usize, prot: u32)
{
    let flags = super::protection::prot_to_flags(prot);
    let mut offset = 0;
    while offset < length {
        Paging::map_page(user_cr3, va + offset, phys + offset, flags);
        offset += PAGE;
    }
}

pub fn sys_mmap(addr: usize, length: usize, prot: u32,
    flags: u32, fd: i64, offset: u64) -> isize
{
    if length == 0 { return -22; }
    let pid      = scheduler::current_pid();
    let user_cr3 = match scheduler::with_proc(pid, |p| p.user_cr3).flatten() {
        Some(c) => c, None => return -12,
    };
    if check_rlimit_as(pid, length) != 0 { return -12; }
    let len_pages  = page_align_up(length);
    let hint_start = if addr != 0 && (flags & MAP_FIXED != 0) { addr }
                     else { pick_free_va(pid, len_pages) };
    if hint_start == 0 { return -12; }

    if flags & MAP_ANON != 0 || fd < 0 {
        for i in 0..(len_pages / PAGE) {
            let va   = hint_start + i * PAGE;
            let phys = match crate::mm::pmm::alloc_frame() { Some(p) => p, None => return -12 };
            let pf   = prot_to_flags(prot);
            Paging::map_page(user_cr3, va, phys, pf);
        }
        let kind = if flags & MAP_GROWSDOWN != 0 {
            VmaKind::Stack
        } else {
            VmaKind::Anonymous
        };
        insert_vma(pid, Vma { start: hint_start, end: hint_start + len_pages,
            prot, flags, kind, offset });
    } else {
        let data = match crate::fs::vfs_ops::vfs_pread(pid, fd as usize, offset, length) {
            Ok(d) => d, Err(_) => return -9,
        };
        for i in 0..(len_pages / PAGE) {
            let va   = hint_start + i * PAGE;
            let phys = match crate::mm::pmm::alloc_frame() { Some(p) => p, None => return -12 };
            let pf   = prot_to_flags(prot);
            Paging::map_page(user_cr3, va, phys, pf);
            let src_start = i * PAGE;
            let src_end   = (src_start + PAGE).min(data.len());
            if src_start < data.len() {
                let dst_slice = unsafe {
                    core::slice::from_raw_parts_mut(
                        crate::mm::vmm::phys_to_virt(phys) as *mut u8, PAGE)
                };
                let copy_len = src_end - src_start;
                dst_slice[..copy_len].copy_from_slice(&data[src_start..src_end]);
            }
        }
        insert_vma(pid, Vma {
            start: hint_start, end: hint_start + len_pages,
            prot, flags,
            kind: VmaKind::FileBacked { fd: fd as usize, file_offset: offset },
            offset,
        });
    }
    hint_start as isize
}

fn pick_free_va(pid: usize, size: usize) -> usize {
    let base: usize = 0x4000_0000;
    let mut candidate = base;
    loop {
        let overlaps = scheduler::with_proc(pid, |p| {
            p.vmas.iter().any(|v| !(candidate + size <= v.start || candidate >= v.end))
        }).unwrap_or(false);
        if !overlaps { return candidate; }
        candidate += size + PAGE;
        if candidate > 0x7FFF_FFFF_0000 { return 0; }
    }
}
