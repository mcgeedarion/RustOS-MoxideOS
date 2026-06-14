use super::mm_lock::{check_rlimit_as, with_mm_write};
use super::protection::prot_to_flags;
use super::vma::{insert_vma, page_align_up};
use super::{Vma, VmaKind, MAP_ANON, MAP_FIXED, MAP_GROWSDOWN, PAGE, PROT_EXEC, PROT_WRITE};
use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};
use crate::proc::scheduler;
use alloc::vec::Vec;

const MAP_FIXED_NOREPLACE: u32 = 0x100000;

pub fn sys_mmap(
    addr: usize,
    length: usize,
    prot: u32,
    flags: u32,
    fd: usize,
    offset: usize,
) -> isize {
    if length == 0 {
        return -22;
    }
    let len = page_align_up(length);
    let pid = scheduler::current_pid();

    if flags & MAP_GROWSDOWN != 0 {
        let over = scheduler::with_proc(pid, |p| p.rlimits.exceeds_stack(len)).unwrap_or(false);
        if over {
            return -12;
        }
    }

    let as_check = check_rlimit_as(pid, len);
    if as_check < 0 {
        return as_check;
    }

    let is_fixed = flags & MAP_FIXED != 0;
    let is_fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;

    // Validate fixed-address constraints and detect collisions.
    if is_fixed || is_fixed_noreplace {
        if addr == 0 || addr & (PAGE - 1) != 0 {
            return -22;
        }
        if is_fixed_noreplace {
            let collision = scheduler::with_proc(pid, |p| {
                p.vmas.iter().any(|v| v.start < addr + len && v.end > addr)
            })
            .unwrap_or(false);
            if collision {
                return -17;
            }
        }
    }

    // Special-case framebuffer mappings via the GOP driver.
    if flags & MAP_ANON == 0 && crate::drivers::gop::is_fb_fd(fd) {
        if let Some(info) = crate::drivers::gop::get() {
            let fb_phys = info.fb_phys as usize;
            let fb_size = crate::drivers::gop::fb_byte_size(&info);
            let phys_off = fb_phys + offset;
            let max_len = fb_size.saturating_sub(offset);
            let safe_len = len.min(max_len);
            if safe_len == 0 {
                return -22;
            }
            return mmap_phys(addr, safe_len, prot, flags, pid, phys_off as u64);
        }
    }

    // Allocate a virtual address region.  For MAP_FIXED/NOREPLACE we reuse the user-supplied
    // address; for anonymous hints we bump next_va.
    let (va, user_cr3) = with_mm_write(pid, |p| {
        let va = if is_fixed || is_fixed_noreplace {
            // On MAP_FIXED (but not noreplace) remove existing VMAs in the range.  We
            // intentionally do not free pages here; removal will be handled below.
            if !is_fixed_noreplace {
                let end = va_end_of(addr, len);
                remove_vma_inner(p, addr, end);
            }
            addr
        } else {
            let v = p.next_va;
            p.next_va = page_align_up(v + len + PAGE);
            v
        };
        (va, p.user_satp)
    })
    .unwrap_or((0, 0));

    if va == 0 {
        return -22;
    }
    if user_cr3 == 0 {
        return -12;
    }

    let is_anon = flags & MAP_ANON != 0 || fd == usize::MAX;
    let is_growsdown = flags & MAP_GROWSDOWN != 0;
    let pte_flags = prot_to_flags(prot);

    if is_anon {
        // Insert the VMA before mapping pages to avoid races on overlapping MAP_FIXED
        // operations (see bug #10).
        let kind = if is_growsdown {
            VmaKind::Stack
        } else {
            VmaKind::Anonymous
        };
        insert_vma(
            pid,
            Vma {
                start: va,
                end: va + len,
                prot,
                flags,
                kind,
                file_offset: 0,
                locked: false,
            },
        );
        // Map each page; on failure roll back and remove the VMA.
        let mut mapped = 0usize;
        for page_va in (va..va + len).step_by(PAGE) {
            match crate::mm::pmm::alloc_page() {
                Some(pa) => {
                    <Arch as Paging>::map_page(user_cr3, page_va, pa, pte_flags);
                    mapped += 1;
                },
                None => {
                    // Roll back partially mapped pages.
                    for rollback_va in (va..va + mapped * PAGE).step_by(PAGE) {
                        if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, rollback_va) {
                            <Arch as Paging>::unmap_page(user_cr3, rollback_va);
                            crate::mm::pmm::free_page(pa);
                        }
                    }
                    // Remove the inserted VMA and shoot down TLB entries.
                    remove_vma(pid, va, len);
                    return -12;
                },
            }
        }
    } else {
        // File-backed or device mappings: just record the VMA.  Pages will be populated on
        // demand.
        insert_vma(
            pid,
            Vma {
                start: va,
                end: va + len,
                prot,
                flags,
                kind: VmaKind::FileBacked(fd, offset as u64),
                file_offset: offset as u64,
                locked: false,
            },
        );
    }
    va as isize
}

#[inline]
fn va_end_of(va: usize, len: usize) -> usize {
    va.saturating_add(len)
}

// Remove VMAs in the range [addr, end) and unmap/free their pages.  This helper
// previously only adjusted the VMA list; it now also unmaps page tables and
// frees underlying physical frames for non-PhysMap mappings (bug #2).
fn remove_vma_inner(p: &mut crate::proc::process::Pcb, addr: usize, end: usize) {
    let user_cr3 = p.user_satp;
    // Collect pages to free after TLB shootdown.
    let mut to_free: Vec<usize> = Vec::new();
    for page_va in (addr..end).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
            // Check if this page belongs to a PhysMap VMA before removal.
            let is_phys = p
                .vmas
                .iter()
                .any(|v| page_va >= v.start && page_va < v.end && matches!(v.kind, VmaKind::PhysMap(_)));
            // Unmap the page from the old address space.
            <Arch as Paging>::unmap_page(user_cr3, page_va);
            if !is_phys {
                to_free.push(pa);
            }
        }
    }
    // Flush TLBs on all CPUs for the removed range.
    crate::smp::ipi::tlb_shootdown(addr as u64, end as u64, 0);
    // Free collected pages after TLB invalidation.
    for pa in to_free {
        crate::mm::pmm::free_page(pa);
    }

    // Now update the VMA list to remove or trim entries.
    let mut i = 0;
    while i < p.vmas.len() {
        let vstart = p.vmas[i].start;
        let vend = p.vmas[i].end;
        if vend <= addr || vstart >= end {
            i += 1;
            continue;
        }
        if vstart >= addr && vend <= end {
            p.vmas.remove(i);
            continue;
        }
        let has_leading = vstart < addr;
        let has_trailing = vend > end;
        if has_leading && has_trailing {
            let mut tail = p.vmas[i].clone();
            tail.start = end;
            if let VmaKind::FileBacked(_, ref mut off) = tail.kind {
                *off += (end - vstart) as u64;
            }
            tail.file_offset = p.vmas[i].file_offset + (end - vstart) as u64;
            p.vmas[i].end = addr;
            p.vmas.insert(i + 1, tail);
            i += 2;
        } else if has_leading {
            p.vmas[i].end = addr;
            i += 1;
        } else {
            let delta = end - vstart;
            p.vmas[i].start = end;
            if let VmaKind::FileBacked(_, ref mut off) = p.vmas[i].kind {
                *off += delta as u64;
            }
            p.vmas[i].file_offset += delta as u64;
            i += 1;
        }
    }
}

fn mmap_phys(addr: usize, len: usize, prot: u32, flags: u32, pid: usize, offset: u64) -> isize {
    let (va, user_cr3) = with_mm_write(pid, |p| {
        let va = if flags & MAP_FIXED != 0 {
            if addr == 0 {
                return (0usize, 0usize);
            }
            remove_vma_inner(p, addr, va_end_of(addr, len));
            addr
        } else {
            let v = p.next_va;
            p.next_va = page_align_up(v + len + PAGE);
            v
        };
        (va, p.user_satp)
    })
    .unwrap_or((0, 0));

    if va == 0 || user_cr3 == 0 {
        return -22;
    }

    let pte_flags = prot_to_flags(prot & !PROT_EXEC);
    let phys_start = offset as usize;
    for (i, page_va) in (va..va + len).step_by(PAGE).enumerate() {
        <Arch as Paging>::map_page(user_cr3, page_va, phys_start + i * PAGE, pte_flags);
    }
    insert_vma(
        pid,
        Vma {
            start: va,
            end: va + len,
            prot: prot & !PROT_EXEC,
            flags,
            kind: VmaKind::PhysMap(offset),
            file_offset: offset,
            locked: false,
        },
    );
    va as isize
}
