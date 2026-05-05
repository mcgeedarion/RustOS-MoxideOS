//! Virtual Memory Area (VMA) tracker + mmap / munmap / mprotect / brk.
//!
//! VMAs are stored directly in the PCB (Pcb::vmas) so every process has
//! an independent VMA list with no hash-table collision risk.
//! The per-process VA bump pointer (Pcb::next_va) and brk (Pcb::brk)
//! are also PCB fields, eliminating the old process-global statics.
//!
//! ## VMA ordering
//! VMAs are kept sorted by `start` address at all times.  This allows
//! find_vma (called on every page fault) to use binary search in O(log n)
//! instead of a linear scan.

extern crate alloc;
use alloc::vec::Vec;
use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;

// ── VMA descriptor ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum VmaKind {
    Anonymous,
    FileBacked(usize, u64),
    Fixed,
}

#[derive(Clone, Debug)]
pub struct Vma {
    pub start:       usize,
    pub end:         usize,
    pub prot:        u32,
    pub flags:       u32,
    pub kind:        VmaKind,
    pub file_offset: u64,
}

// ── PROT_* / MAP_* constants ──────────────────────────────────────────────────────

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;

const MAP_FIXED: u32 = 0x10;
const MAP_ANON:  u32 = 0x20;
const PAGE:      usize = 4096;

// ── VMA helpers ──────────────────────────────────────────────────────────────────

/// Insert a VMA in sorted order by start address.
/// Uses binary_search to find the insertion point in O(log n),
/// then Vec::insert which is O(n) for the shift — acceptable since
/// mmap is infrequent compared to find_vma (called on every page fault).
pub fn insert_vma(pid: usize, vma: Vma) {
    scheduler::with_proc_mut(pid, |p| {
        let idx = p.vmas
            .binary_search_by_key(&vma.start, |v| v.start)
            .unwrap_or_else(|i| i);
        p.vmas.insert(idx, vma);
    });
}

/// Remove all VMAs that overlap [addr, addr+len).
pub fn remove_vma(pid: usize, addr: usize, len: usize) {
    scheduler::with_proc_mut(pid, |p| {
        p.vmas.retain(|v| !(v.start < addr + len && v.end > addr));
    });
}

/// Find the VMA containing `addr` using binary search. O(log n).
/// Called on every page fault — this is the hottest VMA path.
pub fn find_vma(pid: usize, addr: usize) -> Option<Vma> {
    scheduler::with_proc(pid, |p| {
        let vmas = &p.vmas;
        // Binary search for the last VMA whose start <= addr.
        // partition_point gives the index of the first entry with start > addr,
        // so the candidate is one before that.
        let idx = vmas.partition_point(|v| v.start <= addr);
        if idx == 0 { return None; }
        let v = &vmas[idx - 1];
        if addr < v.end { Some(v.clone()) } else { None }
    }).flatten()
}

pub fn clone_vmas(src_pid: usize, dst_pid: usize) {
    // Snapshot src vmas, then write to dst — two separate lock acquisitions
    // to avoid borrow conflicts on the same Vec. Sort order is preserved.
    let src_vmas: Vec<Vma> = scheduler::with_proc(src_pid, |p| p.vmas.clone())
        .unwrap_or_default();
    scheduler::with_proc_mut(dst_pid, |p| p.vmas = src_vmas);
}

/// Clear VMA metadata only (no page unmapping). Used internally after
/// free_address_space has already unmapped the pages.
fn clear_vmas_internal(pid: usize) {
    scheduler::with_proc_mut(pid, |p| p.vmas.clear());
}

// ── free_address_space ────────────────────────────────────────────────────────────────────
//
// Tear down a process's entire user address space:
//   1. For each VMA: walk page-by-page, virt_to_phys → unmap_page → free_page.
//   2. Call Paging::free_page_table(cr3) to release the PML4 and all
//      intermediate page table pages back to the PMM.
//   3. Clear pcb.vmas so the zombie PCB holds no dangling references.
//
// Must be called BEFORE the process switches away from its CR3 (i.e. while
// still running, or from the exit path of the last thread in the group).
// Must NOT be called if other threads still share this CR3 (CLONE_VM).

pub fn free_address_space(pid: usize, user_cr3: usize) {
    if user_cr3 == 0 { return; }

    // Snapshot the VMA list without holding the scheduler lock during
    // the (potentially long) page-by-page teardown loop.
    let vmas: Vec<Vma> = scheduler::with_proc(pid, |p| p.vmas.clone())
        .unwrap_or_default();

    for vma in &vmas {
        for va in (vma.start..vma.end).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, va) {
                <Arch as Paging>::unmap_page(va);
                crate::mm::pmm::free_page(pa);
            }
        }
    }

    <Arch as Paging>::free_page_table(user_cr3);
    clear_vmas_internal(pid);

    scheduler::with_proc_mut(pid, |p| p.user_satp = 0);
}

// ── sys_mmap ──────────────────────────────────────────────────────────────────────────

pub fn sys_mmap(
    addr: usize, length: usize, prot: u32, flags: u32,
    fd: usize, offset: usize,
) -> isize {
    if length == 0 { return -22; }
    let len = page_align_up(length);
    let pid = scheduler::current_pid();

    // Single lock acquisition: resolve va and cr3.
    let (va, user_cr3) = scheduler::with_proc_mut(pid, |p| {
        let va = if flags & MAP_FIXED != 0 {
            if addr == 0 { return (0, 0); }
            addr
        } else {
            let v = p.next_va;
            p.next_va = page_align_up(v + len + PAGE);
            v
        };
        (va, p.user_satp)
    }).unwrap_or((0, 0));

    if va == 0 { return -22; }
    if user_cr3 == 0 { return -12; }

    let pte_flags = prot_to_flags(prot);
    let mut mapped = 0usize;
    for page_va in (va..va + len).step_by(PAGE) {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                <Arch as Paging>::map_page(user_cr3, page_va, pa, pte_flags);
                mapped += 1;
            }
            None => {
                for rollback_va in (va..va + mapped * PAGE).step_by(PAGE) {
                    if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, rollback_va) {
                        <Arch as Paging>::unmap_page(rollback_va);
                        crate::mm::pmm::free_page(pa);
                    }
                }
                return -12;
            }
        }
    }

    insert_vma(pid, Vma {
        start: va,
        end:   va + len,
        prot,
        flags,
        kind: if flags & MAP_ANON != 0 {
            VmaKind::Anonymous
        } else {
            VmaKind::FileBacked(fd, offset as u64)
        },
        file_offset: offset as u64,
    });
    va as isize
}

// ── sys_munmap ──────────────────────────────────────────────────────────────────────────

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    let len = page_align_up(length);
    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::unmap_page(page_va) {
            crate::mm::pmm::free_page(pa);
        }
    }
    remove_vma(scheduler::current_pid(), addr, len);
    0
}

// ── sys_mprotect ──────────────────────────────────────────────────────────────────────────

pub fn sys_mprotect(addr: usize, length: usize, prot: u32) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    let len      = page_align_up(length);
    let pid      = scheduler::current_pid();
    let new_flags = prot_to_flags(prot);
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 { return -12; }
    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
            <Arch as Paging>::map_page(user_cr3, page_va, pa, new_flags);
            <Arch as Paging>::flush_va(page_va);
        }
    }
    scheduler::with_proc_mut(pid, |p| {
        for v in p.vmas.iter_mut() {
            // Early break: list is sorted by start, so once we pass the
            // end of the requested range no further VMAs can overlap.
            if v.start >= addr + len { break; }
            if v.start < addr + len && v.end > addr {
                v.prot = prot;
            }
        }
    });
    0
}

// ── sys_brk ────────────────────────────────────────────────────────────────────────────

pub fn sys_brk(addr: usize) -> isize {
    let pid = scheduler::current_pid();
    let (old_brk, user_cr3) = scheduler::with_proc(pid, |p| (p.brk, p.user_satp))
        .unwrap_or((0, 0));
    if addr == 0 || addr <= old_brk { return old_brk as isize; }
    let new_brk = page_align_up(addr);
    for va in (old_brk..new_brk).step_by(PAGE) {
        if let Some(pa) = crate::mm::pmm::alloc_page() {
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
            <Arch as Paging>::map_page(
                user_cr3, va, pa,
                PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX,
            );
        }
    }
    scheduler::with_proc_mut(pid, |p| p.brk = new_brk);
    new_brk as isize
}

// ── helpers ────────────────────────────────────────────────────────────────────────────

#[inline]
fn page_align_up(n: usize) -> usize { (n + PAGE - 1) & !(PAGE - 1) }

#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}
