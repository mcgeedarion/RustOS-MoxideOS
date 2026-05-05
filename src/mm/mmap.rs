//! Virtual Memory Area (VMA) tracker + mmap / munmap / mprotect / brk.
//!
//! VMAs are stored directly in the PCB (Pcb::vmas) so every process has
//! an independent VMA list with no hash-table collision risk.
//! The per-process VA bump pointer (Pcb::next_va) and brk (Pcb::brk)
//! are also PCB fields, eliminating the old process-global statics.
//!
//! VMA kinds:
//!   Anonymous  — zero-filled private memory (heap, stack, anon mmap)
//!   FileBacked — file-backed mmap (text/data/shared lib)
//!   Fixed      — kernel-placed region (e.g. vsyscall)

extern crate alloc;
use alloc::vec::Vec;
use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::proc::scheduler;

// ── VMA descriptor ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum VmaKind {
    Anonymous,
    /// File-backed mapping: (fd, file_offset in bytes)
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

// ── PROT_* / MAP_* constants ─────────────────────────────────────────────

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;

const MAP_FIXED: u32 = 0x10;
const MAP_ANON:  u32 = 0x20;
const PAGE:      usize = 4096;

// ── VMA helpers (operate on the current process via scheduler) ───────────

/// Insert a VMA into `pid`'s list.
pub fn insert_vma(pid: usize, vma: Vma) {
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.vmas.push(vma);
        }
    });
}

/// Remove all VMAs overlapping [addr, addr+len) from `pid`'s list.
pub fn remove_vma(pid: usize, addr: usize, len: usize) {
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.vmas.retain(|v| !(v.start < addr + len && v.end > addr));
        }
    });
}

/// Find the VMA containing `addr` for `pid`.
pub fn find_vma(pid: usize, addr: usize) -> Option<Vma> {
    scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).and_then(|p| {
            p.vmas.iter().find(|v| v.start <= addr && addr < v.end).cloned()
        })
    })
}

/// Clone all VMAs from `src_pid` into `dst_pid` (used by fork).
pub fn clone_vmas(src_pid: usize, dst_pid: usize) {
    let src_vmas: Vec<Vma> = scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == src_pid)
             .map(|p| p.vmas.clone())
             .unwrap_or_default()
    });
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == dst_pid) {
            p.vmas = src_vmas;
        }
    });
}

/// Clear all VMAs for `pid` (used by exec / exit).
pub fn clear_vmas(pid: usize) {
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.vmas.clear();
        }
    });
}

// ── sys_mmap ─────────────────────────────────────────────────────────────

pub fn sys_mmap(
    addr: usize, length: usize, prot: u32, flags: u32,
    fd:   usize, offset: usize,
) -> isize {
    if length == 0 { return -22; } // EINVAL
    let len = page_align_up(length);

    // Get this process's CR3 and bump the per-process next_va.
    let (va, user_cr3) = scheduler::with_procs(|procs| {
        let pid = procs.iter().enumerate()
            .find(|(_, p)| p.state == crate::proc::process::State::Running)
            .map(|(_, p)| p.pid)
            .unwrap_or(0);
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            let va = if flags & MAP_FIXED != 0 {
                if addr == 0 { return (0, 0); }
                addr
            } else {
                let v = p.next_va;
                p.next_va = page_align_up(v + len + PAGE); // +PAGE = guard gap
                v
            };
            (va, p.user_satp)
        } else {
            (0, 0)
        }
    });
    if va == 0 { return -22; }
    if user_cr3 == 0 { return -12; } // ENOMEM: no address space yet

    let pte_flags = prot_to_flags(prot);

    // Map pages one by one into the process's address space; roll back on OOM.
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

    let pid = scheduler::current_pid();
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

// ── sys_munmap ────────────────────────────────────────────────────────────

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    let len = page_align_up(length);

    let user_cr3 = scheduler::with_procs(|procs| {
        let pid = scheduler_running_pid(procs);
        procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.user_satp)
    });

    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::unmap_page(page_va) {
            crate::mm::pmm::free_page(pa);
        }
        let _ = user_cr3; // CR3 used implicitly by unmap_page on x86
    }

    remove_vma(scheduler::current_pid(), addr, len);
    0
}

// ── sys_mprotect ──────────────────────────────────────────────────────────

pub fn sys_mprotect(addr: usize, length: usize, prot: u32) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    let len       = page_align_up(length);
    let new_flags = prot_to_flags(prot);
    let pid       = scheduler::current_pid();

    let user_cr3 = scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.user_satp)
    });
    if user_cr3 == 0 { return -12; }

    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, page_va) {
            <Arch as Paging>::map_page(user_cr3, page_va, pa, new_flags);
            <Arch as Paging>::flush_va(page_va);
        }
    }

    // Update VMA prot metadata.
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            for v in p.vmas.iter_mut() {
                if v.start < addr + len && v.end > addr {
                    v.prot = prot;
                }
            }
        }
    });
    0
}

// ── sys_brk ───────────────────────────────────────────────────────────────

pub fn sys_brk(addr: usize) -> isize {
    let pid = scheduler::current_pid();

    // Read current brk and CR3 in one lock window.
    let (old_brk, user_cr3) = scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid)
             .map(|p| (p.brk, p.user_satp))
             .unwrap_or((0, 0))
    });

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
        // OOM: stop without error; process faults on the unmapped page.
    }

    // Commit new brk.
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.brk = new_brk;
        }
    });

    new_brk as isize
}

// ── helpers ───────────────────────────────────────────────────────────────

#[inline]
fn page_align_up(n: usize) -> usize { (n + PAGE - 1) & !(PAGE - 1) }

#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}

/// Find the pid of the currently Running process inside a procs slice.
/// Used when current_pid() would deadlock (lock already held).
#[inline]
fn scheduler_running_pid(procs: &[crate::proc::process::Pcb]) -> usize {
    procs.iter()
        .find(|p| p.state == crate::proc::process::State::Running)
        .map(|p| p.pid)
        .unwrap_or(0)
}
