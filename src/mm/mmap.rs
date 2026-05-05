//! Virtual Memory Area (VMA) tracker + mmap / munmap / mprotect / brk.
//!
//! Each process has a per-PCB VMA list stored in the scheduler's PCB.
//!
//! VMA kinds:
//!   Anonymous   — zero-filled private memory (heap, stack, anon mmap)
//!   FileBacked  — file-backed mmap (text/data/shared lib)
//!   Fixed       — kernel-placed region (e.g. vsyscall)

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use crate::arch::{Arch, api::{Paging, PageFlags}};

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

// ── Global VMA table (keyed by pid % MAX_PROCS) ──────────────────────────
// TODO: replace with a HashMap<u32, Vec<Vma>> or store VMAs in the PCB to
// eliminate the pid-collision hazard (pid 1 and pid 257 share the same slot).

const MAX_PROCS: usize = 256;
static VMA_TABLE: Mutex<[Vec<Vma>; MAX_PROCS]> =
    Mutex::new([const { Vec::new() }; MAX_PROCS]);

#[inline]
fn pid_idx(pid: u32) -> usize { pid as usize % MAX_PROCS }

pub fn insert_vma(pid: u32, vma: Vma) {
    VMA_TABLE.lock()[pid_idx(pid)].push(vma);
}

pub fn remove_vma(pid: u32, addr: usize, len: usize) {
    VMA_TABLE.lock()[pid_idx(pid)].retain(|v| !(v.start < addr + len && v.end > addr));
}

pub fn find_vma(pid: u32, addr: usize) -> Option<Vma> {
    VMA_TABLE.lock()[pid_idx(pid)]
        .iter()
        .find(|v| v.start <= addr && addr < v.end)
        .cloned()
}

pub fn clone_vmas(src_key: u32, dst_key: u32) {
    let mut t = VMA_TABLE.lock();
    let src = t[pid_idx(src_key)].clone();
    t[pid_idx(dst_key)] = src;
}

pub fn clear_vmas(pid: u32) {
    VMA_TABLE.lock()[pid_idx(pid)].clear();
}

// ── PROT_* / MAP_* constants ─────────────────────────────────────────────

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;

const MAP_FIXED: u32 = 0x10;
const MAP_ANON:  u32 = 0x20;
const PAGE:      usize = 4096;

// Virtual address bump allocator for anonymous/non-fixed mappings.
// Per-process VA management should eventually live in the PCB.
static NEXT_VA: AtomicUsize = AtomicUsize::new(0x5000_0000);

// BRK pointer — per-process; should move into PCB.
// AtomicUsize fixes the data race that `static mut BRK` had.
static BRK: AtomicUsize = AtomicUsize::new(0x2000_0000);

// ── sys_mmap ─────────────────────────────────────────────────────────────

pub fn sys_mmap(
    addr: usize, length: usize, prot: u32, flags: u32,
    fd:   usize, offset: usize,
) -> isize {
    if length == 0 { return -22; } // EINVAL
    let len = page_align_up(length);

    let va = if flags & MAP_FIXED != 0 {
        if addr == 0 { return -22; }
        addr
    } else {
        // Reserve VA space: bump by len + one guard page.
        let v = NEXT_VA.fetch_add(len + PAGE, Ordering::Relaxed);
        page_align_up(v)
    };

    let pte_flags = prot_to_flags(prot);
    let cr3 = <Arch as Paging>::kernel_cr3();

    // Map pages one by one; roll back on OOM.
    let mut mapped = 0usize;
    for page_va in (va..va + len).step_by(PAGE) {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                <Arch as Paging>::map_page(cr3, page_va, pa, pte_flags);
                mapped += 1;
            }
            None => {
                // Roll back already-mapped pages to avoid leaking.
                for rollback_va in (va..va + mapped * PAGE).step_by(PAGE) {
                    if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, rollback_va) {
                        <Arch as Paging>::unmap_page(rollback_va);
                        crate::mm::pmm::free_page(pa);
                    }
                }
                return -12; // ENOMEM
            }
        }
    }

    let pid = crate::proc::scheduler::current_pid() as u32;
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
    if addr & (PAGE - 1) != 0 { return -22; } // EINVAL: must be page-aligned
    let len = page_align_up(length);
    let cr3 = <Arch as Paging>::kernel_cr3();

    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::unmap_page(page_va) {
            crate::mm::pmm::free_page(pa);
        }
    }

    let pid = crate::proc::scheduler::current_pid() as u32;
    remove_vma(pid, addr, len);
    0
}

// ── sys_mprotect ──────────────────────────────────────────────────────────

pub fn sys_mprotect(addr: usize, length: usize, prot: u32) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    let len      = page_align_up(length);
    let cr3      = <Arch as Paging>::kernel_cr3();
    let new_flags = prot_to_flags(prot);

    for page_va in (addr..addr + len).step_by(PAGE) {
        if let Some(pa) = <Arch as Paging>::virt_to_phys(cr3, page_va) {
            <Arch as Paging>::map_page(cr3, page_va, pa, new_flags);
            <Arch as Paging>::flush_va(page_va);
        }
    }

    // Update VMA protection metadata.
    let pid = crate::proc::scheduler::current_pid() as u32;
    let mut t = VMA_TABLE.lock();
    for v in t[pid_idx(pid)].iter_mut() {
        if v.start < addr + len && v.end > addr {
            v.prot = prot;
        }
    }
    0
}

// ── sys_brk ───────────────────────────────────────────────────────────────

pub fn sys_brk(addr: usize) -> isize {
    let brk = BRK.load(Ordering::Relaxed);
    if addr == 0 || addr < brk { return brk as isize; }

    let new_brk = page_align_up(addr);
    let cr3     = <Arch as Paging>::kernel_cr3();

    for va in (brk..new_brk).step_by(PAGE) {
        if let Some(pa) = crate::mm::pmm::alloc_page() {
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
            <Arch as Paging>::map_page(
                cr3, va, pa,
                PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX,
            );
        }
        // On OOM we stop extending but do not return an error;
        // the process will fault on the unmapped page instead.
    }

    BRK.store(new_brk, Ordering::Relaxed);
    new_brk as isize
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Round `n` up to the next multiple of PAGE.
#[inline]
fn page_align_up(n: usize) -> usize {
    (n + PAGE - 1) & !(PAGE - 1)
}

/// Map POSIX PROT_* bits to arch-neutral HAL PageFlags.
#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}
