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
//!
//! ## Physical mappings (VmaKind::PhysMap)
//!
//! The GOP framebuffer (and any other MMIO region that userspace needs to
//! mmap directly) uses `VmaKind::PhysMap(phys_base)`.  These VMAs differ
//! from anonymous VMAs in two important ways:
//!
//!   1. Pages are mapped with the supplied physical address directly —
//!      no PMM allocation happens.
//!   2. munmap of a PhysMap VMA does NOT return pages to the PMM because
//!      the kernel never owned them.
//!
//! ## How a Wayland compositor / libdrm gets the framebuffer
//!
//!   DRM_IOCTL_MODE_MAP_DUMB  → returns `offset` = GOP fb_phys
//!   mmap(0, size, PROT_RW, MAP_SHARED, drm_fd, offset)
//!       → sys_mmap detects offset == GOP fb_phys → PhysMap path
//!       → pages mapped 1:1 to fb_phys .. fb_phys+size
//!   userspace pointer lands directly on the GOP linear framebuffer

extern crate alloc;
use alloc::vec::Vec;
use crate::arch::{Arch, api::{PageFlags, Paging}};
use crate::proc::scheduler;

// ── VMA descriptor ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum VmaKind {
    Anonymous,
    /// fd-backed file mapping: (fd, file_offset)
    FileBacked(usize, u64),
    /// Fixed kernel-internal mapping (no backing store).
    Fixed,
    /// Direct physical mapping — pages are NOT PMM-owned.
    /// Contains the physical address of the first mapped byte.
    PhysMap(u64),
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

// ── PROT_* / MAP_* constants ─────────────────────────────────────────────────

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;

const MAP_SHARED:  u32 = 0x01;
const MAP_PRIVATE: u32 = 0x02;
const MAP_FIXED:   u32 = 0x10;
const MAP_ANON:    u32 = 0x20;
const PAGE:        usize = 4096;

// ── VMA helpers ──────────────────────────────────────────────────────────────

/// Insert a VMA in sorted order by start address.
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
        let idx = vmas.partition_point(|v| v.start <= addr);
        if idx == 0 { return None; }
        let v = &vmas[idx - 1];
        if addr < v.end { Some(v.clone()) } else { None }
    }).flatten()
}

pub fn clone_vmas(src_pid: usize, dst_pid: usize) {
    let src_vmas: Vec<Vma> = scheduler::with_proc(src_pid, |p| p.vmas.clone())
        .unwrap_or_default();
    scheduler::with_proc_mut(dst_pid, |p| p.vmas = src_vmas);
}

fn clear_vmas_internal(pid: usize) {
    scheduler::with_proc_mut(pid, |p| p.vmas.clear());
}

// ── free_address_space ───────────────────────────────────────────────────────

pub fn free_address_space(pid: usize, user_cr3: usize) {
    if user_cr3 == 0 { return; }

    let vmas: Vec<Vma> = scheduler::with_proc(pid, |p| p.vmas.clone())
        .unwrap_or_default();

    for vma in &vmas {
        // PhysMap VMAs are MMIO / framebuffer — the kernel does not own
        // those physical pages, so never feed them back to the PMM.
        let is_phys = matches!(vma.kind, VmaKind::PhysMap(_));
        for va in (vma.start..vma.end).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, va) {
                <Arch as Paging>::unmap_page(va);
                if !is_phys {
                    crate::mm::pmm::free_page(pa);
                }
            }
        }
    }

    <Arch as Paging>::free_page_table(user_cr3);
    clear_vmas_internal(pid);
    scheduler::with_proc_mut(pid, |p| p.user_satp = 0);
}

// ── sys_mmap ─────────────────────────────────────────────────────────────────
//
// Three mapping kinds are handled:
//
//   1. MAP_ANON (or fd == usize::MAX) — allocate PMM pages, zero-fill.
//   2. PhysMap  — `offset` falls within the GOP framebuffer physical range.
//                 Map pages 1:1 to the physical range; no PMM involvement.
//   3. FileBacked — fd-backed; VMA registered, pages faulted lazily.

pub fn sys_mmap(
    addr: usize, length: usize, prot: u32, flags: u32,
    fd: usize, offset: usize,
) -> isize {
    if length == 0 { return -22; }
    let len = page_align_up(length);
    let pid = scheduler::current_pid();

    // ── Detect GOP framebuffer physical mapping ───────────────────────────
    // libdrm calls mmap(0, size, PROT_RW, MAP_SHARED, drm_fd, phys_offset)
    // where phys_offset == GOP fb_phys (returned by DRM_IOCTL_MODE_MAP_DUMB).
    // Detect by checking whether `offset` falls inside the GOP FB region.
    if flags & MAP_ANON == 0 {
        if let Some(info) = crate::drivers::gop::get() {
            let fb_phys = info.fb_phys as usize;
            let fb_size = crate::drivers::gop::fb_byte_size(&info);
            if offset >= fb_phys && offset < fb_phys + fb_size {
                return mmap_phys(addr, len, prot, flags, pid, offset as u64);
            }
        }
    }

    // ── Normal (anonymous or file-backed) path ────────────────────────────
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

    if va == 0       { return -22; }
    if user_cr3 == 0 { return -12; }

    if flags & MAP_FIXED != 0 {
        remove_vma(pid, va, len);
    }

    let is_anon  = flags & MAP_ANON != 0 || fd == usize::MAX;
    let pte_flags = prot_to_flags(prot);

    if is_anon {
        let mut mapped = 0usize;
        for page_va in (va..va + len).step_by(PAGE) {
            match crate::mm::pmm::alloc_page() {
                Some(pa) => {
                    <Arch as Paging>::map_page(user_cr3, page_va, pa, pte_flags);
                    mapped += 1;
                }
                None => {
                    for rollback_va in (va..va + mapped * PAGE).step_by(PAGE) {
                        if let Some(pa) =
                            <Arch as Paging>::virt_to_phys(user_cr3, rollback_va)
                        {
                            <Arch as Paging>::unmap_page(rollback_va);
                            crate::mm::pmm::free_page(pa);
                        }
                    }
                    return -12; // ENOMEM
                }
            }
        }
        insert_vma(pid, Vma {
            start: va, end: va + len,
            prot, flags,
            kind: VmaKind::Anonymous,
            file_offset: 0,
        });
    } else {
        // File-backed — register VMA; pages faulted lazily by page_fault.rs.
        insert_vma(pid, Vma {
            start: va, end: va + len,
            prot, flags,
            kind: VmaKind::FileBacked(fd, offset as u64),
            file_offset: offset as u64,
        });
    }

    va as isize
}

/// Map `len` bytes of physical memory at `offset` (= phys address) into the
/// current process address space without touching the PMM.
/// PROT_EXEC is silently stripped — framebuffer pages are never executable.
fn mmap_phys(
    addr:   usize,
    len:    usize,
    prot:   u32,
    flags:  u32,
    pid:    usize,
    offset: u64,
) -> isize {
    let (va, user_cr3) = scheduler::with_proc_mut(pid, |p| {
        let va = if flags & MAP_FIXED != 0 {
            if addr == 0 { return (0usize, 0usize); }
            addr
        } else {
            let v = p.next_va;
            p.next_va = page_align_up(v + len + PAGE);
            v
        };
        (va, p.user_satp)
    }).unwrap_or((0, 0));

    if va == 0       { return -22; }
    if user_cr3 == 0 { return -12; }

    if flags & MAP_FIXED != 0 {
        remove_vma(pid, va, len);
    }

    let pte_flags = prot_to_flags(prot & !PROT_EXEC);
    let phys_start = offset as usize;
    for (i, page_va) in (va..va + len).step_by(PAGE).enumerate() {
        <Arch as Paging>::map_page(user_cr3, page_va, phys_start + i * PAGE, pte_flags);
    }

    insert_vma(pid, Vma {
        start: va, end: va + len,
        prot: prot & !PROT_EXEC,
        flags,
        kind: VmaKind::PhysMap(offset),
        file_offset: offset,
    });

    va as isize
}

// ── sys_munmap ───────────────────────────────────────────────────────────────

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    if addr & (PAGE - 1) != 0 { return -22; }
    let len = page_align_up(length);
    let pid = scheduler::current_pid();

    // Collect physical VMA ranges in [addr, addr+len) before unmapping
    // so we know which pages to skip PMM-freeing.
    let phys_ranges: Vec<(usize, usize)> = scheduler::with_proc(pid, |p| {
        p.vmas.iter()
            .filter(|v| {
                matches!(v.kind, VmaKind::PhysMap(_))
                    && v.start < addr + len
                    && v.end   > addr
            })
            .map(|v| (v.start.max(addr), v.end.min(addr + len)))
            .collect()
    }).unwrap_or_default();

    for page_va in (addr..addr + len).step_by(PAGE) {
        let is_phys = phys_ranges.iter().any(|&(s, e)| page_va >= s && page_va < e);
        if is_phys {
            // Unmap but do NOT free the physical page — it belongs to GOP.
            <Arch as Paging>::unmap_page(page_va);
        } else if let Some(pa) = <Arch as Paging>::unmap_page(page_va) {
            crate::mm::pmm::free_page(pa);
        }
    }

    remove_vma(pid, addr, len);
    0
}

// ── sys_mprotect ─────────────────────────────────────────────────────────────

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
            if v.start >= addr + len { break; }
            if v.start < addr + len && v.end > addr {
                v.prot = prot;
            }
        }
    });
    0
}

// ── sys_brk ──────────────────────────────────────────────────────────────────

pub fn sys_brk(addr: usize) -> isize {
    let pid = scheduler::current_pid();
    let (old_brk, user_cr3) = scheduler::with_proc(pid, |p| (p.brk, p.user_satp))
        .unwrap_or((0, 0));
    if addr == 0 || addr <= old_brk { return old_brk as isize; }
    let new_brk = page_align_up(addr);

    for va in (old_brk..new_brk).step_by(PAGE) {
        if let Some(pa) = crate::mm::pmm::alloc_page() {
            <Arch as Paging>::map_page(
                user_cr3, va, pa,
                PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX,
            );
        }
    }

    scheduler::with_proc_mut(pid, |p| p.brk = new_brk);

    insert_vma(pid, Vma {
        start:       old_brk,
        end:         new_brk,
        prot:        PROT_READ | PROT_WRITE,
        flags:       MAP_ANON,
        kind:        VmaKind::Anonymous,
        file_offset: 0,
    });

    new_brk as isize
}

// ── helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn page_align_up(n: usize) -> usize { (n + PAGE - 1) & !(PAGE - 1) }

#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}

// ── procfs helpers (called from procfs.rs) ────────────────────────────────────

pub fn with_vmas<F: FnMut(&Vma)>(pid: u32, mut f: F) {
    scheduler::with_proc(pid as usize, |p| {
        for v in &p.vmas { f(v); }
    });
}

pub fn vma_total_kb(pid: u32) -> usize {
    scheduler::with_proc(pid as usize, |p| {
        p.vmas.iter().map(|v| (v.end - v.start) / 1024).sum()
    }).unwrap_or(0)
}
