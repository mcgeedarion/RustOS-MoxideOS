//! Virtual Memory Area (VMA) tracker + mmap / munmap / mprotect / brk.
//!
//! VMAs are stored directly in the PCB (Pcb::vmas) so every process has
//! an independent VMA list with no hash-table collision risk.
//! The per-process VA bump pointer (Pcb::next_va) and brk (Pcb::brk)
//! are also PCB fields, eliminating the old process-global statics.
//!
//! ## Growable heap (sys_brk)
//!
//! The heap occupies the virtual address range [brk_base, brk) where:
//!
//!   * `brk_base` — set once at exec load time to the first page-aligned
//!     address above the ELF .bss section.  Never changes.
//!   * `brk` — the current program break.  Grows upward on `brk(addr > brk)`
//!     and shrinks downward on `brk(addr < brk)`.
//!
//! A single **guard page** at `brk_base - PAGE` is left permanently unmapped.
//! An off-by-one under-read therefore causes a clean page fault / SIGSEGV
//! instead of silently aliasing .bss.
//!
//! ### Grow path
//! Pages are eagerly allocated from the PMM (glibc expects brk pages to be
//! immediately readable). A full rollback returns `old_brk` unchanged on OOM
//! so `malloc` can fall through to `mmap(MAP_ANON)`.
//!
//! ### Shrink path
//! Pages in `[new_brk, old_brk)` are unmapped and returned to the PMM.
//! The heap VMA is updated (or removed if fully collapsed).
//!
//! ### VMA coalescing
//! Each `brk()` call extends the existing heap VMA in-place rather than
//! inserting a new entry.  The VMA list therefore stays O(1) for the heap
//! regardless of how many `sbrk(n)` increments the user-space malloc issues.
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
//! ## MAP_FIXED_NOREPLACE (Linux 4.17 / MAP_FIXED | 0x100000)
//!
//! Like MAP_FIXED but returns -EEXIST (-17) instead of silently clobbering
//! an existing mapping.  ld.so uses this for precise segment placement while
//! protecting itself against layout surprises.
//!
//! ## RLIMIT_AS enforcement
//!
//! sys_mmap and sys_brk both check the current process RLIMIT_AS soft limit
//! before committing any new mapping.  The check uses the sum of all existing
//! VMA sizes as the current AS usage.  Returns -ENOMEM (-12) on violation.

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
    /// Program break (heap) region. Treated identically to Anonymous for
    /// page-fault handling but tracked separately for /proc/<pid>/status.
    Heap,
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

impl Vma {
    #[inline]
    pub fn is_heap(&self) -> bool { matches!(self.kind, VmaKind::Heap) }
}

// ── PROT_* / MAP_* constants ─────────────────────────────────────────────────

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;

const MAP_SHARED:          u32 = 0x01;
const MAP_PRIVATE:         u32 = 0x02;
const MAP_FIXED:           u32 = 0x10;
pub const MAP_ANON:        u32 = 0x20;
const MAP_FIXED_NOREPLACE: u32 = 0x100000;
pub const PAGE:            usize = 4096;

// ── RLIMIT_AS helper ──────────────────────────────────────────────────────────

/// Sum of all VMA byte sizes for `pid`. Used as the current AS measure.
fn current_as_bytes(pid: usize) -> usize {
    scheduler::with_proc(pid, |p| {
        p.vmas.iter().map(|v| v.end - v.start).sum()
    }).unwrap_or(0)
}

/// Returns -12 (ENOMEM) if mapping `extra` more bytes would exceed RLIMIT_AS.
fn check_rlimit_as(pid: usize, extra: usize) -> isize {
    let over = scheduler::with_proc(pid, |p| {
        p.rlimits.exceeds_as(current_as_bytes(pid), extra)
    }).unwrap_or(false);
    if over { -12 } else { 0 }
}

// ── VMA helpers ──────────────────────────────────────────────────────────────

pub fn insert_vma(pid: usize, vma: Vma) {
    scheduler::with_proc_mut(pid, |p| {
        let idx = p.vmas
            .binary_search_by_key(&vma.start, |v| v.start)
            .unwrap_or_else(|i| i);
        p.vmas.insert(idx, vma);
    });
}

pub fn remove_vma(pid: usize, addr: usize, len: usize) {
    scheduler::with_proc_mut(pid, |p| {
        p.vmas.retain(|v| !(v.start < addr + len && v.end > addr));
    });
}

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

pub fn sys_mmap(
    addr: usize, length: usize, prot: u32, flags: u32,
    fd: usize, offset: usize,
) -> isize {
    if length == 0 { return -22; }
    let len = page_align_up(length);
    let pid = scheduler::current_pid();

    // ── RLIMIT_AS check ───────────────────────────────────────────────────
    // Checked before any allocation.  MAP_FIXED replacements still count
    // (Linux does the same — the old mapping is freed but the new one is
    // accounted, which may transiently exceed limits; accept that for now).
    let as_check = check_rlimit_as(pid, len);
    if as_check < 0 { return as_check; }

    // ── MAP_FIXED_NOREPLACE collision check ───────────────────────────────
    let is_fixed           = flags & MAP_FIXED           != 0;
    let is_fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;

    if is_fixed || is_fixed_noreplace {
        if addr == 0 || addr & (PAGE - 1) != 0 { return -22; }
        if is_fixed_noreplace {
            let collision = scheduler::with_proc(pid, |p| {
                p.vmas.iter().any(|v| v.start < addr + len && v.end > addr)
            }).unwrap_or(false);
            if collision { return -17; } // EEXIST
        }
    }

    // ── Detect GOP framebuffer physical mapping ───────────────────────────
    if flags & MAP_ANON == 0 {
        if let Some(info) = crate::drivers::gop::get() {
            let fb_phys = info.fb_phys as usize;
            let fb_size = crate::drivers::gop::fb_byte_size(&info);
            if offset >= fb_phys && offset < fb_phys + fb_size {
                let max_len  = fb_size - (offset - fb_phys);
                let safe_len = len.min(max_len);
                return mmap_phys(addr, safe_len, prot, flags, pid, offset as u64);
            }
        }
    }

    // ── Normal (anonymous or file-backed) path ────────────────────────────
    let (va, user_cr3) = scheduler::with_proc_mut(pid, |p| {
        let va = if is_fixed || is_fixed_noreplace {
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

    if is_fixed && !is_fixed_noreplace {
        remove_vma(pid, va, len);
    }

    let is_anon   = flags & MAP_ANON != 0 || fd == usize::MAX;
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
                    return -12;
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
        insert_vma(pid, Vma {
            start: va, end: va + len,
            prot, flags,
            kind: VmaKind::FileBacked(fd, offset as u64),
            file_offset: offset as u64,
        });
    }

    va as isize
}

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

    let pte_flags  = prot_to_flags(prot & !PROT_EXEC);
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
    let len       = page_align_up(length);
    let pid       = scheduler::current_pid();
    let new_flags = prot_to_flags(prot);
    let user_cr3  = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
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

    let (brk_base, old_brk, user_cr3) =
        scheduler::with_proc(pid, |p| (p.brk_base, p.brk, p.user_satp))
            .unwrap_or((0, 0, 0));

    if addr == 0 || addr <= brk_base { return old_brk as isize; }

    let new_brk = page_align_up(addr);
    if user_cr3 == 0 { return old_brk as isize; }

    let heap_pte_flags =
        PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER | PageFlags::NX;

    if new_brk > old_brk {
        // ── GROW — check RLIMIT_AS first ──────────────────────────────────
        let extra = new_brk - old_brk;
        let as_check = check_rlimit_as(pid, extra);
        if as_check < 0 { return old_brk as isize; }

        let grow_start = old_brk;
        let grow_end   = new_brk;
        let mut mapped_end = grow_start;

        for va in (grow_start..grow_end).step_by(PAGE) {
            match crate::mm::pmm::alloc_page() {
                Some(pa) => {
                    unsafe {
                        core::ptr::write_bytes(pa as *mut u8, 0, PAGE);
                    }
                    <Arch as Paging>::map_page(user_cr3, va, pa, heap_pte_flags);
                    <Arch as Paging>::flush_va(va);
                    mapped_end = va + PAGE;
                }
                None => {
                    for rollback_va in (grow_start..mapped_end).step_by(PAGE) {
                        if let Some(pa) =
                            <Arch as Paging>::virt_to_phys(user_cr3, rollback_va)
                        {
                            <Arch as Paging>::unmap_page(rollback_va);
                            <Arch as Paging>::flush_va(rollback_va);
                            crate::mm::pmm::free_page(pa);
                        }
                    }
                    return old_brk as isize;
                }
            }
        }

        scheduler::with_proc_mut(pid, |p| p.brk = new_brk);
        coalesce_or_insert_heap_vma(pid, brk_base, new_brk);

    } else if new_brk < old_brk {
        let real_new_brk = new_brk.max(brk_base);
        if real_new_brk == old_brk { return old_brk as isize; }

        let free_start = real_new_brk;
        let free_end   = old_brk;

        for va in (free_start..free_end).step_by(PAGE) {
            if let Some(pa) = <Arch as Paging>::virt_to_phys(user_cr3, va) {
                <Arch as Paging>::unmap_page(va);
                <Arch as Paging>::flush_va(va);
                crate::mm::pmm::free_page(pa);
            }
        }

        scheduler::with_proc_mut(pid, |p| p.brk = real_new_brk);
        trim_heap_vma(pid, brk_base, real_new_brk);
    }

    scheduler::with_proc(pid, |p| p.brk)
        .unwrap_or(old_brk) as isize
}

// ── set_brk_base ─────────────────────────────────────────────────────────────

pub fn set_brk_base(pid: usize, end_of_bss: usize) {
    let base = page_align_up(end_of_bss);
    let heap_start = base + PAGE;
    scheduler::with_proc_mut(pid, |p| {
        p.brk_base = heap_start;
        p.brk      = heap_start;
    });
}

// ── VMA coalescing helpers ────────────────────────────────────────────────────

fn coalesce_or_insert_heap_vma(pid: usize, brk_base: usize, new_brk: usize) {
    let extended = scheduler::with_proc_mut(pid, |p| {
        if let Some(v) = p.vmas.iter_mut().find(|v| v.is_heap() && v.start == brk_base) {
            v.end = new_brk;
            true
        } else {
            false
        }
    }).unwrap_or(false);

    if !extended {
        insert_vma(pid, Vma {
            start:       brk_base,
            end:         new_brk,
            prot:        PROT_READ | PROT_WRITE,
            flags:       MAP_ANON,
            kind:        VmaKind::Heap,
            file_offset: 0,
        });
    }
}

fn trim_heap_vma(pid: usize, brk_base: usize, new_brk: usize) {
    scheduler::with_proc_mut(pid, |p| {
        if new_brk <= brk_base {
            p.vmas.retain(|v| !v.is_heap());
        } else if let Some(v) = p.vmas.iter_mut().find(|v| v.is_heap()) {
            if new_brk > v.start {
                v.end = new_brk;
            }
        }
        p.vmas.retain(|v| !v.is_heap() || v.end > v.start);
    });
}

// ── helpers ───────────────────────────────────────────────────────────────────

#[inline]
pub fn page_align_up(n: usize) -> usize { (n + PAGE - 1) & !(PAGE - 1) }

#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}

// ── procfs helpers ────────────────────────────────────────────────────────────

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

pub fn heap_kb(pid: u32) -> usize {
    scheduler::with_proc(pid as usize, |p| {
        p.vmas.iter()
            .filter(|v| v.is_heap())
            .map(|v| (v.end - v.start) / 1024)
            .sum()
    }).unwrap_or(0)
}

pub fn current_brk(pid: u32) -> usize {
    scheduler::with_proc(pid as usize, |p| p.brk).unwrap_or(0)
}
