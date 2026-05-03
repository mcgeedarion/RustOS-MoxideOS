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
use spin::Mutex;

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
    pub start: usize,
    pub end:   usize,
    pub prot:  u32,
    pub flags: u32,
    pub kind:  VmaKind,
    pub file_offset: u64,
}

// ── Global VMA table (keyed by pid % MAX_PROCS) ──────────────────────────

const MAX_PROCS: usize = 256;
static VMA_TABLE: Mutex<[Vec<Vma>; MAX_PROCS]> =
    Mutex::new([const { Vec::new() }; MAX_PROCS]);

#[inline]
fn pid_idx(pid: u32) -> usize { pid as usize % MAX_PROCS }

pub fn insert_vma(pid: u32, vma: Vma) {
    let mut t = VMA_TABLE.lock();
    t[pid_idx(pid)].push(vma);
}

pub fn remove_vma(pid: u32, addr: usize, len: usize) {
    let mut t = VMA_TABLE.lock();
    let list  = &mut t[pid_idx(pid)];
    list.retain(|v| !(v.start < addr + len && v.end > addr));
}

pub fn find_vma(pid: u32, addr: usize) -> Option<Vma> {
    let t = VMA_TABLE.lock();
    t[pid_idx(pid)].iter().find(|v| v.start <= addr && addr < v.end).cloned()
}

pub fn clone_vmas(src_key: u32, dst_key: u32) {
    let mut t = VMA_TABLE.lock();
    let src: Vec<Vma> = t[pid_idx(src_key)].clone();
    t[pid_idx(dst_key)] = src;
}

pub fn clear_vmas(pid: u32) {
    let mut t = VMA_TABLE.lock();
    t[pid_idx(pid)].clear();
}

// ── PROT_* / MAP_* constants (pub so page_fault.rs and others can use them) ─

pub const PROT_READ:    u32 = 1;
pub const PROT_WRITE:   u32 = 2;
pub const PROT_EXEC:    u32 = 4;
const MAP_SHARED:   u32 = 1;
const MAP_PRIVATE:  u32 = 2;
const MAP_FIXED:    u32 = 0x10;
const MAP_ANON:     u32 = 0x20;
const PAGE:         usize = 4096;

// ── sys_mmap ─────────────────────────────────────────────────────────────

pub fn sys_mmap(
    addr:   usize, length: usize, prot: u32, flags: u32,
    fd:     usize, offset: usize,
) -> isize {
    if length == 0 { return -22; } // EINVAL
    let len = (length + PAGE - 1) & !(PAGE - 1);

    static NEXT_VA: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0x5000_0000);
    let va = if flags & MAP_FIXED != 0 {
        if addr == 0 { return -22; }
        addr
    } else {
        let v = NEXT_VA.fetch_add(len + PAGE, core::sync::atomic::Ordering::Relaxed);
        (v + PAGE - 1) & !(PAGE - 1)
    };

    let pte_flags = prot_to_pte(prot);
    let cr3 = crate::arch::x86_64::paging::current_cr3();

    for page_va in (va..va+len).step_by(PAGE) {
        match crate::mm::pmm::alloc_page() {
            Some(pa) => {
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
                crate::arch::x86_64::paging::map_page(cr3, page_va, pa, pte_flags);
            }
            None => return -12,
        }
    }

    let pid = crate::proc::scheduler::current_pid() as u32;
    insert_vma(pid, Vma {
        start: va, end: va + len,
        prot, flags,
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
    let len = (length + PAGE - 1) & !(PAGE - 1);
    let cr3 = crate::arch::x86_64::paging::current_cr3();
    for page_va in (addr..addr+len).step_by(PAGE) {
        if let Some(pa) = crate::arch::x86_64::paging::unmap_page(page_va) {
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
    let len     = (length + PAGE - 1) & !(PAGE - 1);
    let cr3     = crate::arch::x86_64::paging::current_cr3();
    let new_pte = prot_to_pte(prot);

    for page_va in (addr..addr+len).step_by(PAGE) {
        if let Some(pa) = crate::arch::x86_64::paging::virt_to_phys(cr3, page_va) {
            crate::arch::x86_64::paging::map_page(cr3, page_va, pa, new_pte);
            crate::arch::x86_64::paging::invlpg(page_va);
        }
    }
    let pid = crate::proc::scheduler::current_pid() as u32;
    {
        let mut t = VMA_TABLE.lock();
        for v in t[pid_idx(pid)].iter_mut() {
            if v.start < addr + len && v.end > addr { v.prot = prot; }
        }
    }
    0
}

// ── sys_brk ───────────────────────────────────────────────────────────────

static mut BRK: usize = 0x2000_0000;

pub fn sys_brk(addr: usize) -> isize {
    unsafe {
        if addr == 0 { return BRK as isize; }
        if addr < BRK { return BRK as isize; }
        let old = BRK;
        let new = (addr + PAGE - 1) & !(PAGE - 1);
        let cr3 = crate::arch::x86_64::paging::current_cr3();
        for va in (old..new).step_by(PAGE) {
            if let Some(pa) = crate::mm::pmm::alloc_page() {
                core::ptr::write_bytes(pa as *mut u8, 0, PAGE);
                crate::arch::x86_64::paging::map_page(
                    cr3, va, pa,
                    crate::arch::x86_64::paging::PTE_PRESENT
                    | crate::arch::x86_64::paging::PTE_WRITABLE
                    | crate::arch::x86_64::paging::PTE_USER
                    | crate::arch::x86_64::paging::PTE_NX,
                );
            }
        }
        BRK = new;
        BRK as isize
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

fn prot_to_pte(prot: u32) -> u64 {
    let mut f = crate::arch::x86_64::paging::PTE_PRESENT
              | crate::arch::x86_64::paging::PTE_USER;
    if prot & PROT_WRITE != 0 { f |= crate::arch::x86_64::paging::PTE_WRITABLE; }
    if prot & PROT_EXEC  == 0 { f |= crate::arch::x86_64::paging::PTE_NX; }
    f
}
