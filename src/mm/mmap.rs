//! Virtual memory area (VMA) tracker + mmap / munmap / mprotect / brk.
//!
//! Each process has a per-PCB VMA list stored in the scheduler's PCB.
//!
//! VMA kinds:
//!   Anonymous   — zero-filled private memory (heap, stack, anon mmap)
//!   FileBacked  — file-backed mapping (text, data, shared libs)
//!   Memfd       — memory-file mapping
//!   DmaBuf      — GPU DMA-BUF import
//!
//! Each mmap() call appends a Vma to the per-process list.  munmap() removes
//! the intersecting VMAs (with split if partial).  The page-fault handler
//! queries this list to decide whether to demand-zero or copy-on-write.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;
use alloc::collections::BTreeMap;

// ── VMA descriptor ────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
pub enum VmaKind {
    Anonymous,
    FileBacked { fd: usize, file_offset: usize },
    Memfd      { fd: usize, offset_base: usize },
    DmaBuf     { handle: u32 },
}

pub const PROT_READ:  u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC:  u32 = 4;
pub const PROT_NONE:  u32 = 0;

pub const MAP_SHARED:    u32 = 0x01;
pub const MAP_PRIVATE:   u32 = 0x02;
pub const MAP_FIXED:     u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_GROWSDOWN: u32 = 0x100;
pub const MAP_POPULATE:  u32 = 0x08000;

#[derive(Clone)]
pub struct Vma {
    pub start: usize,
    pub end:   usize,
    pub prot:  u32,
    pub flags: u32,
    pub kind:  VmaKind,
}

// ── Global VMA table (pid → vec of VMAs) ────────────────────────────────

static VMAS: Mutex<BTreeMap<u32, Vec<Vma>>> = Mutex::new(BTreeMap::new());

pub fn insert_vma(pid: u32, vma: Vma) {
    VMAS.lock().entry(pid).or_default().push(vma);
}

pub fn remove_vma(pid: u32, addr: usize, len: usize) {
    let end = addr + len;
    let mut t = VMAS.lock();
    if let Some(list) = t.get_mut(&pid) {
        list.retain(|v| v.end <= addr || v.start >= end);
    }
}

pub fn find_vma(pid: u32, addr: usize) -> Option<Vma> {
    VMAS.lock().get(&pid)?.iter()
        .find(|v| v.start <= addr && addr < v.end)
        .cloned()
}

/// Remove all VMA entries for `pid` and unmap + free all anonymous physical
/// pages.  Called by execve() before installing the new address space so the
/// page-fault handler never sees stale entries.
pub fn clear_vmas(pid: u32) {
    let vmas: Vec<Vma> = {
        let mut t = VMAS.lock();
        t.remove(&pid).unwrap_or_default()
    };
    for vma in &vmas {
        let pages = (vma.end - vma.start) / 4096;
        for i in 0..pages {
            let va = vma.start + i * 4096;
            if let Some(pa) = crate::arch::x86_64::paging::unmap_page(va) {
                if pa != 0 && !matches!(vma.kind, VmaKind::FileBacked { .. }) {
                    crate::mm::pmm::free_page(pa);
                }
            }
        }
    }
}

// ── mmap ──────────────────────────────────────────────────────────────────

/// Find a free virtual address region of `size` bytes starting above `hint`.
fn find_free_region(hint: usize, size: usize, pid: u32) -> usize {
    let base = if hint != 0 { (hint + 0xFFF) & !0xFFF } else { 0x0000_7000_0000_0000usize };
    let t = VMAS.lock();
    let list = match t.get(&pid) { Some(l) => l, None => return base };
    let mut candidate = base;
    'outer: loop {
        for v in list {
            if v.start < candidate + size && v.end > candidate {
                candidate = (v.end + 0xFFF) & !0xFFF;
                continue 'outer;
            }
        }
        break candidate;
    }
}

pub fn sys_mmap(
    addr:   usize,
    length: usize,
    prot:   u32,
    flags:  u32,
    fd:     usize,
    offset: usize,
) -> isize {
    if length == 0 { return -22; }
    let size   = (length + 0xFFF) & !0xFFF;
    let pid    = crate::proc::scheduler::current_pid();
    let va     = if flags & MAP_FIXED != 0 && addr != 0 { addr }
                 else { find_free_region(addr, size, pid) };

    let anon = flags & MAP_ANONYMOUS != 0 || fd == usize::MAX;

    if anon {
        // Demand-zero: allocate pages now (simplifies page-fault handler)
        let pages = size / 4096;
        for i in 0..pages {
            let pa = match crate::mm::pmm::alloc_page() {
                Some(p) => p, None => return -12,
            };
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096); }
            let flags_pte = pte_flags(prot);
            crate::arch::x86_64::paging::map_page(
                crate::arch::x86_64::paging::current_cr3(),
                va + i * 4096, pa, flags_pte);
        }
        insert_vma(pid, Vma { start: va, end: va + size, prot, flags, kind: VmaKind::Anonymous });
        return va as isize;
    }

    // File-backed: check for memfd or DMA-BUF
    if crate::mm::memfd::is_memfd(fd) {
        return sys_mmap_memfd(va, size, prot, flags, fd, offset);
    }
    if crate::drivers::amdgpu_gem::is_gem_fd(fd) {
        return sys_mmap_dmabuf(va, size, prot, fd);
    }

    // Regular file-backed mapping: read file pages into RAM
    let pages = size / 4096;
    for i in 0..pages {
        let pa = match crate::mm::pmm::alloc_page() { Some(p) => p, None => return -12 };
        let file_off = offset + i * 4096;
        let read_len = crate::fs::vfs::pread(fd, pa as *mut u8, 4096, file_off as i64)
            .max(0) as usize;
        if read_len < 4096 {
            unsafe { core::ptr::write_bytes((pa + read_len) as *mut u8, 0, 4096 - read_len); }
        }
        let flags_pte = pte_flags(prot);
        crate::arch::x86_64::paging::map_page(
            crate::arch::x86_64::paging::current_cr3(),
            va + i * 4096, pa, flags_pte);
    }
    insert_vma(pid, Vma {
        start: va, end: va + size, prot, flags,
        kind: VmaKind::FileBacked { fd, file_offset: offset },
    });
    va as isize
}

fn sys_mmap_memfd(va: usize, size: usize, prot: u32, flags: u32, fd: usize, offset: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let pages = size / 4096;
    for i in 0..pages {
        match crate::mm::memfd::map_page(fd, offset / 4096 + i) {
            Some(pa) => {
                let flags_pte = pte_flags(if flags & MAP_SHARED != 0 { prot } else { prot });
                crate::arch::x86_64::paging::map_page(
                    crate::arch::x86_64::paging::current_cr3(),
                    va + i * 4096, pa, flags_pte);
            }
            None => return -12,
        }
    }
    insert_vma(pid, Vma {
        start: va, end: va + size, prot, flags,
        kind: VmaKind::Memfd { fd, offset_base: offset },
    });
    va as isize
}

fn sys_mmap_dmabuf(va: usize, size: usize, prot: u32, _flags: u32, fd: usize) -> isize {
    let pid  = crate::proc::scheduler::current_pid();
    let handle = crate::drivers::amdgpu_gem::fd_to_handle(fd).unwrap_or(0);
    if let Some(bo) = crate::drivers::gem::gem_lookup(handle) {
        let pages = size.min(bo.size) / 4096;
        for i in 0..pages {
            let pa = bo.pa + i * 4096;
            crate::arch::x86_64::paging::map_page(
                crate::arch::x86_64::paging::current_cr3(),
                va + i * 4096, pa, pte_flags(prot));
        }
    }
    insert_vma(pid, Vma {
        start: va, end: va + size, prot, flags: 0,
        kind: VmaKind::DmaBuf { handle },
    });
    va as isize
}

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    if addr & 0xFFF != 0 { return -22; }
    let size  = (length + 0xFFF) & !0xFFF;
    let pages = size / 4096;
    let pid   = crate::proc::scheduler::current_pid();
    let cr3   = crate::arch::x86_64::paging::current_cr3();
    for i in 0..pages {
        let va = addr + i * 4096;
        if let Some(pa) = crate::arch::x86_64::paging::unmap_page(va) {
            if pa != 0 {
                if let Some(vma) = find_vma(pid, va) {
                    if matches!(vma.kind, VmaKind::Anonymous) {
                        crate::mm::pmm::free_page(pa);
                    }
                } else {
                    crate::mm::pmm::free_page(pa);
                }
            }
        }
        // Invalidate TLB entry
        unsafe { core::arch::asm!("invlpg [{v}]", v = in(reg) va, options(nostack)); }
        let _ = cr3;
    }
    remove_vma(pid, addr, size);
    0
}

pub fn sys_brk(addr: usize) -> isize {
    // Lazy brk: just return the requested address (demand-zero on fault)
    let pid = crate::proc::scheduler::current_pid();
    static BRK: spin::Mutex<BTreeMap<u32, usize>> = spin::Mutex::new(BTreeMap::new());
    let mut brk = BRK.lock();
    let cur = *brk.entry(pid).or_insert(0x0001_0000_0000usize);
    if addr == 0 { return cur as isize; }
    if addr > cur {
        let size = (addr - cur + 0xFFF) & !0xFFF;
        let pages = size / 4096;
        for i in 0..pages {
            let va = cur + i * 4096;
            let pa = match crate::mm::pmm::alloc_page() { Some(p) => p, None => return cur as isize };
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096); }
            crate::arch::x86_64::paging::map_page(
                crate::arch::x86_64::paging::current_cr3(), va, pa, 0x7);
        }
        insert_vma(pid, Vma {
            start: cur, end: cur + size, prot: PROT_READ | PROT_WRITE, flags: MAP_ANONYMOUS | MAP_PRIVATE,
            kind: VmaKind::Anonymous,
        });
    }
    *brk.entry(pid).or_insert(addr) = addr;
    addr as isize
}

// ── PTE flag helpers ─────────────────────────────────────────────────────

fn pte_flags(prot: u32) -> u64 {
    let mut f: u64 = 1; // Present
    if prot & PROT_WRITE != 0 { f |= 1 << 1; } // Write
    if prot & PROT_EXEC  == 0 { f |= 1 << 63; } // NX
    f |= 1 << 2; // User
    f
}
