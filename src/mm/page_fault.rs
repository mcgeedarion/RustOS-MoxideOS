//! Demand-paging fault handler.
//!
//! Called from arch/x86_64/idt::page_fault_handler when:
//!   - error_code bit 0 (P) == 0   → page not present
//!   - error_code bit 2 (U) == 1   → fault in user mode
//!
//! ## Fault resolution
//!
//!   Anonymous VMA (MAP_ANONYMOUS | MAP_PRIVATE, or stack, or brk heap):
//!     Alloc one physical page, zero it, map it with VMA prot flags.
//!     This is the "demand-zero" path — pages are not allocated until
//!     the first access.
//!
//!   FileBacked VMA (text/data/shared lib loaded by mmap):
//!     Alloc page, pread(fd, page_buf, 4096, file_offset + page_index*4096),
//!     zero any tail, map with VMA prot flags.
//!     This is the "demand-fill" path — ELF segments are paged in lazily.
//!
//!   No matching VMA → return false → caller delivers SIGSEGV.

use crate::mm::mmap::{find_vma, VmaKind, PROT_WRITE, PROT_EXEC};
use crate::mm::pmm::alloc_page;
use crate::arch::x86_64::paging::{map_page, current_cr3};
use crate::proc::{scheduler, thread};

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);

/// Try to resolve a not-present user fault at `faulting_va`.
/// Returns true if the fault was handled (page mapped); false if SEGFAULT.
pub fn handle_demand_fault(faulting_va: usize) -> bool {
    let page_va = faulting_va & PAGE_MASK;
    let pid     = thread::vma_pid(scheduler::current_pid());

    let vma = match find_vma(pid, faulting_va) {
        Some(v) => v,
        None    => return false,
    };

    let pa = match alloc_page() {
        Some(p) => p,
        None    => return false,
    };

    match &vma.kind {
        // ── Demand-zero (anonymous) ───────────────────────────────────────────
        VmaKind::Anonymous => {
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        }

        // ── Demand-fill (file-backed) ─────────────────────────────────────────
        VmaKind::FileBacked { fd, file_offset } => {
            let page_idx = (page_va - vma.start) / PAGE_SIZE;
            let file_pos = file_offset + page_idx * PAGE_SIZE;
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
            let _ = crate::fs::vfs::pread(*fd, pa as *mut u8, PAGE_SIZE, file_pos as i64);
        }

        // ── Memfd / DmaBuf: should be pre-mapped by mmap() ───────────────
        _ => {
            crate::mm::pmm::free_page(pa);
            return false;
        }
    }

    let pte = prot_to_pte(vma.prot);
    let cr3 = current_cr3();
    map_page(cr3, page_va, pa, pte);

    unsafe {
        core::arch::asm!("invlpg [{v}]", v = in(reg) page_va, options(nostack));
    }

    true
}

/// Convert POSIX PROT_* to x86-64 PTE flags.
///   bit 0  = Present (always)
///   bit 1  = Writable  (PROT_WRITE)
///   bit 2  = User      (always, demand faults are user-mode only)
///   bit 63 = NX        (set unless PROT_EXEC)
#[inline]
fn prot_to_pte(prot: u32) -> u64 {
    let mut f: u64 = 1 | (1 << 2);
    if prot & PROT_WRITE != 0 { f |= 1 << 1; }
    if prot & PROT_EXEC  == 0 { f |= 1u64 << 63; }
    f
}
