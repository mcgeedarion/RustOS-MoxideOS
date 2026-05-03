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
//!     This is the "demand-zero" path.
//!
//!   FileBacked VMA (text/data/shared lib loaded by mmap):
//!     Alloc page, pread(fd, page_buf, 4096, file_offset + page_index*4096),
//!     zero any tail, map with VMA prot flags.
//!     This is the "demand-fill" path.
//!
//!   No matching VMA → return false → caller delivers SIGSEGV.

use crate::mm::mmap::{find_vma, VmaKind, PROT_WRITE, PROT_EXEC};
use crate::mm::pmm::alloc_page;
use crate::arch::x86_64::paging::{map_page, current_cr3, invlpg};
use crate::proc::{scheduler, thread};

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);

/// Try to resolve a not-present user fault at `faulting_va`.
/// Returns true if the fault was handled; false if SIGSEGV.
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
        // ── Demand-zero (anonymous / stack / heap) ───────────────────────────
        VmaKind::Anonymous => {
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        }

        // ── Demand-fill (file-backed: ELF text/data segments) ─────────────────
        // VmaKind::FileBacked(fd, base_file_offset) — tuple variant.
        VmaKind::FileBacked(fd, base_offset) => {
            let page_idx = (page_va - vma.start) / PAGE_SIZE;
            let file_pos = base_offset + page_idx as u64 * PAGE_SIZE as u64;
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
            let _ = crate::fs::vfs::pread(*fd, pa as *mut u8, PAGE_SIZE, file_pos as i64);
        }

        // Fixed / other regions should already be mapped by mmap()
        VmaKind::Fixed => {
            crate::mm::pmm::free_page(pa);
            return false;
        }
    }

    let pte = prot_to_pte(vma.prot);
    let cr3 = current_cr3();
    map_page(cr3, page_va, pa, pte);
    invlpg(page_va);
    true
}

/// POSIX PROT_* → x86-64 PTE flags.
#[inline]
fn prot_to_pte(prot: u32) -> u64 {
    let mut f: u64 = 1 | (1 << 2); // Present | User
    if prot & PROT_WRITE != 0 { f |= 1 << 1; }  // Writable
    if prot & PROT_EXEC  == 0 { f |= 1u64 << 63; } // NX
    f
}
