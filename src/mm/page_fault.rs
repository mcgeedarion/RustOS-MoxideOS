//! Demand-paging fault handler.
//!
//! Called from the arch IDT/trap handler when:
//!   - error_code bit 0 (P) == 0  — page not present
//!   - error_code bit 2 (U) == 1  — fault in user mode
//!
//! Arch-neutral: uses arch::Arch (Paging trait) throughout.
//!
//! Return convention
//! -----------------
//! `handle_demand_fault` returns `true` if the fault was resolved and the
//! faulting instruction should be retried. It returns `false` if the fault
//! could not be resolved; in that case, the appropriate signal (SIGSEGV or
//! SIGBUS) has already been queued on the current process before returning,
//! so the arch trap handler only needs to call `schedule()` or return to
//! user-space to let the signal fire at the next syscall exit.

use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::mm::mmap::{VmaKind, PROT_WRITE, PROT_EXEC, find_vma};
use crate::mm::pmm::{alloc_page, free_page};
use crate::proc::scheduler;
use crate::proc::signal::{send_signal_info, send_sigsegv, SigInfo};

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);

// SIGBUS si_code: hardware memory error at mapped address (POSIX BUS_ADRERR).
const SIGBUS:      u32 = 7;
const BUS_ADRERR:  i32 = 2;

/// Try to resolve a not-present user fault at `faulting_va`.
/// Returns `true` if the fault was handled and the instruction can be retried.
/// Returns `false` if unresolvable; the appropriate signal is already queued.
pub fn handle_demand_fault(faulting_va: usize) -> bool {
    let page_va = faulting_va & PAGE_MASK;
    let pid     = scheduler::current_pid();

    // O(log n) VMA lookup via binary search.
    let vma = match find_vma(pid, faulting_va) {
        Some(v) => v,
        None    => {
            send_sigsegv(pid, faulting_va);
            return false;
        }
    };

    // O(log n) CR3 fetch via pid_idx.
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 {
        send_sigsegv(pid, faulting_va);
        return false;
    }

    let pa = match alloc_page() {
        Some(p) => p,
        None    => {
            // OOM: no signal — let the arch handler deliver SIGKILL or panic.
            return false;
        }
    };

    match &vma.kind {
        VmaKind::Anonymous => {
            // alloc_page() guarantees zero-filled pages; nothing more needed.
        }
        VmaKind::FileBacked(fd, base_offset) => {
            // Zero first: alloc_page() zero-fills, but we document explicitly
            // that pread may not fill the whole page.
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }

            let file_off = (*base_offset + (page_va - vma.start) as u64) as i64;
            let n = crate::fs::vfs::pread(*fd, pa as *mut u8, PAGE_SIZE, file_off);

            // Any result < PAGE_SIZE means the file could not back this page:
            //   n <  0          — I/O error
            //   n == 0          — EOF with no bytes read
            //   0 < n < PAGE_SIZE — partial read (page extends beyond file end)
            // All three cases require SIGBUS per POSIX.
            if (n as usize) < PAGE_SIZE {
                free_page(pa);
                send_signal_info(pid, SigInfo {
                    sig:  SIGBUS,
                    code: BUS_ADRERR,
                    addr: faulting_va,
                    ..Default::default()
                });
                return false;
            }
        }
        VmaKind::Fixed => {
            // MAP_FIXED over an already-unmapped region — access violation.
            free_page(pa);
            send_sigsegv(pid, faulting_va);
            return false;
        }
    }

    let flags = prot_to_flags(vma.prot);
    <Arch as Paging>::map_page(user_cr3, page_va, pa, flags);
    <Arch as Paging>::flush_va(page_va);
    true
}

#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}
