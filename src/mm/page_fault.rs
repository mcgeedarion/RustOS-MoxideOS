//! Demand-paging fault handler — arch-neutral.
//!
//! Called from the arch IDT/trap handler when:
//!   - error_code bit 0 (P) == 0  — page not present
//!   - error_code bit 2 (U) == 1  — fault in user mode
//!
//! Arch-neutral: uses `Arch as Paging` throughout, so both x86_64 and
//! RISC-V share this single implementation. The only arch-specific bits
//! are `map_page` and `flush_va` — both are trait methods.
//!
//! ## File-backed VMA fault handling
//!
//! For `VmaKind::FileBacked(fd, base_offset)` the fault handler:
//!
//!   1. Allocates a fresh physical page from the PMM.
//!   2. Zero-initialises the entire page so any unread suffix is clean.
//!   3. Issues a `vfs::pread` for exactly PAGE_SIZE bytes at the correct
//!      file offset.
//!   4. Classifies the result:
//!
//!      ```
//!      n < 0              → I/O error (EBADF, EIO, …) → free pa, SIGBUS
//!      n == 0             → read at/past EOF           → zero page is fine, map it
//!      0 < n < PAGE_SIZE  → partial read (last page)   → tail already zero, map it
//!      n == PAGE_SIZE     → full page                  → map it
//!      ```
//!
//!      The key correctness rule: **only a negative return is an error**.
//!      A short-but-non-negative read means the file ended inside this page,
//!      which is normal and correct — the caller sees zeroes beyond the file.
//!      The old code treated `n < PAGE_SIZE` as an error, which caused SIGBUS
//!      on every ELF whose last segment page is not exactly 4 KiB-aligned.
//!
//! ## Return convention
//!
//! `handle_demand_fault` returns `true` if the fault was resolved and the
//! faulting instruction should be retried.  It returns `false` if the fault
//! could not be resolved; in that case, the appropriate signal (SIGSEGV or
//! SIGBUS) has already been queued on the current process before returning,
//! so the arch trap handler only needs to call `schedule()` or return to
//! user-space to let the signal fire at the next syscall exit.

use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::mm::mmap::{VmaKind, PROT_WRITE, PROT_EXEC, find_vma};
use crate::mm::pmm::{alloc_page, free_page};
use crate::proc::scheduler;
use crate::proc::signal::{send_signal, send_signal_info, send_sigsegv, SigInfo};

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);

// SIGBUS si_code: hardware memory error at mapped address (POSIX BUS_ADRERR).
const SIGBUS:     u32 = 7;
const BUS_ADRERR: i32 = 2;

/// Try to resolve a not-present user fault at `faulting_va`.
///
/// Returns `true` if the fault was handled and the instruction can be retried.
/// Returns `false` if unresolvable; the appropriate signal is already queued.
///
/// Both x86_64 and RISC-V call this function from their respective trap
/// handlers — no per-arch code is needed here.
pub fn handle_demand_fault(faulting_va: usize) -> bool {
    let page_va = faulting_va & PAGE_MASK;
    let pid     = scheduler::current_pid();

    let vma = match find_vma(pid, faulting_va) {
        Some(v) => v,
        None    => {
            send_sigsegv(pid, faulting_va);
            return false;
        }
    };

    // `user_satp` doubles as CR3 on x86_64 (same field name in the PCB;
    // the Paging trait methods interpret the value correctly per arch).
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 {
        send_sigsegv(pid, faulting_va);
        return false;
    }

    // For PhysMap VMAs the allocated page is immediately returned to the PMM
    // (we re-use the physical address in the VMA instead). For all other
    // kinds we keep it.
    let pa = match alloc_page() {
        Some(p) => p,
        None    => {
            // OOM: deliver SIGKILL so the process is reaped rather than
            // spinning forever retrying the faulting instruction.
            send_signal(pid, 9 /* SIGKILL */);
            return false;
        }
    };

    match &vma.kind {

        VmaKind::Anonymous | VmaKind::Heap | VmaKind::Stack => {
            // alloc_page() guarantees a zero-filled page; nothing more needed.
        }

        // This arm handles both x86_64 and RISC-V identically: `pread` is
        // the shared arch-neutral VFS call and `map_page`/`flush_va` are
        // Paging trait methods dispatched at compile time per arch.
        VmaKind::FileBacked(fd, base_offset) => {
            // Step A — pre-zero the full page so the suffix beyond EOF is
            // already clean before we issue the read.
            // SAFETY: `pa` is a freshly allocated kernel-owned page frame.
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }

            // Step B — compute the byte offset of this page in the file.
            //   page_index = (page_va - vma.start) / PAGE_SIZE
            //   file_off   = base_offset + page_index * PAGE_SIZE
            // Cast to i64 for pread's offset argument.  The VMA can't start
            // above i64::MAX (we'd have rejected the mmap), so this is safe.
            let page_index = (page_va - vma.start) / PAGE_SIZE;
            let file_off   = (*base_offset + (page_index * PAGE_SIZE) as u64) as i64;

            // Step C — kernel-internal positional read (no user-space copy).
            // SAFETY: `pa as *mut u8` points to `PAGE_SIZE` bytes of valid
            // kernel-mapped writable memory (the just-allocated page frame).
            let n = crate::fs::vfs::pread(*fd, pa as *mut u8, PAGE_SIZE, file_off);

            // Step D — classify the result.
            // IMPORTANT: check `n < 0` before casting to usize. A negative
            // isize cast to usize wraps to near usize::MAX, so a naive
            // `(n as usize) < PAGE_SIZE` check would pass for error returns,
            // silently mapping a zero page instead of delivering SIGBUS.
            //   n < 0              I/O error — free the frame, deliver SIGBUS.
            //   n >= 0             Success (full or partial):
            //     n == 0           EOF before this page: zero page is correct.
            //     0 < n < PAGE_SIZE partial page (last page of file): tail is
            //                      already zero from Step A — map as-is.
            //     n == PAGE_SIZE   full page — map as-is.
            if n < 0 {
                // Real I/O error (EBADF, EIO, …): the fd is broken.
                free_page(pa);
                send_signal_info(pid, SigInfo {
                    sig:  SIGBUS,
                    code: BUS_ADRERR,
                    addr: faulting_va,
                    ..Default::default()
                });
                return false;
            }
            // n >= 0: short reads and EOF are not errors — the zero-filled
            // suffix from Step A is the correct POSIX behaviour.
        }

        VmaKind::Fixed => {
            // MAP_FIXED over an already-unmapped region — access violation.
            free_page(pa);
            send_sigsegv(pid, faulting_va);
            return false;
        }

        VmaKind::PhysMap(phys_base) => {
            // Re-map the exact physical page — do NOT use the PMM-allocated
            // `pa`. Return `pa` to the PMM immediately; the physical page is
            // not kernel-owned and must not be freed by us.
            free_page(pa);
            let phys_pa = (*phys_base as usize) + (page_va - vma.start);
            let flags   = prot_to_flags(vma.prot);
            <Arch as Paging>::map_page(user_cr3, page_va, phys_pa, flags);
            <Arch as Paging>::flush_va(page_va);
            return true;
        }
    }

    // prot_to_flags() derives PRESENT | USER | (WRITE if PROT_WRITE) |
    // (NX if !PROT_EXEC) from the VMA's protection flags.  On RISC-V the
    // Paging impl translates these to Sv39 PTE bits; on x86_64 it writes
    // standard x86 PTE bits.  The TLB flush (INVLPG / SFENCE.VMA) is
    // issued by flush_va() so the CPU immediately sees the new PTE.
    let flags = prot_to_flags(vma.prot);
    <Arch as Paging>::map_page(user_cr3, page_va, pa, flags);
    <Arch as Paging>::flush_va(page_va);
    true
}

/// Convert POSIX `prot` bits to arch page-table flags.
///
/// Shared by `handle_demand_fault` and `sys_mprotect` (via `mmap.rs`).
/// The Paging trait's `map_page` interprets `PageFlags` per-arch:
///   - x86_64: PRESENT=bit0, WRITE=bit1, USER=bit2, NX=bit63
///   - RISC-V Sv39: VALID=bit0, READ=bit1, WRITE=bit2, EXEC=bit3, USER=bit4
#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX;    }
    f
}
