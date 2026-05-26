//! User-mode trampoline page for RISC-V.
//!
//! ## Design
//! A single physical page holds `uservec` and `userret` (assembled from
//! `trampoline.S`).  It is mapped at `TRAMPOLINE_VADDR` in **both** the
//! kernel page table and every user page table, so it remains reachable
//! across `satp` switches.
//!
//! Each process also has a private trapframe page mapped at `TRAPFRAME_VADDR`
//! (one page below the trampoline).  The save area at the end of that page
//! carries the per-hart kernel bootstrap values that `uservec` needs before
//! any kernel mapping is accessible.
//!
//! ## Save-area layout (byte offsets from trapframe page start)
//! ```text
//!  272  kernel_satp   — kernel Sv39 SATP value
//!  280  kernel_sp     — top of this process's kernel stack
//!  288  kernel_trap   — kernel VA of riscv_trap_entry
//!  296  user_satp     — user Sv39 SATP value (for reference / debug)
//!  304  hartid        — hart ID restored into tp by uservec
//! ```

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch::riscv64::mem_layout::page;
use crate::arch::riscv64::paging::{map_page_into, PTE_R, PTE_W, PTE_X};
use crate::mm::pmm;

/// VA of the shared trampoline code page in every address space.
pub const TRAMPOLINE_VADDR: usize = 0xFFFF_FFFF_FFFF_F000;

/// VA of the per-process trapframe page (one page below the trampoline).
pub const TRAPFRAME_VADDR: usize = TRAMPOLINE_VADDR - page::SIZE;

// ── Linker symbols ───────────────────────────────────────────────────────────
extern "C" {
    static _trampoline_start: u8;
    static _trampoline_end:   u8;
}

/// Physical address of the single shared trampoline code page.
static TRAMPOLINE_PA: AtomicUsize = AtomicUsize::new(0);

/// Called once at boot.  Copies the trampoline code into a dedicated
/// physical page and maps it RX into the kernel page table.
pub fn trampoline_init() {
    let src = unsafe { &_trampoline_start as *const u8 as usize };
    let end = unsafe { &_trampoline_end   as *const u8 as usize };
    let len = end - src;
    assert!(len <= page::SIZE, "trampoline code exceeds one page");

    let pa = pmm::alloc_page().expect("trampoline_init: OOM");
    unsafe {
        core::ptr::write_bytes(pa as *mut u8, 0, page::SIZE);
        core::ptr::copy_nonoverlapping(src as *const u8, pa as *mut u8, len);
    }

    TRAMPOLINE_PA.store(pa, Ordering::Release);

    // Map into kernel page table — supervisor-only (no PTE_U), read+execute.
    let kroot = kernel_satp_root();
    map_page_into(kroot, TRAMPOLINE_VADDR, pa, PTE_R | PTE_X);
}

/// Physical address of the trampoline code page (valid after `trampoline_init`).
#[inline]
pub fn trampoline_pa() -> usize {
    TRAMPOLINE_PA.load(Ordering::Acquire)
}

/// Map the trampoline and a fresh trapframe page into a user page table.
///
/// Returns the physical address of the newly allocated trapframe page.
/// The caller should store this in `Pcb::trapframe_pa` and derive the
/// kernel VA via `phys_to_virt`.
pub fn map_trampoline_for_process(user_root_pa: usize) -> usize {
    // Shared trampoline code — RX, no PTE_U (supervisor only).
    map_page_into(user_root_pa, TRAMPOLINE_VADDR, trampoline_pa(), PTE_R | PTE_X);

    // Per-process trapframe — RW, no PTE_U (supervisor only).
    let tf_pa = pmm::alloc_page().expect("map_trampoline_for_process: OOM");
    unsafe { core::ptr::write_bytes(tf_pa as *mut u8, 0, page::SIZE); }
    map_page_into(user_root_pa, TRAPFRAME_VADDR, tf_pa, PTE_R | PTE_W);

    tf_pa
}

// ── Save-area helpers ────────────────────────────────────────────────────────

/// Byte offset of the save area within the trapframe page.
pub const SAVE_AREA_OFF: usize = 272; // = 34 * 8  (after 34-slot TrapFrame)

pub mod save {
    use super::SAVE_AREA_OFF;
    pub const KERNEL_SATP: usize = SAVE_AREA_OFF;       // slot 34
    pub const KERNEL_SP:   usize = SAVE_AREA_OFF + 8;   // slot 35
    pub const KERNEL_TRAP: usize = SAVE_AREA_OFF + 16;  // slot 36
    pub const USER_SATP:   usize = SAVE_AREA_OFF + 24;  // slot 37
    pub const HARTID:      usize = SAVE_AREA_OFF + 32;  // slot 38
}

/// Write kernel bootstrap values into the per-process save area so that
/// `uservec` can switch into the kernel without any kernel mappings.
///
/// Call this before every `userret` (and when first setting up a process).
///
/// # Safety
/// `tf_kva` must be the kernel virtual address of the process's trapframe page.
pub unsafe fn fill_save_area(
    tf_kva:      usize,
    kernel_satp: usize,
    kernel_sp:   usize,
    user_satp:   usize,
    hartid:      usize,
) {
    use crate::arch::riscv64::trap::riscv_trap_entry;
    w(tf_kva + save::KERNEL_SATP, kernel_satp);
    w(tf_kva + save::KERNEL_SP,   kernel_sp);
    w(tf_kva + save::KERNEL_TRAP, riscv_trap_entry as usize);
    w(tf_kva + save::USER_SATP,   user_satp);
    w(tf_kva + save::HARTID,      hartid);
}

#[inline]
unsafe fn w(addr: usize, val: usize) {
    core::ptr::write_volatile(addr as *mut usize, val);
}

// ── Internal helper ──────────────────────────────────────────────────────────

/// Return the physical root PA of the current kernel page table.
fn kernel_satp_root() -> usize {
    use crate::arch::riscv64::csr::get_satp;
    use crate::arch::riscv64::mem_layout::{page as P, sv39 as SV};
    let satp = get_satp();
    (satp & SV::SATP_PPN_MASK) << P::SHIFT
}
