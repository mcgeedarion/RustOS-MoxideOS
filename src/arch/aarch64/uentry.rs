//! AArch64 EL0 (user-space) entry and stack allocation.
//!
//! ## ERET register contract
//!
//!   ELR_EL1  ← user entry PC
//!   SPSR_EL1 ← 0 (EL0t, all exceptions unmasked, AArch64)
//!   SP_EL0   ← user stack pointer
//!   TTBR0_EL1← process page-table base
//!   x0-x30   ← zeroed (no kernel pointer leaks)
//!
//! ## Safety
//!
//! The caller must ensure:
//!   - `entry` is a valid mapped EL0 virtual address.
//!   - `user_sp` points to a writable mapped user stack page.
//!   - `ttbr0` is the physical address of the process L0 page table.
//!   - Interrupts are disabled on entry (they re-enable when SPSR.I = 0 is restored by eret).
//!   - This function never returns to the caller.

use crate::mm::pmm;
use core::arch::asm;

/// 16 KiB user stack (4 pages).
const USER_STACK_PAGES: usize = 4;
const PAGE: usize = 4096;

/// Allocate and map a user stack for a fresh process, return the stack top
/// (highest VA; stacks grow down).
///
/// Places the stack just below the AArch64 48-bit user ceiling
/// (0x0000_FFFF_FFFF_F000).
pub fn alloc_user_stack(ttbr0: usize) -> Option<usize> {
    use crate::arch::aarch64::paging;

    const USER_STACK_TOP: usize = 0x0000_FFFF_FFFF_F000;
    let size = USER_STACK_PAGES * PAGE;
    let base = USER_STACK_TOP - size;

    for i in 0..USER_STACK_PAGES {
        let pa = pmm::alloc_page()?;
        unsafe {
            core::ptr::write_bytes(pa as *mut u8, 0, PAGE);
        }
        let va = base + i * PAGE;
        let flags = paging::PTE_VALID
            | paging::PTE_TABLE
            | paging::PTE_USER
            | paging::PTE_AF
            | paging::PTE_SH_INNER;
        unsafe {
            paging::map_page(ttbr0, va, pa, flags);
        }
    }

    Some(USER_STACK_TOP)
}

/// Transition to EL0 via ERET.
///
/// Loads TTBR0, zeros all GPRs to prevent kernel-pointer leaks, then erets
/// to `entry` with `user_sp` as SP_EL0.  Never returns.
///
/// # Safety
/// All preconditions in the module doc must hold.
#[inline(never)]
pub unsafe fn eret_to_user(ttbr0: usize, entry: usize, user_sp: usize) -> ! {
    asm!(
        // Switch to the process address space.
        "msr ttbr0_el1, {ttbr0}",
        "isb",

        "msr elr_el1,  {entry}",
        "msr spsr_el1, xzr",

        "msr sp_el0,   {sp}",

        // Zero all GPRs that musl/libc inspects on startup.
        "mov x0,  xzr",
        "mov x1,  xzr",
        "mov x2,  xzr",
        "mov x3,  xzr",
        "mov x4,  xzr",
        "mov x5,  xzr",
        "mov x6,  xzr",
        "mov x7,  xzr",
        "mov x8,  xzr",
        "mov x9,  xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",

        "eret",

        ttbr0 = in(reg) ttbr0,
        entry = in(reg) entry,
        sp    = in(reg) user_sp,
        options(noreturn),
    );
}
