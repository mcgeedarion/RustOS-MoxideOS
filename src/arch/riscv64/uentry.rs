//! RISC-V userspace entry via SRET.
//!
//! `sret_to_user()` performs the S-mode → U-mode transition after
//! elf64::load() and write_initial_stack() have set up the process.
//!
//! ## CSR setup before SRET
//!   sstatus.SPP  = 0   → return to U-mode (not S-mode)
//!   sstatus.SPIE = 1   → enable interrupts in U-mode after sret
//!   sepc         = entry  → PC on return
//!   satp         = (8 << 60) | (satp_ppn)  → Sv39 page table
//!
//! ## Register contract
//!   sp (x2) ← user_rsp  (initial stack pointer, argc slot)
//!   All other registers zeroed.
//!
//! ## Safety
//! Caller must ensure the page table is loaded into satp and that
//! `entry` and `user_rsp` are valid mapped user virtual addresses.

use core::arch::asm;
use crate::mm::pmm;

const USER_STACK_PAGES: usize = 4;
const PAGE: usize = 4096;

/// Allocate user stack pages, map them into `satp_ppn` address space,
/// and return the user virtual address of the stack top.
pub fn alloc_user_stack(satp_ppn: usize) -> Option<usize> {
    use crate::arch::riscv64::paging;

    // Mirror the x86_64 layout: stack just below 256 GiB (Sv39 user ceiling).
    const USER_STACK_TOP: usize = 0x0000_003F_FFFF_F000;
    let size = USER_STACK_PAGES * PAGE;
    let stack_virt_base = USER_STACK_TOP - size;

    for i in 0..USER_STACK_PAGES {
        let pa = pmm::alloc_page()?;
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
        let va = stack_virt_base + i * PAGE;
        // PTE flags: V | R | W | U  (no exec on stack)
        let flags = paging::PTE_V | paging::PTE_R | paging::PTE_W | paging::PTE_U;
        unsafe { paging::map_page(satp_ppn, va, pa, flags); }
    }

    Some(USER_STACK_TOP)
}

/// Switch to user mode via SRET.
///
/// Sets up sstatus, sepc, satp and zeroes all GPRs before executing sret.
/// Never returns.
///
/// # Safety
/// All preconditions in module doc must hold.
#[inline(never)]
pub unsafe fn sret_to_user(satp_ppn: usize, entry: usize, user_rsp: usize) -> ! {
    // Build satp value: MODE=8 (Sv39), ASID=0, PPN=satp_ppn.
    let satp: usize = (8 << 60) | (satp_ppn & 0x0FFF_FFFF_FFFF);

    asm!(
        // sepc ← entry point
        "csrw sepc, {entry}",

        // sstatus: SPP=0 (U-mode), SPIE=1 (enable U-mode interrupts after sret)
        // Read-modify-write: clear SPP (bit 8), set SPIE (bit 5).
        "csrci sstatus, 0x100",   // clear SPP
        "csrsi sstatus, 0x020",   // set  SPIE

        // Load process page table.
        "csrw satp, {satp}",
        // sfence.vma to flush TLB after satp switch.
        "sfence.vma zero, zero",

        // Zero all caller-saved + callee-saved GPRs to avoid kernel leaks.
        "mv ra, zero",
        "mv gp, zero",
        "mv tp, zero",
        "mv t0, zero",
        "mv t1, zero",
        "mv t2, zero",
        "mv s0, zero",
        "mv s1, zero",
        "mv a0, zero",
        "mv a1, zero",
        "mv a2, zero",
        "mv a3, zero",
        "mv a4, zero",
        "mv a5, zero",
        "mv a6, zero",
        "mv a7, zero",
        "mv s2, zero",
        "mv s3, zero",
        "mv s4, zero",
        "mv s5, zero",
        "mv s6, zero",
        "mv s7, zero",
        "mv s8, zero",
        "mv s9, zero",
        "mv s10, zero",
        "mv s11, zero",
        "mv t3, zero",
        "mv t4, zero",
        "mv t5, zero",
        "mv t6, zero",

        // sp ← user stack pointer.
        "mv sp, {rsp}",

        // Return to U-mode.
        "sret",

        entry = in(reg) entry,
        satp  = in(reg) satp,
        rsp   = in(reg) user_rsp,
        options(noreturn),
    );
}
