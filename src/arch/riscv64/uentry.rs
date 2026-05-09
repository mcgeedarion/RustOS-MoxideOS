//! RISC-V userspace entry via SRET.
//!
//! `jump_to_user()` transitions S-mode → U-mode after elf64::load() and
//! auxv::build_stack() have prepared the process image.
//!
//! ## CSR setup
//!   sstatus.SPP  = 0   → U-mode on sret
//!   sstatus.SPIE = 1   → enable U-mode interrupts after sret
//!   sepc         = entry virtual address
//!   satp         = (8 << 60) | root_ppn  (Sv39)

use core::arch::asm;
use crate::mm::pmm;
use crate::arch::riscv64::paging::{self, PTE_R, PTE_W, PTE_U};

const USER_STACK_PAGES: usize = 4;
const PAGE: usize = 4096;

/// Allocate user stack pages, map them into the address space whose Sv39
/// root page table has physical address `root_ppn << 12`, and return the
/// user virtual address of the stack top.
pub fn alloc_user_stack(root_ppn: usize) -> Option<usize> {
    const USER_STACK_TOP: usize = 0x0000_003F_FFFF_F000;
    let size            = USER_STACK_PAGES * PAGE;
    let stack_virt_base = USER_STACK_TOP - size;
    let root_pa         = root_ppn << 12;

    for i in 0..USER_STACK_PAGES {
        let pa    = pmm::alloc_page()?;
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
        let va    = stack_virt_base + i * PAGE;
        // Use map_page_into so we target the new process's table, not current SATP.
        paging::map_page_into(root_pa, va, pa, PTE_R | PTE_W | PTE_U);
    }

    Some(USER_STACK_TOP)
}

/// Switch to U-mode via SRET.  Never returns.
///
/// `entry`    — ELF entry virtual address.
/// `user_sp`  — initial stack pointer (from auxv::build_stack).
/// `root_ppn` — physical page number of the Sv39 root page table.
#[inline(never)]
pub unsafe fn jump_to_user(entry: usize, user_sp: usize, root_ppn: usize) -> ! {
    let satp: usize = (8usize << 60) | (root_ppn & 0x0FFF_FFFF_FFFF);
    asm!(
        "csrw sepc, {entry}",
        "csrci sstatus, 0x100",   // clear SPP (bit 8) → U-mode
        "csrsi sstatus, 0x020",   // set SPIE (bit 5) → enable U-mode interrupts
        "csrw satp, {satp}",
        "sfence.vma zero, zero",
        // Zero all GPRs to avoid kernel data leaks.
        "mv  ra,  zero", "mv  gp,  zero", "mv  tp,  zero",
        "mv  t0,  zero", "mv  t1,  zero", "mv  t2,  zero",
        "mv  s0,  zero", "mv  s1,  zero",
        "mv  a0,  zero", "mv  a1,  zero", "mv  a2,  zero", "mv  a3,  zero",
        "mv  a4,  zero", "mv  a5,  zero", "mv  a6,  zero", "mv  a7,  zero",
        "mv  s2,  zero", "mv  s3,  zero", "mv  s4,  zero", "mv  s5,  zero",
        "mv  s6,  zero", "mv  s7,  zero", "mv  s8,  zero", "mv  s9,  zero",
        "mv  s10, zero", "mv  s11, zero",
        "mv  t3,  zero", "mv  t4,  zero", "mv  t5,  zero", "mv  t6,  zero",
        "mv  sp,  {sp}",
        "sret",
        entry = in(reg) entry,
        satp  = in(reg) satp,
        sp    = in(reg) user_sp,
        options(noreturn),
    );
}
