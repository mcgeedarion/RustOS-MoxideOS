//! RISC-V userspace entry via SRET through the trampoline page.
//!
//! `jump_to_user()` transitions S-mode → U-mode after `elf64::load()` and
//! `auxv::build_stack()` have prepared the process image.
//!
//! ## Flow
//!   1. Allocate and map the per-process trapframe page + trampoline page.
//!   2. Prime the trapframe's save area with kernel bootstrap values.
//!   3. Set `stvec = uservec` (trampoline entry), `sscratch = TRAPFRAME_VADDR`.
//!   4. Load sepc / sstatus and jump to `userret` in the trampoline.
//!      `userret` switches `satp`, restores GPRs, and executes `sret`.

use crate::mm::pmm;
use crate::arch::riscv64::paging::{self, PTE_R, PTE_W, PTE_U};
use crate::arch::riscv64::trampoline::{
    TRAPFRAME_VADDR, fill_save_area, map_trampoline_for_process,
};
use crate::arch::riscv64::mem_layout::{page, sv39 as SV, satp as SATP_MODE};
use crate::smp::percpu;

const USER_STACK_PAGES: usize = 4;

/// Allocate user stack pages, map them into the address space whose Sv39
/// root page table has physical address `root_ppn << 12`, and return the
/// user virtual address of the stack top.
pub fn alloc_user_stack(root_ppn: usize) -> Option<usize> {
    const USER_STACK_TOP: usize = 0x0000_003F_FFFF_F000;
    let size            = USER_STACK_PAGES * page::SIZE;
    let stack_virt_base = USER_STACK_TOP - size;
    let root_pa         = root_ppn << page::SHIFT;

    for i in 0..USER_STACK_PAGES {
        let pa = pmm::alloc_page()?;
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, page::SIZE); }
        let va = stack_virt_base + i * page::SIZE;
        paging::map_page_into(root_pa, va, pa, PTE_R | PTE_W | PTE_U);
    }

    Some(USER_STACK_TOP)
}

/// Switch to U-mode via the trampoline's `userret` stub.  Never returns.
///
/// `entry`    — ELF entry virtual address.
/// `user_sp`  — initial stack pointer (from `auxv::build_stack`).
/// `root_ppn` — physical page number of the Sv39 root page table.
/// `kstack_top` — top of this process's kernel stack (for `uservec` bootstrap).
#[inline(never)]
pub unsafe fn jump_to_user(
    entry:      usize,
    user_sp:    usize,
    root_ppn:   usize,
    kstack_top: usize,
) -> ! {
    use core::arch::asm;

    let user_satp   = SATP_MODE::MODE_SV39 | (root_ppn & SV::SATP_PPN_MASK);
    let root_pa     = root_ppn << page::SHIFT;
    let kernel_satp = {
        use crate::arch::riscv64::csr::get_satp;
        get_satp()
    };
    let hartid = percpu::current_cpu_id();

    // Map trampoline + trapframe pages into the user page table.
    let tf_pa  = map_trampoline_for_process(root_pa);
    // Kernel VA of the trapframe page (identity-mapped in the kernel PT).
    let tf_kva = tf_pa; // kernel uses identity map over physical RAM

    // Populate the TrapFrame fields the trampoline will restore on sret.
    // sepc = entry, sstatus: SPP=0 (U-mode), SPIE=1 (interrupts on after sret).
    let sstatus_user: usize = 0x20; // SPIE bit 5
    unsafe {
        // sepc slot (offset 248 = 31*8)
        core::ptr::write_volatile((tf_kva + 31 * 8) as *mut usize, entry);
        // sstatus slot (offset 256 = 32*8)
        core::ptr::write_volatile((tf_kva + 32 * 8) as *mut usize, sstatus_user);
        // sp slot (offset 8 = 1*8)
        core::ptr::write_volatile((tf_kva + 1 * 8) as *mut usize, user_sp);
    }

    // Prime save area so first trap back into kernel works.
    fill_save_area(tf_kva, kernel_satp, kstack_top, user_satp, hartid);

    // Resolve userret VA in the kernel mapping (same PA, trampoline code).
    // userret is at the label inside the trampoline page.  We compute its
    // offset from _trampoline_start and add it to the kernel VA of the page.
    extern "C" {
        static _trampoline_start: u8;
        fn userret();
    }
    let tramp_start_kva = unsafe { &_trampoline_start as *const u8 as usize };
    let userret_kva     = userret as usize;
    // offset of userret within the trampoline section
    let userret_off     = userret_kva - tramp_start_kva;
    let tramp_pa        = crate::arch::riscv64::trampoline::trampoline_pa();
    let userret_exec_va = tramp_pa + userret_off; // kernel identity-mapped VA

    // Point stvec at uservec (trampoline entry) so future U-mode traps land there.
    extern "C" { fn uservec(); }
    use crate::arch::riscv64::csr::set_stvec;
    set_stvec(uservec as usize);

    // Jump into userret: a0 = TRAPFRAME_VADDR (user VA), a1 = user_satp.
    asm!(
        "mv  a0, {tf_va}",
        "mv  a1, {satp}",
        // sscratch = TRAPFRAME_VADDR so uservec can find the trapframe.
        "csrw sscratch, {tf_va}",
        "jr  {userret}",
        tf_va  = in(reg) TRAPFRAME_VADDR,
        satp   = in(reg) user_satp,
        userret = in(reg) userret_exec_va,
        options(noreturn),
    );
}
