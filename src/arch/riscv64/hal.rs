//! RISC-V 64 HAL implementation — `arch::api` trait impls.

use crate::arch::api::{
    ArchInit, Interrupts, Cpu, Timer, Paging, PageFlags,
    ContextSwitch, TrapFrame, Syscall, Serial, FpState, Tlb,
};
use crate::arch::riscv64::{
    paging as rv_paging,
    csr,
};

pub struct ArchImpl;

// ─── ArchInit ────────────────────────────────────────────────────────────────────────

impl ArchInit for ArchImpl {
    fn early_init() {
        unsafe {
            extern "C" { fn riscv_trap_entry(); }
            csr::write_stvec(riscv_trap_entry as usize);
        }
    }

    fn late_init() {
        unsafe {
            // Enable SSIE (software, bit 1), STIE (timer, bit 5),
            // and SEIE (external/PLIC, bit 9).
            let sie = csr::read_sie();
            csr::write_sie(sie | (1 << 1) | (1 << 5) | (1 << 9));
            // Enable global supervisor interrupt enable (sstatus.SIE, bit 1).
            let ss = csr::read_sstatus();
            csr::write_sstatus(ss | (1 << 1));
        }
    }
}

// ─── Interrupts ────────────────────────────────────────────────────────────────────

impl Interrupts for ArchImpl {
    #[inline]
    fn enable() {
        unsafe {
            let ss = csr::read_sstatus();
            csr::write_sstatus(ss | (1 << 1));
        }
    }
    #[inline]
    fn disable() {
        unsafe {
            let ss = crate::arch::riscv64::csr::read_sstatus();
            crate::arch::riscv64::csr::write_sstatus(ss & !(1 << 1));
        }
    }
    #[inline]
    fn are_enabled() -> bool {
        unsafe { csr::read_sstatus() & (1 << 1) != 0 }
    }
}

// ─── Cpu ────────────────────────────────────────────────────────────────────────────

impl Cpu for ArchImpl {
    #[inline]
    fn halt() {
        unsafe { core::arch::asm!("wfi", options(nostack, nomem)); }
    }
    #[inline]
    fn spin_hint() {
        unsafe { core::arch::asm!("nop", options(nostack, nomem)); }
    }
    fn id() -> u32 {
        let id: u64;
        unsafe {
            core::arch::asm!(
                "li a7, 0x4",
                "li a6, 0",
                "li a0, 0",
                "ecall",
                out("a0") id,
                options(nostack)
            );
        }
        id as u32
    }
    fn flags() -> usize {
        unsafe { csr::read_sstatus() }
    }
}

// ─── Timer ─────────────────────────────────────────────────────────────────────────

impl Timer for ArchImpl {
    fn init_timer() {
        let now  = Self::read_ticks();
        let next = now + 10_000_000;
        unsafe {
            core::arch::asm!(
                "li a7, 0x54494D45",
                "li a6, 0",
                "mv a0, {t}",
                "ecall",
                t = in(reg) next,
                options(nostack)
            );
        }
    }
    fn ticks_per_sec() -> u64 { 100 }
    fn read_ticks() -> u64 {
        let v: u64;
        unsafe { core::arch::asm!("rdtime {}", out(reg) v, options(nostack, nomem)); }
        v
    }
}

// ─── Paging ───────────────────────────────────────────────────────────────────────

impl Paging for ArchImpl {
    fn map_page(cr3: usize, va: usize, pa: usize, flags: PageFlags) -> bool {
        let mut pte: u64 = 1;
        if flags.contains(PageFlags::WRITE)   { pte |= 1 << 2; }
        if flags.contains(PageFlags::EXEC)    { pte |= 1 << 3; }
        if flags.contains(PageFlags::USER)    { pte |= 1 << 4; }
        if flags.contains(PageFlags::PRESENT) { pte |= 1 << 1; }
        rv_paging::map_page(cr3, va, pa, pte);
        true
    }
    fn unmap_page(cr3: usize, va: us