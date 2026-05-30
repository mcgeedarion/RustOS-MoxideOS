//! AArch64 HAL primitives for Armv8-A+ UEFI systems with GICv2/GICv3.

#![allow(dead_code)]

use core::arch::asm;
use core::ops::Range;

use super::mem_layout::{page, uart, va48};

pub struct ArchImpl;

#[inline]
pub fn kernel_va_range() -> Range<usize> {
    va48::KERNEL_BASE..usize::MAX
}

#[inline]
pub fn is_user_addr(addr: usize) -> bool {
    addr < va48::USER_TOP
}

#[inline]
pub fn is_valid_addr(addr: usize) -> bool {
    let sign = addr >> 48;
    sign == 0 || sign == 0xffff
}

#[inline]
pub unsafe fn tlb_flush_all() {
    asm!(
        "dsb ishst",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        options(nostack)
    );
}

#[inline]
pub unsafe fn tlb_flush_page(va: usize) {
    // TLBI operand is VA[55:12].
    let va_page = va >> page::SHIFT;
    asm!("dsb ishst", "tlbi vaae1is, {page}", "dsb ish", "isb", page = in(reg) va_page, options(nostack));
}

#[inline]
pub fn cpu_relax() {
    unsafe {
        asm!("yield", options(nostack, nomem));
    }
}

#[inline]
pub fn wait_for_interrupt() {
    unsafe {
        asm!("wfi", options(nostack, nomem));
    }
}

#[inline]
pub fn time_now_cycles() -> u64 {
    let cnt: u64;
    unsafe {
        asm!("mrs {cnt}, cntvct_el0", cnt = out(reg) cnt, options(nostack, nomem));
    }
    cnt
}

#[inline]
pub fn debug_break() {
    unsafe {
        asm!("brk #0xf000", options(nostack));
    }
}

#[inline]
pub fn cpu_id() -> usize {
    let mpidr: usize;
    unsafe {
        asm!("mrs {mpidr}, mpidr_el1", mpidr = out(reg) mpidr, options(nostack, nomem));
    }
    mpidr & 0xff_ff
}

#[inline]
pub unsafe fn interrupts_enable() {
    asm!("msr daifclr, #0b0010", options(nostack));
}

#[inline]
pub unsafe fn interrupts_disable() {
    asm!("msr daifset, #0b0010", options(nostack));
}

#[inline]
pub fn interrupts_enabled() -> bool {
    let daif: usize;
    unsafe {
        asm!("mrs {daif}, daif", daif = out(reg) daif, options(nostack, nomem));
    }
    daif & (1 << 7) == 0
}

#[inline]
pub fn current_el() -> usize {
    let el: usize;
    unsafe {
        asm!("mrs {el}, CurrentEL", el = out(reg) el, options(nostack, nomem));
    }
    (el >> 2) & 0b11
}

#[inline]
pub fn read_esr_el1() -> usize {
    let esr: usize;
    unsafe {
        asm!("mrs {esr}, esr_el1", esr = out(reg) esr, options(nostack, nomem));
    }
    esr
}

#[inline]
pub fn read_far_el1() -> usize {
    let far: usize;
    unsafe {
        asm!("mrs {far}, far_el1", far = out(reg) far, options(nostack, nomem));
    }
    far
}

#[inline]
pub fn read_elr_el1() -> usize {
    let elr: usize;
    unsafe {
        asm!("mrs {elr}, elr_el1", elr = out(reg) elr, options(nostack, nomem));
    }
    elr
}

#[inline]
pub fn init() {
    unsafe {
        interrupts_disable();
    }
    serial_init();
}

#[inline]
pub fn halt() -> ! {
    loop {
        wait_for_interrupt();
    }
}

#[inline]
pub fn disable() {
    unsafe {
        interrupts_disable();
    }
}

#[inline]
pub fn serial_init() {}

#[inline]
pub fn serial_putc(byte: u8) {
    let base = uart::PL011_BASE as *mut u8;
    unsafe {
        while ((base.add(uart::FR) as *const u32).read_volatile() & uart::FR_TXFF) != 0 {
            cpu_relax();
        }
        (base.add(uart::DR) as *mut u32).write_volatile(byte as u32);
    }
}

pub fn serial_write(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            serial_putc(b'\r');
        }
        serial_putc(b);
    }
}

#[inline]
pub fn serial_getc() -> Option<u8> {
    let base = uart::PL011_BASE as *mut u8;
    unsafe {
        if ((base.add(uart::FR) as *const u32).read_volatile() & uart::FR_RXFE) != 0 {
            None
        } else {
            Some((base.add(uart::DR) as *const u32).read_volatile() as u8)
        }
    }
}

impl ArchImpl {
    pub fn halt() -> ! {
        halt()
    }
    pub fn disable() {
        disable()
    }
    pub fn serial_putc(byte: u8) {
        serial_putc(byte)
    }
    pub fn serial_write(bytes: &[u8]) {
        serial_write(bytes)
    }
}
