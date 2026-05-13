//! 16550 UART serial driver.
//!
//! All port addresses and register constants are imported from
//! [`crate::arch::x86_64::mem_layout::serial`] — no magic numbers here.

use super::mem_layout::serial as S;

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "outb %al, %dx",
        in("dx") port,
        in("al") val,
        options(att_syntax)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!(
        "inb %dx, %al",
        out("al") v,
        in("dx") port,
        options(att_syntax, nostack)
    );
    v
}

/// Initialise COM1 at 38400 baud, 8N1, FIFO enabled.
pub fn init() {
    unsafe {
        outb(S::COM1_BASE + S::OFF_IER, 0x00);       // disable interrupts
        outb(S::COM1_BASE + S::OFF_LCR, S::LCR_DLAB);// enable DLAB
        outb(S::COM1_BASE + S::OFF_DLL, (S::BAUD_38400 & 0xFF) as u8); // baud lo
        outb(S::COM1_BASE + S::OFF_DLH, (S::BAUD_38400 >> 8) as u8);   // baud hi
        outb(S::COM1_BASE + S::OFF_LCR, S::LCR_8N1); // 8N1, DLAB off
        outb(S::COM1_BASE + S::OFF_FCR, S::FCR_ENABLE_CLEAR_14);
        outb(S::COM1_BASE + S::OFF_MCR, S::MCR_RTS_DTR);
    }
}

/// Write one byte, blocking until the UART transmit register is empty.
/// Appends CR after LF to keep terminal output correctly formatted.
pub fn write_byte(b: u8) {
    unsafe {
        while inb(S::COM1_BASE + S::OFF_LSR) & S::LSR_THRE == 0 {}
        outb(S::COM1_BASE, b);
        if b == b'\n' { write_byte(b'\r'); }
    }
}

pub fn write_str(s: &str) {
    for b in s.bytes() { write_byte(b); }
}
