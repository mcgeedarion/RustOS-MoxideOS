//! PL011 UART driver — thin wrapper over the register-level access already
//! implemented in `hal.rs`.
//!
//! `hal.rs` handles the low-level MMIO reads/writes and PL011 constants;
//! this module provides an `init()` function that programs the baud-rate
//! divisors and enables the UART, matching the approach taken by the x86_64
//! `serial.rs` module.
//!
//! ## Baud rate
//!
//! The default divisors target 115200 baud assuming a 24 MHz UART clock
//! (as configured by QEMU virt).  On real hardware the clock may differ;
//! pass `ibrd`/`fbrd` values appropriate for the platform.

#![allow(dead_code)]

use super::mem_layout::uart;
use core::ptr::{read_volatile, write_volatile};

// PL011 register offsets (u32-indexed).
const DR: usize = 0x000; // Data register
const FR: usize = 0x018; // Flag register
const IBRD: usize = 0x024; // Integer baud-rate divisor
const FBRD: usize = 0x028; // Fractional baud-rate divisor
const LCR_H: usize = 0x02C; // Line control
const CR: usize = 0x030; // Control
const IMSC: usize = 0x038; // Interrupt mask set/clear
const ICR: usize = 0x044; // Interrupt clear

const FR_TXFF: u32 = 1 << 5; // TX FIFO full
const FR_RXFE: u32 = 1 << 4; // RX FIFO empty

const LCR_FEN: u32 = 1 << 4; // FIFO enable
const LCR_8BIT: u32 = 0b11 << 5;

const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

#[inline]
fn reg(offset: usize) -> *mut u32 {
    (uart::PL011_BASE + offset) as *mut u32
}

/// Initialise the PL011 UART.
///
/// `ibrd` and `fbrd` are the integer and fractional baud-rate divisors.
/// For 115200 @ 24 MHz: ibrd = 13, fbrd = 1.
pub unsafe fn init(ibrd: u32, fbrd: u32) {
    // Disable UART.
    write_volatile(reg(CR), 0);
    // Clear all pending interrupts.
    write_volatile(reg(ICR), 0x7ff);
    // Program baud rate.
    write_volatile(reg(IBRD), ibrd);
    write_volatile(reg(FBRD), fbrd);
    // 8-bit, FIFO enabled.
    write_volatile(reg(LCR_H), LCR_8BIT | LCR_FEN);
    // Mask all interrupts (we poll).
    write_volatile(reg(IMSC), 0);
    // Re-enable: UART + TX + RX.
    write_volatile(reg(CR), CR_UARTEN | CR_TXE | CR_RXE);
}

/// Write one byte, blocking until the TX FIFO has space.
pub fn write_byte(b: u8) {
    unsafe {
        while read_volatile(reg(FR)) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        write_volatile(reg(DR), b as u32);
    }
}

/// Write a byte slice; converts bare `\n` to `\r\n`.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

/// Non-blocking read.  Returns `None` if the RX FIFO is empty.
pub fn read_byte() -> Option<u8> {
    unsafe {
        if read_volatile(reg(FR)) & FR_RXFE != 0 {
            None
        } else {
            Some(read_volatile(reg(DR)) as u8)
        }
    }
}
