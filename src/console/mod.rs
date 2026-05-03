//! Kernel console — serial-backed print macros.
//!
//! Provides `serial_println!` and `serial_print!` for use throughout the kernel.
//! These write directly to COM1 (0x3F8) without locking, which is safe for
//! single-CPU early boot output and low-frequency diagnostic prints.
//!
//! For user-facing TTY I/O see shell::tty.

const COM1: u16 = 0x3F8;

#[inline]
fn write_byte(b: u8) {
    unsafe {
        // Wait until the Transmit Holding Register is empty (LSR bit 5).
        loop {
            let lsr: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") lsr,
                in("dx") COM1 + 5,
                options(nostack)
            );
            if lsr & 0x20 != 0 { break; }
        }
        core::arch::asm!(
            "out dx, al",
            in("dx") COM1,
            in("al") b,
            options(nostack)
        );
    }
}

/// Write a raw byte slice to the serial console.
pub fn write_bytes(buf: &[u8]) {
    for &b in buf {
        if b == b'\n' { write_byte(b'\r'); } // CRNL for terminals
        write_byte(b);
    }
}

/// Serial console writer that implements core::fmt::Write.
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }
}

/// Print to the serial console without a trailing newline.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!(crate::console::SerialWriter, $($arg)*);
    }};
}

/// Print to the serial console with a trailing newline.
#[macro_export]
macro_rules! serial_println {
    ()              => { $crate::serial_print!("\n") };
    ($($arg:tt)*)   => { $crate::serial_print!("{}", format_args!($($arg)*)); $crate::serial_print!("\n"); };
}

/// `println!` alias — used throughout the kernel wherever console output is needed.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => { $crate::serial_println!($($arg)*) };
}
