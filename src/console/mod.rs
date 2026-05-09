//! Kernel console — serial-backed print macros.
//!
//! On x86_64 we write directly to COM1 (I/O port 0x3F8).
//! On RISC-V we use the SBI console_putchar (EID=0x01) ecall,
//! which OpenSBI handles before we have any UART driver of our own.

// ── x86_64: I/O-port UART ────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod inner {
    const COM1: u16 = 0x3F8;

    #[inline]
    fn write_byte(b: u8) {
        unsafe {
            loop {
                let lsr: u8;
                core::arch::asm!("in al, dx", out("al") lsr, in("dx") COM1 + 5, options(nostack));
                if lsr & 0x20 != 0 { break; }
            }
            core::arch::asm!("out dx, al", in("dx") COM1, in("al") b, options(nostack));
        }
    }

    pub fn write_bytes(buf: &[u8]) {
        for &b in buf {
            if b == b'\n' { write_byte(b'\r'); }
            write_byte(b);
        }
    }
}

// ── RISC-V: SBI legacy console_putchar ecall ─────────────────────────────────
//
// Legacy SBI extension EID=1.  Supported by OpenSBI on QEMU virt.
// No UART driver required for early boot output.

#[cfg(target_arch = "riscv64")]
mod inner {
    #[inline]
    fn sbi_putchar(c: u8) {
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") 1usize,
                in("a6") 0usize,
                in("a0") c as usize,
                options(nostack)
            );
        }
    }

    pub fn write_bytes(buf: &[u8]) {
        for &b in buf {
            if b == b'\n' { sbi_putchar(b'\r'); }
            sbi_putchar(b);
        }
    }
}

// ── Architecture-agnostic surface ────────────────────────────────────────────

pub fn write_bytes(buf: &[u8]) { inner::write_bytes(buf); }

pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!(crate::console::SerialWriter, $($arg)*);
    }};
}

#[macro_export]
macro_rules! serial_println {
    ()            => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => {
        $crate::serial_print!("{}", format_args!($($arg)*));
        $crate::serial_print!("\n");
    };
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => { $crate::serial_println!($($arg)*) };
}
