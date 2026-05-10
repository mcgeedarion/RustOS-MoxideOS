//! Bare-metal serial I/O for the GDB stub.
//!
//! Separate from `console::mod` because:
//!   - RSP is a binary protocol; we must NOT inject `\r` before `\n`.
//!   - We need a blocking *read* path, which the console write-only layer
//!     does not provide.

// ── x86_64: COM1 (0x3F8) ─────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub mod port {
    const COM1_DATA: u16 = 0x3F8;
    const COM1_LSR:  u16 = 0x3FD; // Line Status Register

    #[inline]
    pub fn read_byte() -> u8 {
        unsafe {
            loop {
                let lsr: u8;
                // Wait until bit 0 (Data Ready) is set.
                core::arch::asm!(
                    "in al, dx",
                    out("al") lsr,
                    in("dx") COM1_LSR,
                    options(nostack, nomem)
                );
                if lsr & 0x01 != 0 {
                    let b: u8;
                    core::arch::asm!(
                        "in al, dx",
                        out("al") b,
                        in("dx") COM1_DATA,
                        options(nostack, nomem)
                    );
                    return b;
                }
                core::hint::spin_loop();
            }
        }
    }

    #[inline]
    pub fn write_byte(b: u8) {
        unsafe {
            loop {
                let lsr: u8;
                core::arch::asm!(
                    "in al, dx",
                    out("al") lsr,
                    in("dx") COM1_LSR,
                    options(nostack, nomem)
                );
                if lsr & 0x20 != 0 { break; } // Transmitter Holding Register Empty
                core::hint::spin_loop();
            }
            core::arch::asm!(
                "out dx, al",
                in("dx") COM1_DATA,
                in("al") b,
                options(nostack, nomem)
            );
        }
    }
}

// ── RISC-V: SBI console_getchar / console_putchar ────────────────────────────

#[cfg(target_arch = "riscv64")]
pub mod port {
    /// SBI legacy EID=0x02 (console_getchar). Returns -1 if no char available.
    #[inline]
    pub fn read_byte() -> u8 {
        loop {
            let ret: isize;
            unsafe {
                core::arch::asm!(
                    "ecall",
                    in("a7") 2usize, // SBI_CONSOLE_GETCHAR
                    in("a6") 0usize,
                    lateout("a0") ret,
                    options(nostack)
                );
            }
            if ret >= 0 { return ret as u8; }
            core::hint::spin_loop();
        }
    }

    #[inline]
    pub fn write_byte(b: u8) {
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") 1usize, // SBI_CONSOLE_PUTCHAR
                in("a6") 0usize,
                in("a0") b as usize,
                options(nostack)
            );
        }
    }
}

// ── Arch-agnostic wrappers ────────────────────────────────────────────────────

pub fn read_byte()       -> u8  { port::read_byte() }
pub fn write_byte(b: u8)        { port::write_byte(b) }
pub fn write_bytes(buf: &[u8])  { for &b in buf { port::write_byte(b); } }
