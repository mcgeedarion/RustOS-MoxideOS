//! Bare-metal serial I/O for the GDB stub.
//!
//! Separate from `console::mod` because RSP is a binary framing protocol —
//! we must NOT inject `\r` before `\n`, and we need a blocking *read* path.
//!
//! ## x86_64
//!
//! Both `read_byte` and `write_byte` talk directly to COM1 (I/O ports
//! 0x3F8..0x3FD) without going through the console driver.
//!
//! The console driver's `write_byte` inserts `0x0D` (CR) before every `0x0A`
//! (LF) for human-readable output.  In RSP, packet data is binary and the
//! checksum is computed over the raw bytes.  A stray `0x0D` injected into a
//! packet body changes the checksum and causes GDB to NAK the entire packet.
//! We avoid this by inlining the FIFO-polling write directly.
//!
//! ## RISC-V
//!
//! Uses SBI legacy ecalls (EID=1 write, EID=2 read).  SBI does not inject CR,
//! so no special handling is needed.

// ── x86_64 ───────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub mod port {
    const COM1_DATA: u16 = 0x3F8;
    const COM1_LSR:  u16 = 0x3FD;
    /// LSR bit 0: Data Ready (receiver has a byte).
    const LSR_DR:    u8  = 0x01;
    /// LSR bit 5: Transmitter Holding Register Empty (safe to write).
    const LSR_THRE:  u8  = 0x20;

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

    #[inline]
    unsafe fn outb(port: u16, val: u8) {
        core::arch::asm!(
            "outb %al, %dx",
            in("al") val,
            in("dx") port,
            options(att_syntax, nostack)
        );
    }

    /// Blocking read: polls LSR Data-Ready bit.
    pub fn read_byte() -> u8 {
        loop {
            let lsr = unsafe { inb(COM1_LSR) };
            if lsr & LSR_DR != 0 {
                return unsafe { inb(COM1_DATA) };
            }
            core::hint::spin_loop();
        }
    }

    /// Blocking write: polls LSR THRE bit, then writes one byte.
    ///
    /// Intentionally does NOT delegate to `arch::serial::write_byte`:
    /// that function injects CR before LF which corrupts RSP checksums.
    pub fn write_byte(b: u8) {
        loop {
            let lsr = unsafe { inb(COM1_LSR) };
            if lsr & LSR_THRE != 0 {
                unsafe { outb(COM1_DATA, b) };
                return;
            }
            core::hint::spin_loop();
        }
    }
}

// ── RISC-V: SBI legacy ecalls ──────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub mod port {
    /// SBI legacy EID=0x02 (console_getchar).  Spins until a char is ready.
    pub fn read_byte() -> u8 {
        loop {
            let ret: isize;
            unsafe {
                core::arch::asm!(
                    "ecall",
                    in("a7") 2usize,
                    in("a6") 0usize,
                    lateout("a0") ret,
                    options(nostack)
                );
            }
            if ret >= 0 { return ret as u8; }
            core::hint::spin_loop();
        }
    }

    /// SBI legacy EID=0x01 (console_putchar).
    pub fn write_byte(b: u8) {
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") 1usize,
                in("a6") 0usize,
                in("a0") b as usize,
                options(nostack)
            );
        }
    }
}

// ── Arch-agnostic wrappers ────────────────────────────────────────────────────

pub fn read_byte()       -> u8 { port::read_byte() }
pub fn write_byte(b: u8)       { port::write_byte(b) }
pub fn write_bytes(buf: &[u8]) { for &b in buf { port::write_byte(b); } }
