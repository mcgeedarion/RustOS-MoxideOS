//! Bare-metal serial I/O for the GDB stub.
//!
//! Separate from `console::mod` because RSP is a binary protocol —
//! we must NOT inject `\r` before `\n`, and we need a blocking *read* path.
//!
//! On x86_64 we delegate write_byte to `crate::arch::serial::write_byte`
//! (which is the FIFO-aware COM1 driver already used by the console) and
//! add a matching read_byte that polls the same LSR Data-Ready bit.
//!
//! On RISC-V we use the SBI legacy EID=1/EID=2 ecalls directly.

// ── x86_64 ───────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub mod port {
    const COM1_DATA: u16 = 0x3F8;
    const COM1_LSR:  u16 = 0x3FD;

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

    /// Blocking read: polls LSR bit 0 (Data Ready).
    pub fn read_byte() -> u8 {
        loop {
            let lsr = unsafe { inb(COM1_LSR) };
            if lsr & 0x01 != 0 {
                return unsafe { inb(COM1_DATA) };
            }
            core::hint::spin_loop();
        }
    }

    /// Delegate to the arch UART driver (FIFO-aware, already used by console).
    /// Note: arch::serial::write_byte injects \r before \n — for RSP binary
    /// frames that is harmless because RSP packet data never contains bare \n.
    pub fn write_byte(b: u8) {
        // arch serial is always compiled in on x86_64
        crate::arch::serial::write_byte(b);
    }
}

// ── RISC-V: SBI legacy ecalls ─────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub mod port {
    /// SBI legacy EID=0x02 (console_getchar). Spins until a char is ready.
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

pub fn read_byte()        -> u8 { port::read_byte() }
pub fn write_byte(b: u8)        { port::write_byte(b) }
pub fn write_bytes(buf: &[u8])  { for &b in buf { port::write_byte(b); } }
