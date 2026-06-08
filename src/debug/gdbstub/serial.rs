// src/debug/gdbstub/serial.rs

use core::fmt;

const COM1_BASE: u16 = 0x3F8;

const REG_DATA: u16 = COM1_BASE;
const REG_IER: u16 = COM1_BASE + 1;
const REG_FCR: u16 = COM1_BASE + 2;
const REG_LCR: u16 = COM1_BASE + 3;
const REG_MCR: u16 = COM1_BASE + 4;
const REG_LSR: u16 = COM1_BASE + 5;
const REG_DLL: u16 = COM1_BASE;
const REG_DLH: u16 = COM1_BASE + 1;

const LSR_DATA_READY: u8 = 1 << 0;
const LSR_THRE: u8 = 1 << 5;
const BAUD_115200: u16 = 1;

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "outb %al, %dx",
        in("dx") port,
        in("al") val,
        options(att_syntax, nostack, preserves_flags)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!(
        "inb %dx, %al",
        in("dx") port,
        out("al") val,
        options(att_syntax, nostack, preserves_flags)
    );
    val
}

/// A thin wrapper around COM1 configured for GDB RSP communication.
pub struct SerialPort;

impl SerialPort {
    /// Construct without touching hardware. Call [`init`] before use.
    ///
    /// # Safety
    /// Caller must ensure no other code is concurrently driving COM1.
    pub const unsafe fn new() -> Self {
        Self
    }

    /// Program COM1 to 115200-8N1, FIFO enabled, no interrupts.
    ///
    /// # Safety
    /// Raw I/O port access; must not race with other users of COM1.
    pub unsafe fn init(&mut self) {
        outb(REG_IER, 0x00);
        outb(REG_LCR, 0x80);
        outb(REG_DLL, (BAUD_115200 & 0xFF) as u8);
        outb(REG_DLH, (BAUD_115200 >> 8) as u8);
        outb(REG_LCR, 0x03);
        outb(REG_FCR, 0xC7);
        outb(REG_MCR, 0x0B);
    }

    #[inline]
    unsafe fn wait_rx(&mut self) {
        while inb(REG_LSR) & LSR_DATA_READY == 0 {
            core::hint::spin_loop();
        }
    }

    #[inline]
    unsafe fn wait_tx(&mut self) {
        while inb(REG_LSR) & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
    }

    #[inline]
    unsafe fn try_read(&mut self) -> Option<u8> {
        if inb(REG_LSR) & LSR_DATA_READY != 0 {
            Some(inb(REG_DATA))
        } else {
            None
        }
    }

    #[inline]
    pub unsafe fn read_byte(&mut self) -> u8 {
        self.wait_rx();
        inb(REG_DATA)
    }

    #[inline]
    pub unsafe fn write_byte(&mut self, byte: u8) {
        self.wait_tx();
        outb(REG_DATA, byte);
    }

    pub fn write(&mut self, byte: u8) -> Result<(), SerialError> {
        unsafe { self.write_byte(byte) };
        Ok(())
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), SerialError> {
        for &b in buf {
            self.write(b)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), SerialError> {
        unsafe { self.wait_tx() };
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8, SerialError> {
        Ok(unsafe { self.read_byte() })
    }

    pub fn peek(&mut self) -> Result<Option<u8>, SerialError> {
        Ok(unsafe { self.try_read() })
    }
}

#[derive(Debug)]
pub enum SerialError {}

impl fmt::Display for SerialError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}
