// src/debug/gdbstub/serial.rs

//! Bare-metal serial I/O for the GDB stub.
//!
//! Separate from `console::mod` because RSP is a bidirectional protocol —
//! GDB needs both reliable reads and writes over the same UART port.
//! The console module is write-only; this one wraps COM1 with blocking
//! read/write and implements the `gdbstub::conn::Connection` trait.

use core::fmt;
use gdbstub::conn::Connection;
use x86_64::instructions::port::Port;

const COM1_BASE: u16 = 0x3F8;

const REG_DATA: u16 = COM1_BASE; // RBR (r) / THR (w)
const REG_IER: u16 = COM1_BASE + 1; // Interrupt Enable
const REG_FCR: u16 = COM1_BASE + 2; // FIFO Control (write)
const REG_LCR: u16 = COM1_BASE + 3; // Line Control
const REG_MCR: u16 = COM1_BASE + 4; // Modem Control
const REG_LSR: u16 = COM1_BASE + 5; // Line Status
const REG_DLL: u16 = COM1_BASE; // Divisor Latch Low  (DLAB=1)
const REG_DLH: u16 = COM1_BASE + 1; // Divisor Latch High (DLAB=1)

// LSR bit flags
const LSR_DATA_READY: u8 = 1 << 0; // Received byte waiting in RBR
const LSR_THRE: u8 = 1 << 5; // Transmitter Holding Register Empty

// Baud divisor for 115200 baud (base clock = 1.8432 MHz)
const BAUD_115200: u16 = 1;

/// A thin wrapper around COM1 configured for GDB RSP communication.
///
/// Initialized once at boot via [`SerialPort::init`]; all subsequent
/// use goes through the [`Connection`] impl.
pub struct SerialPort {
    data: Port<u8>,
    ier: Port<u8>,
    fcr: Port<u8>,
    lcr: Port<u8>,
    mcr: Port<u8>,
    lsr: Port<u8>,
}

impl SerialPort {
    /// Construct without touching hardware.  Call [`init`] before use.
    ///
    /// # Safety
    /// Caller must ensure no other code is concurrently driving COM1.
    pub const unsafe fn new() -> Self {
        Self {
            data: Port::new(REG_DATA),
            ier: Port::new(REG_IER),
            fcr: Port::new(REG_FCR),
            lcr: Port::new(REG_LCR),
            mcr: Port::new(REG_MCR),
            lsr: Port::new(REG_LSR),
        }
    }

    /// Program COM1 to 115200-8N1, FIFO enabled, no interrupts.
    ///
    /// Must be called exactly once before the GDB stub is started.
    ///
    /// # Safety
    /// Raw I/O port access; must not race with other users of COM1.
    pub unsafe fn init(&mut self) {
        // Disable all interrupts
        self.ier.write(0x00);

        // Enable DLAB to set baud rate divisor
        self.lcr.write(0x80);
        let mut dll: Port<u8> = Port::new(REG_DLL);
        let mut dlh: Port<u8> = Port::new(REG_DLH);
        dll.write((BAUD_115200 & 0xFF) as u8);
        dlh.write((BAUD_115200 >> 8) as u8);

        // 8 data bits, no parity, 1 stop bit (clear DLAB)
        self.lcr.write(0x03);

        // Enable FIFO, clear TX/RX queues, 14-byte threshold
        self.fcr.write(0xC7);

        // DTR + RTS + OUT2 (enables IRQ line on real hardware, harmless in QEMU)
        self.mcr.write(0x0B);
    }

    /// Block until the Line Status Register says a byte is waiting.
    #[inline]
    unsafe fn wait_rx(&mut self) {
        while self.lsr.read() & LSR_DATA_READY == 0 {
            core::hint::spin_loop();
        }
    }

    /// Block until the transmitter holding register is empty.
    #[inline]
    unsafe fn wait_tx(&mut self) {
        while self.lsr.read() & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
    }

    /// Non-blocking peek: returns `Some(byte)` if one is sitting in the FIFO.
    #[inline]
    unsafe fn try_read(&mut self) -> Option<u8> {
        if self.lsr.read() & LSR_DATA_READY != 0 {
            Some(self.data.read())
        } else {
            None
        }
    }

    /// Blocking read — spins until a byte arrives.
    #[inline]
    pub unsafe fn read_byte(&mut self) -> u8 {
        self.wait_rx();
        self.data.read()
    }

    /// Blocking write — spins until the THR is empty, then sends.
    #[inline]
    pub unsafe fn write_byte(&mut self, byte: u8) {
        self.wait_tx();
        self.data.write(byte);
    }
}

/// Infallible error type — port I/O on x86 cannot fail at the Rust level.
#[derive(Debug)]
pub enum SerialError {}

impl fmt::Display for SerialError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

impl Connection for SerialPort {
    type Error = SerialError;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        // SAFETY: `init` was called at boot; no concurrent users.
        unsafe { self.write_byte(byte) };
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        for &b in buf {
            self.write(b)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Spin until the transmitter shift register drains (LSR bit 6 = TEMT).
        // For the stub's purposes, waiting on THRE (bit 5) is sufficient.
        unsafe { self.wait_tx() };
        Ok(())
    }

    fn read(&mut self) -> Result<u8, Self::Error> {
        Ok(unsafe { self.read_byte() })
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        Ok(unsafe { self.try_read() })
    }
}
