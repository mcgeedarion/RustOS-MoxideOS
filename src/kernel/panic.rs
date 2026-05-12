//! Kernel panic handler and global allocator error handler.
//! Canonical location: src/kernel/panic.rs

use core::fmt::Write;
use crate::arch::{Arch, api::{Interrupts, Cpu, Serial}};

#[cold] #[inline(never)]
fn halt_loop() -> ! { loop { Arch::halt(); } }

#[panic_handler]
#[cold]
fn panic(info: &core::panic::PanicInfo) -> ! {
    Arch::disable();
    crate::smp::ipi::halt_all_except_self();
    Arch::serial_write(b"\r\n\r\n*** KERNEL PANIC ***\r\n");
    if let Some(loc) = info.location() {
        Arch::serial_write(b"Location: ");
        Arch::serial_write(loc.file().as_bytes());
        Arch::serial_write(b":");
        serial_u64(loc.line() as u64);
        Arch::serial_write(b"\r\n");
    }
    Arch::serial_write(b"Message:  ");
    let _ = write!(ArchSerialWriter, "{}", info.message());
    Arch::serial_write(b"\r\n");
    halt_loop()
}

#[alloc_error_handler]
#[cold]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    Arch::disable();
    Arch::serial_write(b"\r\n*** OOM: alloc_error ***\r\n");
    Arch::serial_write(b"Requested size:  "); serial_u64(layout.size() as u64);
    Arch::serial_write(b"\r\nRequested align: "); serial_u64(layout.align() as u64);
    Arch::serial_write(b"\r\n");
    halt_loop()
}

struct ArchSerialWriter;
impl Write for ArchSerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        Arch::serial_write(s.as_bytes()); Ok(())
    }
}

fn serial_u64(mut n: u64) {
    if n == 0 { Arch::serial_putc(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 20usize;
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    Arch::serial_write(&buf[i..]);
}
