//! Kernel panic handler and global allocator error handler.
//! Canonical location: src/kernel/panic.rs

use crate::arch::{
    api::{Cpu, Interrupts, Serial},
    Arch,
};
use core::fmt::Write;

#[cold]
#[inline(never)]
fn halt_loop() -> ! {
    loop {
        Arch::halt();
    }
}

#[panic_handler]
#[cold]
fn panic(info: &core::panic::PanicInfo) -> ! {
    Arch::disable();
    crate::smp::ipi::halt_all_except_self();
    serial_write(b"\r\n\r\n*** KERNEL PANIC ***\r\n");
    if let Some(loc) = info.location() {
        serial_write(b"Location: ");
        serial_write(loc.file().as_bytes());
        serial_write(b":");
        serial_u64(loc.line() as u64);
        serial_write(b"\r\n");
    }
    serial_write(b"Message:  ");
    let _ = write!(ArchSerialWriter, "{}", info.message());
    serial_write(b"\r\n");
    halt_loop()
}

#[alloc_error_handler]
#[cold]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    Arch::disable();
    serial_write(b"\r\n*** OOM: alloc_error ***\r\n");
    serial_write(b"Requested size:  ");
    serial_u64(layout.size() as u64);
    serial_write(b"\r\nRequested align: ");
    serial_u64(layout.align() as u64);
    serial_write(b"\r\n");
    halt_loop()
}

struct ArchSerialWriter;
impl Write for ArchSerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_write(s.as_bytes());
        Ok(())
    }
}

fn serial_write(bytes: &[u8]) {
    for &b in bytes {
        Arch::serial_putc(b);
    }
}

fn serial_u64(mut n: u64) {
    if n == 0 {
        Arch::serial_putc(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20usize;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    serial_write(&buf[i..]);
}
