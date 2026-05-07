//! Kernel panic handler and global allocator error handler.
//!
//! On panic we:
//!   1. Halt IPIs on all other CPUs.
//!   2. Disable interrupts on the current CPU via the arch HAL.
//!   3. Print the panic message + location to the serial console.
//!   4. Halt via the arch HAL (x86 `hlt`, RISC-V `wfi`).
//!
//! ## Arch-neutrality
//! This file must compile for every supported architecture.  All
//! arch-specific operations (disable interrupts, write serial byte, halt)
//! go through the `crate::arch` HAL traits so that the same source is
//! used on x86_64 and riscv64.  No inline `asm!` blocks appear here.

use core::fmt::Write;
use crate::arch::{Arch, api::{Interrupts, Cpu, Serial}};

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // 1. Disable local interrupts first so no timer fires mid-panic.
    Arch::disable();

    // 2. Halt all other CPUs via IPI (best-effort; SMP may not be up yet).
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
fn alloc_error(layout: core::alloc::Layout) -> ! {
    Arch::disable();
    Arch::serial_write(b"\r\n*** OOM: alloc_error ***\r\n");
    Arch::serial_write(b"Requested size:  ");
    serial_u64(layout.size() as u64);
    Arch::serial_write(b"\r\nRequested align: ");
    serial_u64(layout.align() as u64);
    Arch::serial_write(b"\r\n");
    halt_loop()
}

fn halt_loop() -> ! {
    // Interrupts are already disabled; loop on the arch halt primitive.
    // x86: `hlt` sleeps until NMI/SMI (benign, loops back).
    // RISC-V: `wfi` sleeps until interrupt (interrupts disabled so never wakes).
    loop { Arch::halt(); }
}

// ── Serial writer ───────────────────────────────────────────────────────────

/// Zero-size type that implements `fmt::Write` by writing bytes directly
/// to the arch serial port.  No allocator, no locks — safe in panic context.
struct ArchSerialWriter;

impl Write for ArchSerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        Arch::serial_write(s.as_bytes());
        Ok(())
    }
}

fn serial_u64(mut n: u64) {
    if n == 0 { Arch::serial_putc(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i   = 20usize;
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    Arch::serial_write(&buf[i..]);
}
