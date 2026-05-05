//! Kernel panic handler and global allocator error handler.
//!
//! On panic we:
//!   1. Disable interrupts so no timer/IRQ fires mid-panic.
//!   2. Print the panic message + location to the serial console.
//!   3. Halt in a cli/hlt loop.
//!
//! ## Message formatting
//! `info.message().as_str()` only returns `Some` for bare string literals.
//! Format args like `panic!("val={}", x)` would return `None` and lose the
//! message.  Instead we use a stack-allocated `SerialWriter` that implements
//! `core::fmt::Write` and feeds bytes directly to the UART, so all format
//! arguments are captured without any heap allocation.

use core::fmt::Write;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::asm!("cli", options(nostack, nomem)); }

    serial_raw(b"\r\n\r\n*** KERNEL PANIC ***\r\n");

    if let Some(loc) = info.location() {
        serial_raw(b"Location: ");
        serial_raw(loc.file().as_bytes());
        serial_raw(b":");
        serial_u64(loc.line() as u64);
        serial_raw(b"\r\n");
    }

    // Use SerialWriter so format args are printed, not dropped.
    serial_raw(b"Message:  ");
    let _ = write!(SerialWriter, "{}", info.message());
    serial_raw(b"\r\n");

    halt_loop()
}

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    unsafe { core::arch::asm!("cli", options(nostack, nomem)); }
    serial_raw(b"\r\n*** OOM: alloc_error ***\r\n");
    serial_raw(b"Requested size:  ");
    serial_u64(layout.size() as u64);
    serial_raw(b"\r\nRequested align: ");
    serial_u64(layout.align() as u64);
    serial_raw(b"\r\n");
    halt_loop()
}

fn halt_loop() -> ! {
    loop { unsafe { core::arch::asm!("cli; hlt", options(nostack, nomem)); } }
}

// ── Serial writer ───────────────────────────────────────────────────────────

/// Zero-size type that implements `fmt::Write` by writing bytes directly
/// to COM1 (0x3F8). No allocator, no locks — safe to use in panic context.
struct SerialWriter;

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_raw(s.as_bytes());
        Ok(())
    }
}

// ── Raw serial I/O (no allocator, no locks) ──────────────────────────────

fn serial_raw(bytes: &[u8]) {
    for &b in bytes {
        unsafe {
            loop {
                let lsr: u8;
                core::arch::asm!("in al, dx", in("dx") 0x3F8u16 + 5, out("al") lsr);
                if lsr & 0x20 != 0 { break; }
            }
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") b);
        }
    }
}

fn serial_u64(mut n: u64) {
    if n == 0 { serial_raw(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut i   = 20usize;
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    serial_raw(&buf[i..]);
}
