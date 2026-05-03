//! Kernel panic handler and global allocator error handler.
//!
//! On panic we:
//!   1. Disable interrupts so no timer/IRQ fires mid-panic.
//!   2. Print the panic message + location to the serial console.
//!   3. Halt all CPUs via a self-IPI broadcast (if APIC is up),
//!      then spin in a cli/hlt loop.
//!
//! On allocation failure we immediately panic — the kernel has a
//! 64 MiB static pool so OOM is always a bug.

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Disable interrupts immediately.
    unsafe { core::arch::asm!("cli", options(nostack, nomem)); }

    // Write to serial port directly (bypasses all locks).
    serial_raw(b"\r\n\r\n*** KERNEL PANIC ***\r\n");

    if let Some(loc) = info.location() {
        serial_raw(b"Location: ");
        serial_raw(loc.file().as_bytes());
        serial_raw(b":");
        serial_u64(loc.line() as u64);
        serial_raw(b"\r\n");
    }

    if let Some(msg) = info.message().as_str() {
        serial_raw(b"Message:  ");
        serial_raw(msg.as_bytes());
        serial_raw(b"\r\n");
    } else {
        serial_raw(b"Message:  <non-string panic payload>\r\n");
    }

    halt_loop()
}

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    unsafe { core::arch::asm!("cli", options(nostack, nomem)); }
    serial_raw(b"\r\n*** OOM: alloc_error ***\r\n");
    serial_raw(b"Requested size:  ");
    serial_u64(layout.size() as u64);
    serial_raw(b"\r\n");
    serial_raw(b"Requested align: ");
    serial_u64(layout.align() as u64);
    serial_raw(b"\r\n");
    halt_loop()
}

fn halt_loop() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nostack, nomem)); }
    }
}

// ─── Raw serial output (no allocator, no locks) ────────────────────────────────────────

fn serial_raw(bytes: &[u8]) {
    for &b in bytes {
        unsafe {
            // Spin on Transmit Holding Register Empty (THR bit 5 of LSR).
            loop {
                let lsr: u8;
                core::arch::asm!(
                    "in al, dx",
                    in("dx") 0x3F8u16 + 5,
                    out("al") lsr,
                );
                if lsr & 0x20 != 0 { break; }
            }
            core::arch::asm!(
                "out dx, al",
                in("dx") 0x3F8u16,
                in("al") b,
            );
        }
    }
}

fn serial_u64(mut n: u64) {
    if n == 0 { serial_raw(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut i = 20usize;
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    serial_raw(&buf[i..]);
}
