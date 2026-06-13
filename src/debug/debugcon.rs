//! QEMU debugcon port (0xe9) — zero-overhead logging that bypasses the UART
//! driver, safe to call before the console is initialised.
//!
//! Enable in QEMU with:
//!   -debugcon stdio              # mix with QEMU output on stdout
//!   -debugcon file:kernel.log    # dedicated file (recommended)
//!
//! The port is a QEMU-specific convention; writes to 0xe9 are no-ops on real
//! hardware, so these functions are always safe to call without a feature gate.
//!
//! On RISC-V this module is not compiled (see mod.rs cfg guard).  Use
//! SBI `console_putchar` (ecall extension 0x01) for equivalent early output.

const DEBUGCON_PORT: u16 = 0xe9;

/// Write a single byte to the QEMU debugcon port.
#[inline(always)]
pub fn putb(b: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") DEBUGCON_PORT,
            in("al") b,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Write a UTF-8 string slice to the debugcon port.
#[inline(always)]
pub fn puts(s: &str) {
    for b in s.bytes() {
        putb(b);
    }
}

/// `dprint!` — like `kprint!` but writes to debugcon instead of the TTY.
///
/// ```rust
/// dprint!("[boot] stack at {:#x}\n", stack_ptr);
/// ```
#[macro_export]
macro_rules! dprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct _Dc;
        impl core::fmt::Write for _Dc {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                $crate::debug::debugcon::puts(s);
                Ok(())
            }
        }
        let _ = core::fmt::write(&mut _Dc, format_args!($($arg)*));
    }};
}

/// `dprintln!` — `dprint!` with a trailing newline.
#[macro_export]
macro_rules! dprintln {
    ()            => { $crate::dprint!("\n") };
    ($($arg:tt)*) => { $crate::dprint!("{}", format_args!($($arg)*)); $crate::dprint!("\n") };
}
