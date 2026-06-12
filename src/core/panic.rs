//! Kernel panic handler.

use core::fmt;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

/// Set to `true` the first time we enter a panic.  Used to detect
static IN_PANIC: AtomicBool = AtomicBool::new(false);

/// A `fmt::Write` sink that routes characters to the early (UART) console
/// without requiring the full console subsystem to be alive.
struct EarlyWriter;

impl fmt::Write for EarlyWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            // SAFETY: called only during panic; single-threaded by convention.
            unsafe { crate::arch::console::early_putchar(byte) };
        }
        Ok(())
    }
}

/// Structured panic information printed before the CPU halts.
#[derive(Debug)]
pub struct PanicContext<'a> {
    pub message: &'a str,
    pub file: &'a str,
    pub line: u32,
    pub column: u32,
    pub registers: Option<&'a [u8]>,
}

/// Caller must have already disabled interrupts on the local CPU.
#[cold]
#[inline(never)]
pub unsafe fn do_panic(ctx: &PanicContext<'_>) -> ! {
    if IN_PANIC.swap(true, Ordering::SeqCst) {
        let _ = write!(EarlyWriter, "\n\n[DOUBLE PANIC — halting]\n");
        arch_halt();
    }

    let _ = writeln!(
        EarlyWriter,
        "\n\n\
         ╔══════════════════════════════════════════════════════╗\n\
         ║                  K E R N E L  P A N I C              ║\n\
         ╚══════════════════════════════════════════════════════╝\n\
         Message : {}\n\
         Location: {}:{}:{}",
        ctx.message, ctx.file, ctx.line, ctx.column
    );

    if let Some(regs) = ctx.registers {
        let _ = writeln!(
            EarlyWriter,
            "Register dump ({} bytes): {:?}",
            regs.len(),
            regs
        );
    }

    arch_halt();
}

///
#[macro_export]
macro_rules! kernel_panic {
    ($msg:expr) => {{
        unsafe {
            $crate::core::panic::do_panic(&$crate::core::panic::PanicContext {
                message: $msg,
                file: file!(),
                line: line!(),
                column: column!(),
                registers: None,
            });
        }
    }};
    ($msg:expr, $regs:expr) => {{
        unsafe {
            $crate::core::panic::do_panic(&$crate::core::panic::PanicContext {
                message: $msg,
                file: file!(),
                line: line!(),
                column: column!(),
                registers: Some($regs),
            });
        }
    }};
}

/// Spin-halt the current CPU.  Uses the arch-specific idle instruction.
#[inline(always)]
unsafe fn arch_halt() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("cli; hlt", options(nomem, nostack));

        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "msr daifset, #0xf", // mask all interrupts (D, A, I, F)
            "wfi",
            options(nomem, nostack)
        );

        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("wfi", options(nomem, nostack));

        // Unknown architecture: busy-loop.
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64",
        )))]
        core::hint::spin_loop();
    }
}
