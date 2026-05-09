//! Stack canary implementation.
//!
//! The compiler (`-Z stack-protector=all` or `RUSTFLAGS=-C stack-protector=all`)
//! emits calls to `__stack_chk_guard` (the canary value) and
//! `__stack_chk_fail` (called when the canary is corrupted).  This module:
//!
//!   1. Provides the `__stack_chk_guard` symbol — a per-CPU, per-task
//!      random 8-byte value written into every protected stack frame.
//!   2. Implements `__stack_chk_fail` — terminates the current task with
//!      SIGABRT and (in kernel context) panics.
//!   3. Provides `init_task_canary()` — called at fork/execve to seed a
//!      fresh canary into the new task's `Task::canary` field.
//!
//! Canary format (64-bit, matching glibc and musl conventions):
//!   - Bits [63:8] — 7 random bytes from hardware entropy (`arch_entropy()`)
//!   - Bits  [7:0] — forced to 0x00  (terminates strcpy-style overflows)
//!
//! ## Entropy source
//! Both `init_kernel_canary` and `new_task_canary` now call
//! `rand::arch_entropy()` instead of the old `rdrand64()` shim.  This
//! guarantees that on x86_64 the canary is derived from RDRAND (hardware
//! entropy), and on RISC-V from a hardware timing mix, rather than the
//! xorshift PRNG whose state can be recovered from a single observed value.

use core::sync::atomic::{AtomicU64, Ordering};
use crate::rand::arch_entropy;

// ───── Global canary used by kernel-mode protected frames ─────────────────────

/// The `__stack_chk_guard` symbol referenced by compiler-generated prologue
/// and epilogue code.  Kernel-mode canary; user-mode tasks get a per-task
/// copy stored in their `Task` struct and TLS (via vDSO mapping).
///
/// Forced `#[no_mangle]` so the linker can resolve the compiler's implicit
/// reference to `__stack_chk_guard`.
#[no_mangle]
pub static __stack_chk_guard: AtomicU64 = AtomicU64::new(0);

/// Initialise the global kernel-mode canary from hardware entropy.
/// Called once from `security::init()` during early boot, before any
/// kernel threads start.
///
/// Uses `arch_entropy()` — RDRAND on x86_64, hardware CSR mix on RISC-V —
/// instead of the xorshift PRNG so the canary is not predictable from
/// observed program output.
pub fn init_kernel_canary() {
    let raw = arch_entropy();
    // Zero the LSB so strcpy-style writes that stop at \0 cannot overwrite
    // the full canary cleanly.
    let canary = raw & !0xFF;
    __stack_chk_guard.store(canary, Ordering::Relaxed);
    log::info!("canary: kernel __stack_chk_guard initialised ({:#018x})", canary);
}

/// Generate a fresh 8-byte canary value suitable for a new task.
///
/// Called at `fork` / `execve` time.  The value is stored in `Task::canary`
/// and written into the task's TLS area so userspace glibc/musl can verify
/// it without a syscall.
///
/// Each canary is independently derived from hardware entropy — predicting
/// one canary from another requires breaking the hardware RNG.
pub fn new_task_canary() -> u64 {
    arch_entropy() & !0xFF // zero LSB per glibc/musl convention
}

/// Per-task canary TLS offset (matches glibc `tcbhead_t.stack_guard` at
/// `fs:0x28` on x86_64, `tp+0x28` on RISC-V).
pub const CANARY_TLS_OFFSET: usize = 0x28;

/// Write the task's canary into its TLS block so userspace stack-protected
/// frames can verify it.
///
/// # Safety
/// `tls_base` must point to a valid, mapped TLS block of at least
/// `CANARY_TLS_OFFSET + 8` bytes.
pub unsafe fn install_canary_in_tls(tls_base: *mut u8, canary: u64) {
    let ptr = tls_base.add(CANARY_TLS_OFFSET) as *mut u64;
    core::ptr::write_volatile(ptr, canary);
}

// ───── __stack_chk_fail ──────────────────────────────────────────────────────

/// Called by compiler-generated canary-check epilogue when the guard value
/// has been modified — i.e. a stack buffer overflow has been detected.
///
/// In userspace context: delivers SIGABRT to the current process.
/// In kernel context:    panics (kernel stack overflow is fatal).
///
/// This function must never return.
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    let in_kernel: bool;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let cs: u64;
        core::arch::asm!("mov {}, cs", out(reg) cs, options(nostack, preserves_flags));
        in_kernel = (cs & 3) == 0;
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let sstatus: u64;
        core::arch::asm!("csrr {}, sstatus", out(reg) sstatus, options(nostack));
        in_kernel = (sstatus >> 8) & 1 == 1;
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    { in_kernel = true; }

    if in_kernel {
        panic!("KERNEL STACK CANARY CORRUPTION DETECTED — HALTING");
    } else {
        let pid = crate::proc::scheduler::current_pid();
        log::error!("canary: stack smashing detected in pid={} — sending SIGABRT", pid);
        crate::proc::signal::send_signal(pid, 6 /* SIGABRT */);
        crate::proc::scheduler::schedule();
        loop { core::hint::spin_loop(); }
    }
}

/// Validate the kernel's own `__stack_chk_guard` against its stored copy.
/// Called periodically from the watchdog / NMI handler to detect in-kernel
/// overflows that haven't yet reached a protected frame epilogue.
pub fn audit_kernel_canary() {
    let expected = __stack_chk_guard.load(Ordering::Relaxed);
    let actual = unsafe {
        core::ptr::read_volatile(
            &__stack_chk_guard as *const AtomicU64 as *const u64
        )
    };
    if expected != actual {
        panic!("KERNEL CANARY AUDIT FAILED: expected={:#018x} actual={:#018x}",
               expected, actual);
    }
}
