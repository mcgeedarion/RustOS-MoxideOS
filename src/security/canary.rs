//! Stack canary implementation.
//!
//! Provides `__stack_chk_guard` and `__stack_chk_fail` for compiler-emitted
//! stack-protector instrumentation, plus helpers for per-task canary init.
//!
//! ## H4 fix — audit_kernel_canary was a no-op
//!
//! The previous implementation read back the canary from the *same* AtomicU64
//! using `read_volatile` and compared it to `AtomicU64::load()` — both reads
//! go to the same address, so they always agree.  A stack overwrite that
//! corrupts `__stack_chk_guard` in place would never be caught.
//!
//! Fix: `init_kernel_canary()` stores the expected canary in a *separate*
//! static `CANARY_EXPECTED` (distinct symbol, different cache line).  The
//! audit then compares the live guard against this copy; a smash that
//! overwrites `__stack_chk_guard` without also corrupting `CANARY_EXPECTED`
//! is now detectable.

use core::sync::atomic::{AtomicU64, Ordering};
use crate::rand::arch_entropy;

#[no_mangle]
pub static __stack_chk_guard: AtomicU64 = AtomicU64::new(0);

/// H4 fix: separate storage for the expected canary value so that
/// audit_kernel_canary() can detect in-place corruption of __stack_chk_guard.
/// Placed in its own cache line via repr(align) to reduce false-positive
/// aliasing with the guard itself.
#[repr(align(64))]
struct CanaryExpected(AtomicU64);
static CANARY_EXPECTED: CanaryExpected = CanaryExpected(AtomicU64::new(0));

pub fn init_kernel_canary() {
    let raw    = arch_entropy();
    let canary = raw & !0xFF;  // zero LSB: stops strcpy-style overwrites
    __stack_chk_guard.store(canary, Ordering::Relaxed);
    // H4 fix: persist expected value in the *separate* static so the audit
    // function has a ground truth that is distinct from the live guard.
    CANARY_EXPECTED.0.store(canary, Ordering::Relaxed);
    log::info!("canary: kernel __stack_chk_guard initialised");
}

pub fn new_task_canary() -> u64 {
    arch_entropy() & !0xFF
}

pub const CANARY_TLS_OFFSET: usize = 0x28;

pub unsafe fn install_canary_in_tls(tls_base: *mut u8, canary: u64) {
    let ptr = tls_base.add(CANARY_TLS_OFFSET) as *mut u64;
    core::ptr::write_volatile(ptr, canary);
}

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
    { let in_kernel = true; }

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

/// Validate the live `__stack_chk_guard` against the stored expected value.
///
/// H4 fix: compares against `CANARY_EXPECTED` (a separate static set at
/// `init_kernel_canary()` time) rather than re-reading `__stack_chk_guard`
/// itself, which made the check a tautological no-op.
pub fn audit_kernel_canary() {
    let expected = CANARY_EXPECTED.0.load(Ordering::Relaxed);
    // read_volatile so the compiler cannot CSE this with the store path.
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
