//! IRQ handler stubs.
//! Real IRQ handling (APIC timer, keyboard, NVMe) is added per-driver.
//! The IDT is set up in idt.rs; this file holds the Rust-side dispatch.
//!
//! ## RLIMIT_CPU enforcement
//!
//! Every tick (TICK_NS = 1 ms) the running process's `cpu_time_ns` counter
//! is incremented.  When the counter crosses a second boundary the accumulated
//! seconds are compared against the process's soft and hard CPU limits:
//!
//!   cpu_secs >= soft  → SIGXCPU (24) delivered every second as a warning.
//!   cpu_secs >= hard  → SIGKILL (9) delivered immediately (POSIX mandatory).
//!
//! PID 0 (kernel idle) is never charged or checked.

use crate::proc::scheduler::TICK_NS;

const SIGXCPU: u32 = 24;
const SIGKILL: u32 = 9;
const RLIMIT_CPU: usize = 0;

/// Called from the APIC timer IRQ to drive the scheduler.
/// Wired by apic.rs once the APIC is initialised.
#[no_mangle]
pub extern "C" fn timer_irq_handler() {
    let pid = crate::proc::scheduler::current_pid();

    // Charge the tick to the current process.
    if pid != 0 {
        let (soft, hard) = crate::proc::rlimit::getrlimit_for(pid, RLIMIT_CPU);

        let cpu_secs = crate::proc::scheduler::with_proc_mut(pid, |p| {
            p.cpu_time_ns = p.cpu_time_ns.saturating_add(TICK_NS);
            p.cpu_time_ns / 1_000_000_000
        }).unwrap_or(0);

        // Hard limit: kill immediately.
        if hard != crate::proc::rlimit::RLIM_INFINITY && cpu_secs >= hard {
            crate::proc::signal::send_signal(pid, SIGKILL);
        }
        // Soft limit: warn with SIGXCPU each elapsed second at or above limit.
        // We deliver once per second (when cpu_time_ns % 1_000_000_000 wraps
        // from the saturating_add above) to avoid signal storms.
        else if soft != crate::proc::rlimit::RLIM_INFINITY && cpu_secs >= soft {
            // Only signal on whole-second boundaries to avoid delivering on
            // every tick once the process is above the limit.
            let prev_ns = crate::proc::scheduler::with_proc(pid, |p| {
                p.cpu_time_ns.saturating_sub(TICK_NS)
            }).unwrap_or(0);
            let prev_secs = prev_ns / 1_000_000_000;
            if cpu_secs > prev_secs {
                crate::proc::signal::send_signal(pid, SIGXCPU);
            }
        }
    }

    crate::proc::scheduler::schedule();
}
