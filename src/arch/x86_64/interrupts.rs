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
//!
//! ## RLIMIT_RTTIME enforcement
//!
//! Only charged when the current process runs under SCHED_FIFO or SCHED_RR.
//! The accumulator (`rt_cpu_time_us`) measures microseconds of *continuous*
//! RT execution.  It is reset to 0 each time the task voluntarily blocks
//! (see scheduler::block_current).
//!
//!   rt_cpu_time_us >= soft  → SIGXCPU delivered once.
//!   rt_cpu_time_us >= hard  → SIGKILL delivered immediately.
//!
//! Linux delivers SIGXCPU only once (at the soft limit) and then SIGKILL at
//! the hard limit — there is no repeated-per-interval warning like RLIMIT_CPU.
//!
//! ## Timer wheel
//!
//! Every tick calls `time::tick_advance(TICK_NS)` to advance the monotonic
//! clock, then `time::timer::expire_timers()` to fire any due callbacks
//! (nanosleep wakeups, ITIMER_REAL, timerfd, etc.).

use crate::proc::scheduler::TICK_NS;
use crate::proc::scheduler::SchedPolicy;

const SIGXCPU: u32 = 24;
const SIGKILL: u32 = 9;
const RLIMIT_CPU:    usize = 0;
const RLIMIT_RTTIME: usize = 15;

/// Called from the APIC timer IRQ to drive the scheduler.
/// Wired by apic.rs once the APIC is initialised.
#[no_mangle]
pub extern "C" fn timer_irq_handler() {
    // ────────────────────────────────────────────────────────────────
    // 0. Advance monotonic clock + fire due timer-wheel entries.
    //    Must happen before rlimit checks so that nanosleep wakeup callbacks
    //    run at the correct time and transition tasks to Ready before
    //    schedule() picks them up.
    // ────────────────────────────────────────────────────────────────
    crate::time::tick_advance(TICK_NS);
    crate::time::timer::expire_timers();

    let pid = crate::proc::scheduler::current_pid();

    if pid != 0 {
        // ────────────────────────────────────────────────────────────────
        // 1. Charge the tick and read back state in one lock acquisition.
        // ────────────────────────────────────────────────────────────────
        let (soft_cpu, hard_cpu) = crate::proc::rlimit::getrlimit_for(pid, RLIMIT_CPU);
        let (soft_rt,  hard_rt)  = crate::proc::rlimit::getrlimit_for(pid, RLIMIT_RTTIME);

        let (cpu_secs, prev_ns, rt_us, policy) =
            crate::proc::scheduler::with_proc_mut(pid, |p| {
                let prev = p.cpu_time_ns;
                p.cpu_time_ns = p.cpu_time_ns.saturating_add(TICK_NS);

                let policy = p.sched.policy;
                if matches!(policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
                    p.rt_cpu_time_us = p.rt_cpu_time_us
                        .saturating_add(TICK_NS / 1_000);
                }

                (
                    p.cpu_time_ns / 1_000_000_000,
                    prev,
                    p.rt_cpu_time_us,
                    policy,
                )
            }).unwrap_or((0, 0, 0, SchedPolicy::Normal));

        // ────────────────────────────────────────────────────────────────
        // 2. RLIMIT_CPU enforcement.
        // ────────────────────────────────────────────────────────────────
        if hard_cpu != crate::proc::rlimit::RLIM_INFINITY && cpu_secs >= hard_cpu {
            crate::proc::signal::send_signal(pid, SIGKILL);
        } else if soft_cpu != crate::proc::rlimit::RLIM_INFINITY && cpu_secs >= soft_cpu {
            let prev_secs = prev_ns / 1_000_000_000;
            if cpu_secs > prev_secs {
                crate::proc::signal::send_signal(pid, SIGXCPU);
            }
        }

        // ────────────────────────────────────────────────────────────────
        // 3. RLIMIT_RTTIME enforcement — only for SCHED_FIFO / SCHED_RR.
        // ────────────────────────────────────────────────────────────────
        if matches!(policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
            if hard_rt != crate::proc::rlimit::RLIM_INFINITY && rt_us >= hard_rt {
                crate::proc::signal::send_signal(pid, SIGKILL);
            } else if soft_rt != crate::proc::rlimit::RLIM_INFINITY && rt_us >= soft_rt {
                let prev_rt_us = rt_us.saturating_sub(TICK_NS / 1_000);
                if prev_rt_us < soft_rt {
                    crate::proc::signal::send_signal(pid, SIGXCPU);
                }
            }
        }
    }

    crate::proc::scheduler::schedule();
}
