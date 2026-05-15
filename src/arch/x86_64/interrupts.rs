//! IRQ handler dispatch — timer, scheduler tick, rlimit enforcement.
//!
//! ## Timer tick responsibilities (called every TICK_NS = 1 ms)
//!
//!  1. Advance the monotonic clock (`time::tick_advance`).
//!  2. Fire due timer-wheel entries (`time::timer::expire_timers`).
//!  3. Fire interval timers / POSIX timers (`proc::itimer::tick`).
//!  4. Charge CPU time to the running process.
//!  5. Enforce RLIMIT_CPU  (SIGXCPU / SIGKILL).
//!  6. Enforce RLIMIT_RTTIME for SCHED_FIFO/SCHED_RR tasks.
//!  7. Call the scheduler (`schedule()`) to potentially preempt.
//!
//! ## RLIMIT_CPU
//!
//!   cpu_secs >= soft  → SIGXCPU (24) once per second.
//!   cpu_secs >= hard  → SIGKILL (9) immediately (POSIX mandatory).
//!
//! ## RLIMIT_RTTIME
//!
//! Charged only for SCHED_FIFO / SCHED_RR.  Accumulator resets on voluntary
//! block (see scheduler::block_current).  Soft limit fires SIGXCPU once;
//! hard limit fires SIGKILL.
//!
//! ## Generic exception handler
//!
//! `generic_exception_handler` is defined in idt.rs and exposed here for
//! documentation purposes only.  All exception routing goes through idt.rs.

use crate::proc::scheduler::TICK_NS;
use crate::proc::scheduler::SchedPolicy;

const SIGXCPU: u32 = 24;
const SIGKILL: u32 = 9;
const RLIMIT_CPU:    usize = 0;
const RLIMIT_RTTIME: usize = 15;

/// Called from the APIC timer IRQ stub (vector 32) on every tick.
///
/// Receives the full `InterruptFrame` so it can be inspected by profiling
/// tools or a future NMI-based sampling profiler.  For the scheduler the
/// frame pointer itself is not used — `schedule()` saves/restores context
/// through its own mechanism.
#[no_mangle]
pub extern "C" fn timer_irq_handler(frame: &mut crate::arch::x86_64::idt::InterruptFrame) {
    let _ = frame; // reserved for future profiling use

    // ── 1. Advance clock and fire timer wheel ────────────────────────────
    crate::time::tick_advance(TICK_NS);
    crate::time::timer::expire_timers();

    // ── 2. Expire interval timers and POSIX per-process timers ───────────
    // Delivers SIGALRM for ITIMER_REAL and per-timer signos for
    // timer_create() timers.  Must run after tick_advance so that
    // read_monotonic_ns() returns the updated value inside tick().
    crate::proc::itimer::tick();

    let pid = crate::proc::scheduler::current_pid();

    if pid != 0 {
        // ── 3. Charge tick and snapshot rlimit state ─────────────────────
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

        // ── 4. RLIMIT_CPU enforcement ────────────────────────────────────
        if hard_cpu != crate::proc::rlimit::RLIM_INFINITY && cpu_secs >= hard_cpu {
            crate::proc::signal::send_signal(pid, SIGKILL);
        } else if soft_cpu != crate::proc::rlimit::RLIM_INFINITY && cpu_secs >= soft_cpu {
            let prev_secs = prev_ns / 1_000_000_000;
            if cpu_secs > prev_secs {
                crate::proc::signal::send_signal(pid, SIGXCPU);
            }
        }

        // ── 5. RLIMIT_RTTIME enforcement (SCHED_FIFO / SCHED_RR only) ────
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

    // ── 6. Send EOI before calling schedule() so the APIC is unblocked ───
    // schedule() may switch to another task and not return for a long time.
    crate::arch::x86_64::apic::send_eoi();

    // ── 7. Preemption point ──────────────────────────────────────────────
    crate::proc::scheduler::schedule();
}
