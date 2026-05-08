//! Public scheduler helper functions exposed for use by the rest of the kernel
//! (syscall layer, /proc, tests).
//!
//! These are thin wrappers around the global process list + run-queue.

use crate::proc::scheduler::{SchedPolicy, NICE0_WEIGHT};

// Re-export so syscall/sched.rs can call it via the public path.
/// Public wrapper around the internal `nice_to_weight` function.
pub fn nice_to_weight_pub(nice: i8) -> u64 {
    let n = nice.clamp(-20, 19) as i64;
    let base: u64 = 1024;
    if n == 0 { return base; }
    if n > 0 {
        let mut w = base;
        for _ in 0..n { w = w * 4 / 5; }
        w.max(1)
    } else {
        let mut w = base;
        for _ in 0..(-n) { w = w * 5 / 4; }
        w
    }
}

/// Admission test for a new SCHED_DEADLINE task on `cpu`.
///
/// Returns `true` if the total utilisation after adding the proposed task
/// remains ≤ 1.0 (i.e., the sum of `runtime/period` across all deadline
/// tasks on `cpu` would not exceed 100%).
///
/// This is a simplified schedulability check; a production kernel would
/// also account for migration overhead, WCET slack, etc.
pub fn dl_admission_test(cpu: u32, runtime_ns: u64, period_ns: u64) -> bool {
    if period_ns == 0 { return false; }
    let blk = unsafe { &crate::smp::percpu::PERCPU_BLOCKS[cpu as usize] };

    // Sum utilisation of all existing deadline tasks on this CPU.
    // We iterate the run-queue entries safely by peeking the dl_heap.
    // Note: this is an O(n) scan protected by the assumption that the
    // caller holds no run-queue lock (admission is done before enqueue).
    let mut used_num: u64 = 0;   // numerator   (sum of runtimes)
    let mut used_den: u64 = 1;   // denominator (LCM of periods — simplified)

    // Walk through PCBs looking for DL tasks pinned to this CPU.
    crate::proc::scheduler::with_procs_ro(|procs| {
        for pcb in procs.iter() {
            if pcb.sched.policy == SchedPolicy::Deadline
                && pcb.sched.cpu_allowed(cpu)
                && pcb.sched.dl_period > 0
            {
                // Compute rational sum: used += dl_runtime / dl_period.
                // We work in integer arithmetic scaled to 1_000_000_000
                // (nanoseconds) to avoid FP.
                let u = pcb.sched.dl_runtime.saturating_mul(1_000_000_000)
                    / pcb.sched.dl_period;
                used_num = used_num.saturating_add(u);
            }
        }
    });

    let new_u = runtime_ns.saturating_mul(1_000_000_000) / period_ns;
    used_num.saturating_add(new_u) <= 1_000_000_000 // ≤ 100% utilisation
}
