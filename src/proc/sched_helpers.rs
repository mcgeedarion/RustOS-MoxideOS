//! CBS (Constant Bandwidth Server) admission accounting and misc scheduler
//! helpers that are shared between `scheduler.rs` and `syscall/sched.rs`.
//!
//! ## Utilization tracking
//!
//! Each SCHED_DEADLINE task contributes a utilization fraction
//!
//!     U_i = runtime_i / period_i
//!
//! to every CPU in its affinity mask.  We store the sum in a per-CPU
//! `AtomicU64` scaled by `CBS_SCALE = 2^32`, so one full CPU worth of
//! utilization equals exactly `CBS_SCALE`.
//!
//!     scaled_U_i = (runtime_i as u128 << 32) / period_i
//!
//! Admission is rejected with `-EBUSY` if adding the new task's scaled
//! utilization to any of its allowed CPUs would reach or exceed
//! `CBS_SCALE`.
//!
//! Callers must release utilization (`cbs_release`) before calling
//! `cbs_admit` again for the same task (e.g. on parameter updates).

use core::sync::atomic::{AtomicU64, Ordering};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Fixed-point scale: 1.0 CPU = CBS_SCALE units.
pub const CBS_SCALE: u64 = 1u64 << 32;

/// Maximum CPUs tracked by the admission table.
/// Must be ≥ the maximum CPUMASK bit width (64).
pub const MAX_CBS_CPUS: usize = 64;

// ── Global utilization table ──────────────────────────────────────────────────

/// Per-CPU utilization accumulators.  Index = CPU id.
/// Value = sum of (runtime << 32) / period for all DEADLINE tasks
/// whose cpumask includes that CPU.
struct CbsUtilBucket {
    cpu: [AtomicU64; MAX_CBS_CPUS],
}

// SAFETY: AtomicU64 is Send+Sync; the array wrapper just adds a name.
unsafe impl Sync for CbsUtilBucket {}

impl CbsUtilBucket {
    const fn new() -> Self {
        Self {
            cpu: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
            ],
        }
    }
}

static CBS_UTIL: CbsUtilBucket = CbsUtilBucket::new();

// ── Admission test ────────────────────────────────────────────────────────────

fn scaled_util(runtime: u64, period: u64) -> Option<u64> {
    if period == 0 { return None; }
    let wide = (runtime as u128) << 32;
    let result = wide / period as u128;
    if result > u64::MAX as u128 { return None; }
    Some(result as u64)
}

/// Attempt to admit a DEADLINE task.
///
/// - `_pid`      : task being admitted (reserved for future per-task tracking)
/// - `runtime`   : `sched_runtime` in nanoseconds
/// - `period`    : `sched_period` in nanoseconds
/// - `cpumask`   : bitmask of CPUs the task may run on
/// - `privileged`: if true (CAP_SYS_NICE), skip the utilization check
///
/// On success the per-CPU utilization counters are updated atomically.
/// On failure **no** counters are modified.
///
/// Returns `Ok(())` or `Err(-16)` (EBUSY) / `Err(-22)` (EINVAL).
pub fn cbs_admit(
    _pid: usize,
    runtime: u64,
    period: u64,
    cpumask: u64,
    privileged: bool,
) -> Result<(), i32> {
    let su = scaled_util(runtime, period).ok_or(-22i32)?;

    if privileged {
        commit(su, cpumask);
        return Ok(());
    }

    let ncpus = crate::smp::percpu::cpu_count() as usize;
    let ncpus = ncpus.min(MAX_CBS_CPUS);

    for cpu in 0..ncpus {
        if cpumask & (1u64 << cpu) == 0 { continue; }
        let current = CBS_UTIL.cpu[cpu].load(Ordering::Relaxed);
        if current.saturating_add(su) > CBS_SCALE {
            return Err(-16); // EBUSY
        }
    }

    commit(su, cpumask);
    Ok(())
}

/// Release the utilization previously claimed by a DEADLINE task.
///
/// Must be called when a task exits, changes policy away from Deadline,
/// or is about to have its parameters updated (release old, admit new).
pub fn cbs_release(runtime: u64, period: u64, cpumask: u64) {
    let su = match scaled_util(runtime, period) {
        Some(v) => v,
        None    => return,
    };
    let ncpus = crate::smp::percpu::cpu_count() as usize;
    let ncpus = ncpus.min(MAX_CBS_CPUS);
    for cpu in 0..ncpus {
        if cpumask & (1u64 << cpu) == 0 { continue; }
        // Saturating sub: guard against double-release bugs.
        let prev = CBS_UTIL.cpu[cpu].load(Ordering::Relaxed);
        CBS_UTIL.cpu[cpu].fetch_sub(su.min(prev), Ordering::Relaxed);
    }
}

/// Query the current utilization (0..=CBS_SCALE) for a CPU.
/// Returns CBS_SCALE + 1 if `cpu` is out of range.
pub fn cbs_util_for_cpu(cpu: usize) -> u64 {
    if cpu >= MAX_CBS_CPUS { return CBS_SCALE + 1; }
    CBS_UTIL.cpu[cpu].load(Ordering::Relaxed)
}

fn commit(su: u64, cpumask: u64) {
    let ncpus = crate::smp::percpu::cpu_count() as usize;
    let ncpus = ncpus.min(MAX_CBS_CPUS);
    for cpu in 0..ncpus {
        if cpumask & (1u64 << cpu) == 0 { continue; }
        CBS_UTIL.cpu[cpu].fetch_add(su, Ordering::Relaxed);
    }
}

// ── nice_to_weight (re-export for syscall/sched.rs) ───────────────────────────

pub fn nice_to_weight_pub(nice: i8) -> u64 {
    crate::proc::scheduler::nice_to_weight(nice)
}
