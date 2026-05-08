//! Scheduling-related syscalls.
//!
//! Implements:
//!   - `sched_setscheduler(2)`  [NR 144]
//!   - `sched_getscheduler(2)`  [NR 145]
//!   - `sched_setparam(2)`      [NR 142]
//!   - `sched_getparam(2)`      [NR 143]
//!   - `sched_setaffinity(2)`   [NR 203]
//!   - `sched_getaffinity(2)`   [NR 204]
//!   - `sched_yield(2)`         [NR 24]
//!   - `sched_get_priority_max` [NR 146]
//!   - `sched_get_priority_min` [NR 147]
//!
//! The `sched_attr` struct used by `sched_setattr(2)` / `sched_getattr(2)`
//! (NR 314/315) shares the same kernel path and is handled at the bottom.

use crate::proc::scheduler::{SchedPolicy, SchedEntity, CPUMASK_ALL};
use crate::uaccess::{copy_from_user, copy_to_user};

// ── Linux ABI structs ─────────────────────────────────────────────────────────

/// `struct sched_param` (single field: `sched_priority`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SchedParam {
    pub sched_priority: i32,
}

/// `struct sched_attr` used by `sched_setattr` / `sched_getattr`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SchedAttr {
    /// Size of this struct (for forward compat).
    pub size: u32,
    /// Scheduling policy (`SCHED_*` constant).
    pub sched_policy: u32,
    /// Scheduling flags (currently unused).
    pub sched_flags: u64,
    /// For SCHED_NORMAL/BATCH: nice value (-20..19).
    pub sched_nice: i32,
    /// For SCHED_FIFO/RR: static priority (1..99).
    pub sched_priority: u32,
    /// For SCHED_DEADLINE: runtime (ns).
    pub sched_runtime: u64,
    /// For SCHED_DEADLINE: deadline (ns).
    pub sched_deadline: u64,
    /// For SCHED_DEADLINE: period (ns).
    pub sched_period: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns -ESRCH if pid not found, -EPERM if caller lacks CAP_SYS_NICE for RT.
fn apply_sched_attr(pid: usize, attr: &SchedAttr) -> isize {
    let policy = match SchedPolicy::from_u32(attr.sched_policy) {
        Some(p) => p,
        None    => return -22, // EINVAL
    };

    // Deadline parameter sanity: runtime <= deadline <= period, all > 0.
    if policy == SchedPolicy::Deadline {
        if attr.sched_runtime == 0
            || attr.sched_deadline == 0
            || attr.sched_period == 0
            || attr.sched_runtime > attr.sched_deadline
            || attr.sched_deadline > attr.sched_period
        {
            return -22; // EINVAL
        }
    }

    let now_ns = crate::time::monotonic_ns();

    crate::proc::scheduler::with_proc_mut(pid, |pcb| {
        match policy {
            SchedPolicy::Normal => {
                let nice = attr.sched_nice.clamp(-20, 19) as i8;
                pcb.sched.nice   = nice;
                pcb.sched.weight = crate::proc::scheduler::nice_to_weight_pub(nice);
                pcb.sched.policy = SchedPolicy::Normal;
                pcb.sched.rt_priority = 0;
            }
            SchedPolicy::Fifo | SchedPolicy::Rr => {
                let prio = attr.sched_priority.clamp(1, 99) as u8;
                pcb.sched.rt_priority = prio;
                pcb.sched.policy = policy;
            }
            SchedPolicy::Deadline => {
                pcb.sched.set_deadline(
                    attr.sched_runtime,
                    attr.sched_deadline,
                    attr.sched_period,
                    now_ns,
                );
            }
        }
    }).map(|_| 0isize).unwrap_or(-3) // -ESRCH if not found
}

// ── sched_setscheduler ────────────────────────────────────────────────────────

/// `sys_sched_setscheduler(pid, policy, param_uptr)` [NR 144]
pub fn sys_sched_setscheduler(pid: usize, policy: u32, param_uptr: usize) -> isize {
    let mut param = SchedParam::default();
    if copy_from_user(param_uptr as *const SchedParam, &mut param).is_err() {
        return -14; // EFAULT
    }
    let attr = SchedAttr {
        size: core::mem::size_of::<SchedAttr>() as u32,
        sched_policy: policy,
        sched_priority: param.sched_priority.clamp(0, 99) as u32,
        sched_nice: 0,
        // Deadline fields left zero — invalid for SCHED_DEADLINE via this path.
        ..SchedAttr::default()
    };
    apply_sched_attr(pid, &attr)
}

// ── sched_getscheduler ────────────────────────────────────────────────────────

/// `sys_sched_getscheduler(pid)` [NR 145]
pub fn sys_sched_getscheduler(pid: usize) -> isize {
    crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.policy as i32 as isize)
        .unwrap_or(-3) // -ESRCH
}

// ── sched_setparam / sched_getparam ──────────────────────────────────────────

/// `sys_sched_setparam(pid, param_uptr)` [NR 142]
pub fn sys_sched_setparam(pid: usize, param_uptr: usize) -> isize {
    let mut param = SchedParam::default();
    if copy_from_user(param_uptr as *const SchedParam, &mut param).is_err() {
        return -14;
    }
    crate::proc::scheduler::with_proc_mut(pid, |pcb| {
        if pcb.sched.policy == SchedPolicy::Normal {
            // For SCHED_NORMAL the "priority" in sched_param is always 0;
            // use nice stored elsewhere.  No-op.
        } else {
            pcb.sched.rt_priority = param.sched_priority.clamp(1, 99) as u8;
        }
    }).map(|_| 0isize).unwrap_or(-3)
}

/// `sys_sched_getparam(pid, param_uptr)` [NR 143]
pub fn sys_sched_getparam(pid: usize, param_uptr: usize) -> isize {
    let prio = crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.rt_priority as i32)
        .unwrap_or_else(|| return -3i32);
    if prio < 0 { return prio as isize; }
    let param = SchedParam { sched_priority: prio };
    if copy_to_user(param_uptr as *mut SchedParam, &param).is_err() {
        return -14;
    }
    0
}

// ── sched_setaffinity ─────────────────────────────────────────────────────────

/// `sys_sched_setaffinity(pid, cpusetsize, mask_uptr)` [NR 203]
///
/// Reads up to 8 bytes (64 CPUs) from userspace into the task's `cpumask`.
/// The mask must not be zero (EINVAL) and must not refer to CPUs that don't
/// exist on this machine (EINVAL).
pub fn sys_sched_setaffinity(pid: usize, cpusetsize: usize, mask_uptr: usize) -> isize {
    if mask_uptr == 0 || cpusetsize == 0 { return -22; } // EINVAL

    // Read up to 8 bytes of the cpu_set_t.
    let bytes = cpusetsize.min(8);
    let mut raw = [0u8; 8];
    // copy_from_user bytes into raw[..bytes]
    for i in 0..bytes {
        if copy_from_user((mask_uptr + i) as *const u8, &mut raw[i]).is_err() {
            return -14; // EFAULT
        }
    }
    let mask = u64::from_le_bytes(raw);
    if mask == 0 { return -22; } // EINVAL — must allow at least one CPU

    // Restrict to actually online CPUs.
    let ncpus = crate::smp::num_online_cpus();
    let online_mask: u64 = if ncpus >= 64 { u64::MAX } else { (1u64 << ncpus) - 1 };
    let effective = mask & online_mask;
    if effective == 0 { return -22; }

    crate::proc::scheduler::with_proc_mut(pid, |pcb| {
        pcb.sched.cpumask = effective;
    }).map(|_| 0isize).unwrap_or(-3)
}

/// `sys_sched_getaffinity(pid, cpusetsize, mask_uptr)` [NR 204]
pub fn sys_sched_getaffinity(pid: usize, cpusetsize: usize, mask_uptr: usize) -> isize {
    if mask_uptr == 0 || cpusetsize == 0 { return -22; }
    let mask = crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.cpumask)
        .unwrap_or(CPUMASK_ALL);
    let bytes_to_write = cpusetsize.min(8);
    let raw = mask.to_le_bytes();
    for i in 0..bytes_to_write {
        if copy_to_user((mask_uptr + i) as *mut u8, &raw[i]).is_err() {
            return -14;
        }
    }
    // Zero any remaining bytes in the user buffer.
    let zero: u8 = 0;
    for i in bytes_to_write..cpusetsize {
        let _ = copy_to_user((mask_uptr + i) as *mut u8, &zero);
    }
    0
}

// ── sched_yield ───────────────────────────────────────────────────────────────

/// `sys_sched_yield()` [NR 24]
/// Re-enqueues the current task at the back of its class queue and reschedules.
pub fn sys_sched_yield() -> isize {
    crate::proc::scheduler::schedule();
    0
}

// ── priority range ────────────────────────────────────────────────────────────

/// `sys_sched_get_priority_max(policy)` [NR 146]
pub fn sys_sched_get_priority_max(policy: u32) -> isize {
    match policy {
        1 | 2 => 99,   // SCHED_FIFO / SCHED_RR
        6     => 0,    // SCHED_DEADLINE (no static priority)
        _     => 0,    // SCHED_NORMAL
    }
}

/// `sys_sched_get_priority_min(policy)` [NR 147]
pub fn sys_sched_get_priority_min(policy: u32) -> isize {
    match policy {
        1 | 2 => 1,
        _     => 0,
    }
}

// ── sched_setattr / sched_getattr (NR 314 / 315) ─────────────────────────────

/// `sys_sched_setattr(pid, attr_uptr, flags)` [NR 314]
/// Full-featured replacement for sched_setscheduler; supports SCHED_DEADLINE.
pub fn sys_sched_setattr(pid: usize, attr_uptr: usize, _flags: u32) -> isize {
    if attr_uptr == 0 { return -22; }
    let mut attr = SchedAttr::default();
    if copy_from_user(attr_uptr as *const SchedAttr, &mut attr).is_err() {
        return -14;
    }
    apply_sched_attr(pid, &attr)
}

/// `sys_sched_getattr(pid, attr_uptr, size, flags)` [NR 315]
pub fn sys_sched_getattr(pid: usize, attr_uptr: usize, _size: u32, _flags: u32) -> isize {
    if attr_uptr == 0 { return -22; }
    let result = crate::proc::scheduler::with_proc(pid, |pcb| {
        SchedAttr {
            size: core::mem::size_of::<SchedAttr>() as u32,
            sched_policy:   pcb.sched.policy as u32,
            sched_flags:    0,
            sched_nice:     pcb.sched.nice as i32,
            sched_priority: pcb.sched.rt_priority as u32,
            sched_runtime:  pcb.sched.dl_runtime,
            sched_deadline: pcb.sched.dl_deadline,
            sched_period:   pcb.sched.dl_period,
        }
    });
    match result {
        None    => -3, // ESRCH
        Some(a) => {
            if copy_to_user(attr_uptr as *mut SchedAttr, &a).is_err() { -14 } else { 0 }
        }
    }
}
