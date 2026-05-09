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
//!   - `setpriority(2)`         [NR 141]
//!   - `getpriority(2)`         [NR 140]
//!
//! The `sched_attr` struct used by `sched_setattr(2)` / `sched_getattr(2)`
//! (NR 314/315) shares the same kernel path and is handled at the bottom.
//!
//! ## RLIMIT_NICE and RLIMIT_RTPRIO enforcement
//!
//! `RLIMIT_NICE` limits how far an unprivileged process can **lower** its
//! nice value (i.e. raise its priority).  The formula mirrors Linux:
//!
//!     min_nice = 20 - rlimit_nice_soft
//!
//! So `RLIMIT_NICE = 0` → only nice >= 20 (lowest priority).
//!    `RLIMIT_NICE = 40` → full range (-20..19).
//!
//! CAP_SYS_NICE bypasses the limit entirely.
//!
//! `RLIMIT_RTPRIO` is the maximum RT priority an unprivileged process may
//! request.  Priority 0 means no RT scheduling is allowed.

use crate::proc::scheduler::{SchedPolicy, SchedEntity, CPUMASK_ALL};
use crate::proc::rlimit::{RLIMIT_NICE, RLIMIT_RTPRIO, RLIM_INFINITY};
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
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: u32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
}

// ── RLIMIT helpers ────────────────────────────────────────────────────────────

/// Returns the minimum nice value the calling process is allowed to set,
/// honouring `RLIMIT_NICE`.  Processes with `CAP_SYS_NICE` are unrestricted.
fn nice_floor(pid: usize) -> i8 {
    use crate::proc::scheduler::with_proc;
    let (soft, _) = crate::proc::scheduler::with_proc(pid, |p| p.rlimits.get(RLIMIT_NICE))
        .unwrap_or((RLIM_INFINITY, RLIM_INFINITY));
    let privileged = with_proc(pid, |p| p.caps.has(crate::security::Cap::SysNice))
        .unwrap_or(false);
    if privileged { return -20; }
    if soft == RLIM_INFINITY { return -20; }
    // Linux formula: min_nice = 20 - rlim_cur  (clamped to [-20, 19])
    let floor = 20i64 - soft as i64;
    floor.clamp(-20, 19) as i8
}

/// Returns the maximum RT priority the calling process is allowed to request.
/// 0 means no RT policy is permitted.  `CAP_SYS_NICE` is unrestricted (99).
fn rt_prio_ceiling(pid: usize) -> u8 {
    use crate::proc::scheduler::with_proc;
    let (soft, _) = with_proc(pid, |p| p.rlimits.get(RLIMIT_RTPRIO))
        .unwrap_or((RLIM_INFINITY, RLIM_INFINITY));
    let privileged = with_proc(pid, |p| p.caps.has(crate::security::Cap::SysNice))
        .unwrap_or(false);
    if privileged { return 99; }
    if soft == RLIM_INFINITY { return 99; }
    soft.min(99) as u8
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns -ESRCH if pid not found, -EPERM if the change violates a limit.
fn apply_sched_attr(pid: usize, attr: &SchedAttr) -> isize {
    let policy = match SchedPolicy::from_u32(attr.sched_policy) {
        Some(p) => p,
        None    => return -22, // EINVAL
    };

    if policy == SchedPolicy::Deadline {
        if attr.sched_runtime == 0
            || attr.sched_deadline == 0
            || attr.sched_period == 0
            || attr.sched_runtime > attr.sched_deadline
            || attr.sched_deadline > attr.sched_period
        {
            return -22;
        }
    }

    // ── RLIMIT_RTPRIO: reject unprivileged RT elevation ───────────────────────
    if matches!(policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
        let ceiling = rt_prio_ceiling(pid);
        if ceiling == 0 {
            return -13; // EPERM — RT scheduling not allowed at all
        }
        if attr.sched_priority as u8 > ceiling {
            return -13; // EPERM — requested priority exceeds RLIMIT_RTPRIO
        }
    }

    let now_ns = crate::time::monotonic_ns();

    crate::proc::scheduler::with_proc_mut(pid, |pcb| {
        let was_rt    = matches!(pcb.sched.policy, SchedPolicy::Fifo | SchedPolicy::Rr);
        let becomes_rt = matches!(policy, SchedPolicy::Fifo | SchedPolicy::Rr);

        match policy {
            SchedPolicy::Normal => {
                // ── RLIMIT_NICE: clamp nice to the permitted floor ─────────────
                let floor = nice_floor(pid);
                let nice  = attr.sched_nice.clamp(floor as i32, 19) as i8;
                pcb.sched.nice   = nice;
                pcb.sched.weight = crate::proc::scheduler::nice_to_weight_pub(nice);
                pcb.sched.policy = SchedPolicy::Normal;
                pcb.sched.rt_priority = 0;
            }
            SchedPolicy::Fifo | SchedPolicy::Rr => {
                let ceiling = rt_prio_ceiling(pid);
                let prio    = (attr.sched_priority as u8).min(ceiling);
                pcb.sched.rt_priority = prio.max(1); // enforce minimum 1 for RT
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

        // Reset the RLIMIT_RTTIME accumulator on any RT policy change.
        if was_rt || becomes_rt {
            pcb.rt_cpu_time_us = 0;
        }
    }).map(|_| 0isize).unwrap_or(-3)
}

// ── sched_setscheduler ────────────────────────────────────────────────────────

/// `sys_sched_setscheduler(pid, policy, param_uptr)` [NR 144]
pub fn sys_sched_setscheduler(pid: usize, policy: u32, param_uptr: usize) -> isize {
    let mut param = SchedParam::default();
    if copy_from_user(param_uptr as *const SchedParam, &mut param).is_err() {
        return -14;
    }
    let attr = SchedAttr {
        size: core::mem::size_of::<SchedAttr>() as u32,
        sched_policy: policy,
        sched_priority: param.sched_priority.clamp(0, 99) as u32,
        sched_nice: 0,
        ..SchedAttr::default()
    };
    apply_sched_attr(pid, &attr)
}

// ── sched_getscheduler ────────────────────────────────────────────────────────

/// `sys_sched_getscheduler(pid)` [NR 145]
pub fn sys_sched_getscheduler(pid: usize) -> isize {
    crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.policy as i32 as isize)
        .unwrap_or(-3)
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
            // No-op for CFS tasks.
        } else {
            let ceiling = rt_prio_ceiling(pid);
            let prio    = (param.sched_priority.clamp(1, 99) as u8).min(ceiling);
            pcb.sched.rt_priority = prio;
        }
    }).map(|_| 0isize).unwrap_or(-3)
}

/// `sys_sched_getparam(pid, param_uptr)` [NR 143]
pub fn sys_sched_getparam(pid: usize, param_uptr: usize) -> isize {
    let prio = crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.rt_priority as i32)
        .unwrap_or_else(|| -3i32);
    if prio < 0 { return prio as isize; }
    let param = SchedParam { sched_priority: prio };
    if copy_to_user(param_uptr as *mut SchedParam, &param).is_err() {
        return -14;
    }
    0
}

// ── setpriority / getpriority ─────────────────────────────────────────────────

/// `sys_setpriority(which, who, prio)` [NR 141]
///
/// `which`: 0=PRIO_PROCESS, 1=PRIO_PGRP, 2=PRIO_USER.
/// `prio` is the **userspace nice value** — already in the conventional
/// -20..19 range (the kernel's internal range is the same).
pub fn sys_setpriority(which: i32, who: usize, prio: i32) -> isize {
    if which != 0 { return -38; } // ENOSYS for PGRP/USER for now
    let pid = if who == 0 { crate::proc::scheduler::current_pid() } else { who };
    let floor = nice_floor(pid);
    let clamped = prio.clamp(floor as i32, 19) as i8;
    crate::proc::scheduler::with_proc_mut(pid, |p| {
        p.sched.nice   = clamped;
        p.sched.weight = crate::proc::scheduler::nice_to_weight_pub(clamped);
    }).map(|_| 0isize).unwrap_or(-3)
}

/// `sys_getpriority(which, who)` [NR 140]
///
/// Returns `20 - nice` (the kernel convention: higher return value = higher
/// priority) so the libc wrapper can negate and subtract 20 to get the
/// conventional nice value.
pub fn sys_getpriority(which: i32, who: usize) -> isize {
    if which != 0 { return -38; }
    let pid = if who == 0 { crate::proc::scheduler::current_pid() } else { who };
    crate::proc::scheduler::with_proc(pid, |p| (20 - p.sched.nice as i32) as isize)
        .unwrap_or(-3)
}

// ── sched_setaffinity ─────────────────────────────────────────────────────────

/// `sys_sched_setaffinity(pid, cpusetsize, mask_uptr)` [NR 203]
pub fn sys_sched_setaffinity(pid: usize, cpusetsize: usize, mask_uptr: usize) -> isize {
    if mask_uptr == 0 || cpusetsize == 0 { return -22; }
    let bytes = cpusetsize.min(8);
    let mut raw = [0u8; 8];
    for i in 0..bytes {
        if copy_from_user((mask_uptr + i) as *const u8, &mut raw[i]).is_err() {
            return -14;
        }
    }
    let mask = u64::from_le_bytes(raw);
    if mask == 0 { return -22; }
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
    let zero: u8 = 0;
    for i in bytes_to_write..cpusetsize {
        let _ = copy_to_user((mask_uptr + i) as *mut u8, &zero);
    }
    0
}

// ── sched_yield ───────────────────────────────────────────────────────────────

/// `sys_sched_yield()` [NR 24]
pub fn sys_sched_yield() -> isize {
    crate::proc::scheduler::schedule();
    0
}

// ── priority range ────────────────────────────────────────────────────────────

/// `sys_sched_get_priority_max(policy)` [NR 146]
pub fn sys_sched_get_priority_max(policy: u32) -> isize {
    match policy {
        1 | 2 => 99,
        6     => 0,
        _     => 0,
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
        None    => -3,
        Some(a) => {
            if copy_to_user(attr_uptr as *mut SchedAttr, &a).is_err() { -14 } else { 0 }
        }
    }
}
