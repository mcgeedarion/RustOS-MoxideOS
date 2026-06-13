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
//!
//! ## CBS admission (SCHED_DEADLINE)
//!
//! Before any SCHED_DEADLINE task is accepted, `cbs_admit` checks that
//! the resulting total utilization on every CPU in the task's affinity
//! mask stays ≤ 1.0 (represented as CBS_SCALE in fixed-point).  If the
//! CPU would be overcommitted the call returns -EBUSY (-16).
//!
//! CAP_SYS_NICE bypasses the utilization cap (but still updates the
//! counters so subsequent unprivileged admits see correct totals).
//!
//! When a task's deadline parameters are updated the old utilization is
//! released before the new parameters are admitted, so the counters
//! always reflect the live set of admitted tasks.

use super::errno::{eacces, ebusy, efault, einval, esrch};
use crate::proc::rlimit::{RLIMIT_NICE, RLIMIT_RTPRIO, RLIM_INFINITY};
use crate::proc::sched_helpers::{cbs_admit, cbs_release};
use crate::proc::scheduler::{SchedEntity, SchedPolicy, CPUMASK_ALL};
use crate::uaccess::{copy_from_user, copy_to_user};

// Recognised values for the `which` argument of setpriority / getpriority.
const PRIO_PROCESS: i32 = 0;

/// `struct sched_param` (single field: `sched_priority`).
#[derive(Clone, Copy, Default)]
pub struct SchedParam {
    pub sched_priority: i32,
}

/// `struct sched_attr` used by `sched_setattr` / `sched_getattr`.
///
/// Wire layout (56 bytes, little-endian on x86-64):
///   [0..4]   size          u32
///   [4..8]   sched_policy  u32
///   [8..16]  sched_flags   u64
///   [16..20] sched_nice    i32
///   [20..24] sched_priority u32
///   [24..32] sched_runtime  u64
///   [32..40] sched_deadline u64
///   [40..48] sched_period   u64
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

const SCHED_ATTR_SIZE: usize = 48; // bytes in the user-visible wire format

// All access to user-space memory goes through the byte-slice uaccess ABI,
// consistent with every other syscall module.  No typed-pointer transmutes.

/// Read a `SchedParam` (4-byte sched_priority i32) from user space.
fn read_sched_param(uptr: usize) -> Result<SchedParam, isize> {
    if uptr == 0 {
        return Err(efault());
    }
    let mut buf = [0u8; 4];
    copy_from_user(&mut buf, uptr).map_err(|_| efault())?;
    Ok(SchedParam {
        sched_priority: i32::from_ne_bytes(buf),
    })
}

/// Write a `SchedParam` to user space.
fn write_sched_param(uptr: usize, param: &SchedParam) -> Result<(), isize> {
    if uptr == 0 {
        return Err(efault());
    }
    copy_to_user(uptr, &param.sched_priority.to_ne_bytes()).map_err(|_| efault())
}

/// Read a `SchedAttr` from user space using the fixed 48-byte wire layout.
fn read_sched_attr(uptr: usize) -> Result<SchedAttr, isize> {
    if uptr == 0 {
        return Err(einval());
    }
    let mut buf = [0u8; SCHED_ATTR_SIZE];
    copy_from_user(&mut buf, uptr).map_err(|_| efault())?;
    Ok(SchedAttr {
        size: u32::from_ne_bytes(buf[0..4].try_into().unwrap_or([0; 4])),
        sched_policy: u32::from_ne_bytes(buf[4..8].try_into().unwrap_or([0; 4])),
        sched_flags: u64::from_ne_bytes(buf[8..16].try_into().unwrap_or([0; 8])),
        sched_nice: i32::from_ne_bytes(buf[16..20].try_into().unwrap_or([0; 4])),
        sched_priority: u32::from_ne_bytes(buf[20..24].try_into().unwrap_or([0; 4])),
        sched_runtime: u64::from_ne_bytes(buf[24..32].try_into().unwrap_or([0; 8])),
        sched_deadline: u64::from_ne_bytes(buf[32..40].try_into().unwrap_or([0; 8])),
        sched_period: u64::from_ne_bytes(buf[40..48].try_into().unwrap_or([0; 8])),
    })
}

/// Write a `SchedAttr` to user space using the fixed 48-byte wire layout.
fn write_sched_attr(uptr: usize, attr: &SchedAttr) -> Result<(), isize> {
    if uptr == 0 {
        return Err(efault());
    }
    let mut buf = [0u8; SCHED_ATTR_SIZE];
    buf[0..4].copy_from_slice(&attr.size.to_ne_bytes());
    buf[4..8].copy_from_slice(&attr.sched_policy.to_ne_bytes());
    buf[8..16].copy_from_slice(&attr.sched_flags.to_ne_bytes());
    buf[16..20].copy_from_slice(&attr.sched_nice.to_ne_bytes());
    buf[20..24].copy_from_slice(&attr.sched_priority.to_ne_bytes());
    buf[24..32].copy_from_slice(&attr.sched_runtime.to_ne_bytes());
    buf[32..40].copy_from_slice(&attr.sched_deadline.to_ne_bytes());
    buf[40..48].copy_from_slice(&attr.sched_period.to_ne_bytes());
    copy_to_user(uptr, &buf).map_err(|_| efault())
}

fn nice_floor(pid: usize) -> i8 {
    use crate::proc::scheduler::with_proc;
    let (soft, _) = crate::proc::scheduler::with_proc(pid, |p| p.rlimits.get(RLIMIT_NICE))
        .unwrap_or((RLIM_INFINITY, RLIM_INFINITY));
    let privileged = with_proc(pid, |p| p.caps.has(crate::security::Cap::SysNice)).unwrap_or(false);
    if privileged {
        return -20;
    }
    if soft == RLIM_INFINITY {
        return -20;
    }
    let floor = 20i64 - soft as i64;
    floor.clamp(-20, 19) as i8
}

fn rt_prio_ceiling(pid: usize) -> u8 {
    use crate::proc::scheduler::with_proc;
    let (soft, _) =
        with_proc(pid, |p| p.rlimits.get(RLIMIT_RTPRIO)).unwrap_or((RLIM_INFINITY, RLIM_INFINITY));
    let privileged = with_proc(pid, |p| p.caps.has(crate::security::Cap::SysNice)).unwrap_or(false);
    if privileged {
        return 99;
    }
    if soft == RLIM_INFINITY {
        return 99;
    }
    soft.min(99) as u8
}

/// True if the process holds CAP_SYS_NICE.
fn is_privileged(pid: usize) -> bool {
    crate::proc::scheduler::with_proc(pid, |p| p.caps.has(crate::security::Cap::SysNice))
        .unwrap_or(false)
}

/// Snapshot of a task's current deadline parameters and cpumask, used
/// to release CBS utilization before applying new parameters.
struct DeadlineSnapshot {
    runtime: u64,
    period: u64,
    cpumask: u64,
}

/// Read the current deadline parameters + cpumask for `pid` if it is
/// currently a SCHED_DEADLINE task.  Returns None otherwise.
fn snapshot_deadline(pid: usize) -> Option<DeadlineSnapshot> {
    crate::proc::scheduler::with_proc(pid, |pcb| {
        if pcb.sched.policy != SchedPolicy::Deadline {
            return None;
        }
        Some(DeadlineSnapshot {
            runtime: pcb.sched.dl_runtime,
            period: pcb.sched.dl_period,
            cpumask: pcb.sched.cpumask,
        })
    })
    .flatten()
}

/// Apply a `SchedAttr` to `pid`.
///
/// Returns 0 on success, or a negative errno isize on failure:
///   `esrch()`   — pid not found
///   `einval()`  — invalid policy or deadline parameters
///   `eacces()`  — RLIMIT_RTPRIO would be exceeded (maps to EPERM/EACCES)
///   `ebusy()`   — CBS admission refused (would overcommit a CPU)
fn apply_sched_attr(pid: usize, attr: &SchedAttr) -> isize {
    let policy = match SchedPolicy::from_u32(attr.sched_policy) {
        Some(p) => p,
        None => return einval(),
    };

    if policy == SchedPolicy::Deadline {
        if attr.sched_runtime == 0
            || attr.sched_deadline == 0
            || attr.sched_period == 0
            || attr.sched_runtime > attr.sched_deadline
            || attr.sched_deadline > attr.sched_period
        {
            return einval();
        }
    }

    if matches!(policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
        let ceiling = rt_prio_ceiling(pid);
        if ceiling == 0 {
            return eacces();
        }
        if attr.sched_priority as u8 > ceiling {
            return eacces();
        }
    }

    if policy == SchedPolicy::Deadline {
        let privileged = is_privileged(pid);

        let cpumask =
            crate::proc::scheduler::with_proc(pid, |p| p.sched.cpumask).unwrap_or(CPUMASK_ALL);

        let old = snapshot_deadline(pid);

        if let Some(ref snap) = old {
            cbs_release(snap.runtime, snap.period, snap.cpumask);
        }

        if let Err(e) = cbs_admit(
            pid,
            attr.sched_runtime,
            attr.sched_period,
            cpumask,
            privileged,
        ) {
            if let Some(ref snap) = old {
                let _ = cbs_admit(0, snap.runtime, snap.period, snap.cpumask, true);
            }
            return e as isize;
        }
    }

    if policy != SchedPolicy::Deadline {
        if let Some(snap) = snapshot_deadline(pid) {
            cbs_release(snap.runtime, snap.period, snap.cpumask);
        }
    }

    let now_ns = crate::time::monotonic_ns();

    crate::proc::scheduler::with_proc_mut(pid, |pcb, _pl| {
        let was_rt = matches!(pcb.sched.policy, SchedPolicy::Fifo | SchedPolicy::Rr);
        let becomes_rt = matches!(policy, SchedPolicy::Fifo | SchedPolicy::Rr);

        match policy {
            SchedPolicy::Normal => {
                let floor = nice_floor(pid);
                let nice = attr.sched_nice.clamp(floor as i32, 19) as i8;
                pcb.sched.nice = nice;
                pcb.sched.weight = crate::proc::scheduler::nice_to_weight_pub(nice);
                pcb.sched.policy = SchedPolicy::Normal;
                pcb.sched.rt_priority = 0;
            },
            SchedPolicy::Fifo | SchedPolicy::Rr => {
                let ceiling = rt_prio_ceiling(pid);
                let prio = (attr.sched_priority as u8).min(ceiling);
                pcb.sched.rt_priority = prio.max(1);
                pcb.sched.policy = policy;
            },
            SchedPolicy::Deadline => {
                pcb.sched.set_deadline(
                    attr.sched_runtime,
                    attr.sched_deadline,
                    attr.sched_period,
                    now_ns,
                );
            },
        }

        if was_rt || becomes_rt {
            pcb.rt_cpu_time_us = 0;
        }
    })
    .map(|_| 0isize)
    .unwrap_or_else(|| esrch())
}

/// `sys_sched_setscheduler(pid, policy, param_uptr)` [NR 144]
pub fn sys_sched_setscheduler(pid: usize, policy: u32, param_uptr: usize) -> isize {
    let param = match read_sched_param(param_uptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let attr = SchedAttr {
        size: SCHED_ATTR_SIZE as u32,
        sched_policy: policy,
        sched_priority: param.sched_priority.clamp(0, 99) as u32,
        sched_nice: 0,
        ..SchedAttr::default()
    };
    apply_sched_attr(pid, &attr)
}

/// `sys_sched_getscheduler(pid)` [NR 145]
pub fn sys_sched_getscheduler(pid: usize) -> isize {
    crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.policy as i32 as isize)
        .unwrap_or_else(|| esrch())
}

/// `sys_sched_setparam(pid, param_uptr)` [NR 142]
pub fn sys_sched_setparam(pid: usize, param_uptr: usize) -> isize {
    let param = match read_sched_param(param_uptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::proc::scheduler::with_proc_mut(pid, |pcb, _pl| {
        if pcb.sched.policy != SchedPolicy::Normal {
            let ceiling = rt_prio_ceiling(pid);
            let prio = (param.sched_priority.clamp(1, 99) as u8).min(ceiling);
            pcb.sched.rt_priority = prio;
        }
        // Normal/CFS: no-op (use setscheduler with sched_nice instead).
    })
    .map(|_| 0isize)
    .unwrap_or_else(|| esrch())
}

/// `sys_sched_getparam(pid, param_uptr)` [NR 143]
pub fn sys_sched_getparam(pid: usize, param_uptr: usize) -> isize {
    let prio = match crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.rt_priority as i32) {
        Some(p) => p,
        None => return esrch(),
    };
    let param = SchedParam {
        sched_priority: prio,
    };
    match write_sched_param(param_uptr, &param) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `sys_setpriority(which, who, prio)` [NR 141]
///
/// Only PRIO_PROCESS (which == 0) is implemented; PRIO_PGRP and
/// PRIO_USER return EINVAL (not ENOSYS) per POSIX.
pub fn sys_setpriority(which: i32, who: usize, prio: i32) -> isize {
    if which != PRIO_PROCESS {
        return einval();
    }
    let pid = if who == 0 {
        crate::proc::scheduler::current_pid()
    } else {
        who
    };
    let floor = nice_floor(pid as usize);
    let clamped = prio.clamp(floor as i32, 19) as i8;
    crate::proc::scheduler::with_proc_mut(pid as usize, |p, _pl| {
        p.sched.nice = clamped;
        p.sched.weight = crate::proc::scheduler::nice_to_weight_pub(clamped);
    })
    .map(|_| 0isize)
    .unwrap_or_else(|| esrch())
}

/// `sys_getpriority(which, who)` [NR 140]
///
/// Returns 20 - nice (kernel-internal range, 1..40) so the sign is
/// positive, matching Linux getpriority(2) semantics.
pub fn sys_getpriority(which: i32, who: usize) -> isize {
    if which != PRIO_PROCESS {
        return einval();
    }
    let pid = if who == 0 {
        crate::proc::scheduler::current_pid()
    } else {
        who
    };
    crate::proc::scheduler::with_proc(pid as usize, |p| (20 - p.sched.nice as i32) as isize)
        .unwrap_or_else(|| esrch())
}

/// `sys_sched_setaffinity(pid, cpusetsize, mask_uptr)` [NR 203]
pub fn sys_sched_setaffinity(pid: usize, cpusetsize: usize, mask_uptr: usize) -> isize {
    if mask_uptr == 0 || cpusetsize == 0 {
        return einval();
    }

    let bytes = cpusetsize.min(8);
    let mut raw = [0u8; 8];
    if copy_from_user(&mut raw[..bytes], mask_uptr).is_err() {
        return efault();
    }
    let mask = u64::from_le_bytes(raw);
    if mask == 0 {
        return einval();
    }

    let ncpus = crate::smp::num_online_cpus();
    let online_mask: u64 = if ncpus >= 64 {
        u64::MAX
    } else {
        (1u64 << ncpus) - 1
    };
    let effective = mask & online_mask;
    if effective == 0 {
        return einval();
    }

    let snap = snapshot_deadline(pid);
    if let Some(ref s) = snap {
        let privileged = is_privileged(pid);
        cbs_release(s.runtime, s.period, s.cpumask);
        if let Err(e) = cbs_admit(pid, s.runtime, s.period, effective, privileged) {
            let _ = cbs_admit(0, s.runtime, s.period, s.cpumask, true);
            return e as isize;
        }
    }

    let result = crate::proc::scheduler::with_proc_mut(pid, |pcb, _pl| {
        pcb.sched.cpumask = effective;
    });
    if result.is_none() {
        return esrch();
    }

    let current_cpu = crate::proc::scheduler::with_proc(pid, |pcb| pcb.cpu_id).unwrap_or(0);
    if effective & (1u64 << current_cpu) == 0 {
        let target = effective.trailing_zeros() as usize;
        crate::proc::scheduler::migrate_task(pid, target);
    }

    0
}

/// `sys_sched_getaffinity(pid, cpusetsize, mask_uptr)` [NR 204]
pub fn sys_sched_getaffinity(pid: usize, cpusetsize: usize, mask_uptr: usize) -> isize {
    if mask_uptr == 0 || cpusetsize == 0 {
        return einval();
    }
    let mask =
        crate::proc::scheduler::with_proc(pid, |pcb| pcb.sched.cpumask).unwrap_or(CPUMASK_ALL);
    let bytes_to_write = cpusetsize.min(8);
    let raw = mask.to_le_bytes();
    if copy_to_user(mask_uptr, &raw[..bytes_to_write]).is_err() {
        return efault();
    }
    // Zero-pad any bytes beyond what our 64-bit mask covers.
    let zero = [0u8; 8];
    let rem = cpusetsize.saturating_sub(bytes_to_write);
    if rem > 0 {
        if copy_to_user(mask_uptr + bytes_to_write, &zero[..rem.min(8)]).is_err() {
            return efault();
        }
    }
    0
}

/// `sys_sched_yield()` [NR 24]
pub fn sys_sched_yield() -> isize {
    crate::proc::scheduler::schedule();
    0
}

/// `sys_sched_get_priority_max(policy)` [NR 146]
pub fn sys_sched_get_priority_max(policy: u32) -> isize {
    match policy {
        1 | 2 => 99,
        6 => 0,
        _ => 0,
    }
}

/// `sys_sched_get_priority_min(policy)` [NR 147]
pub fn sys_sched_get_priority_min(policy: u32) -> isize {
    match policy {
        1 | 2 => 1,
        _ => 0,
    }
}

/// `sys_sched_setattr(pid, attr_uptr, flags)` [NR 314]
pub fn sys_sched_setattr(pid: usize, attr_uptr: usize, _flags: u32) -> isize {
    let attr = match read_sched_attr(attr_uptr) {
        Ok(a) => a,
        Err(e) => return e,
    };
    apply_sched_attr(pid, &attr)
}

/// `sys_sched_getattr(pid, attr_uptr, size, flags)` [NR 315]
pub fn sys_sched_getattr(pid: usize, attr_uptr: usize, _size: u32, _flags: u32) -> isize {
    let attr = match crate::proc::scheduler::with_proc(pid, |pcb| SchedAttr {
        size: SCHED_ATTR_SIZE as u32,
        sched_policy: pcb.sched.policy as u32,
        sched_flags: 0,
        sched_nice: pcb.sched.nice as i32,
        sched_priority: pcb.sched.rt_priority as u32,
        sched_runtime: pcb.sched.dl_runtime,
        sched_deadline: pcb.sched.dl_deadline,
        sched_period: pcb.sched.dl_period,
    }) {
        Some(a) => a,
        None => return esrch(),
    };
    match write_sched_attr(attr_uptr, &attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
