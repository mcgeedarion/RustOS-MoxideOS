//! Per-process resource limits (getrlimit / setrlimit / prlimit64).
//!
//! Stores one `(soft, hard)` pair per POSIX resource.  The soft limit is
//! the kernel-enforced ceiling; the hard limit is the unprivileged ceiling
//! for the soft limit.  Only root (CAP_SYS_RESOURCE) may raise the hard limit.
//!
//! Resources tracked:
//!   RLIMIT_CPU     (0)  — CPU time in seconds          (unenforced, stored)
//!   RLIMIT_FSIZE   (1)  — max file size                (unenforced, stored)
//!   RLIMIT_DATA    (2)  — max data segment size        (unenforced, stored)
//!   RLIMIT_STACK   (3)  — max stack size               (unenforced, stored)
//!   RLIMIT_CORE    (4)  — max core file size           (unenforced, stored)
//!   RLIMIT_RSS     (5)  — max resident set size        (unenforced, stored)
//!   RLIMIT_NPROC   (6)  — max number of processes      (unenforced, stored)
//!   RLIMIT_NOFILE  (7)  — max open file descriptors    (ENFORCED in fcntl)
//!   RLIMIT_MEMLOCK (8)  — max locked memory            (unenforced, stored)
//!   RLIMIT_AS      (9)  — max virtual address space    (ENFORCED in mmap/brk)
//!   RLIMIT_LOCKS   (10) — max file locks               (unenforced, stored)
//!   RLIMIT_SIGPENDING (11) — max pending signals       (unenforced, stored)
//!   RLIMIT_MSGQUEUE   (12) — max POSIX MQ bytes        (unenforced, stored)
//!   RLIMIT_NICE    (13) — max nice decrease            (unenforced, stored)
//!   RLIMIT_RTPRIO  (14) — max real-time priority       (unenforced, stored)
//!   RLIMIT_RTTIME  (15) — max real-time CPU time (us)  (ENFORCED in interrupts/scheduler)
//!                         soft → SIGXCPU; hard → SIGKILL.
//!                         Counter (Pcb::rt_cpu_time_us) is charged each timer
//!                         tick while the task runs under SCHED_FIFO/RR, and
//!                         reset to zero on every voluntary block (futex_wait,
//!                         nanosleep, waitpid) via scheduler::block_current().
//!                         Also reset to zero on any sched_setscheduler /
//!                         sched_setattr policy change (enter or leave RT).

// ── Resource indices ─────────────────────────────────────────────────────────

pub const RLIMIT_CPU:       usize = 0;
pub const RLIMIT_FSIZE:     usize = 1;
pub const RLIMIT_DATA:      usize = 2;
pub const RLIMIT_STACK:     usize = 3;
pub const RLIMIT_CORE:      usize = 4;
pub const RLIMIT_RSS:       usize = 5;
pub const RLIMIT_NPROC:     usize = 6;
pub const RLIMIT_NOFILE:    usize = 7;
pub const RLIMIT_MEMLOCK:   usize = 8;
pub const RLIMIT_AS:        usize = 9;
pub const RLIMIT_LOCKS:     usize = 10;
pub const RLIMIT_SIGPENDING:usize = 11;
pub const RLIMIT_MSGQUEUE:  usize = 12;
pub const RLIMIT_NICE:      usize = 13;
pub const RLIMIT_RTPRIO:    usize = 14;
pub const RLIMIT_RTTIME:    usize = 15;
pub const RLIMIT_NLIMITS:   usize = 16;

/// Sentinel: unlimited (RLIM_INFINITY).
pub const RLIM_INFINITY: u64 = u64::MAX;

// ── Defaults ─────────────────────────────────────────────────────────────────
//
// Match the Linux kernel's init_task defaults for a root process.

const DEFAULTS: [(u64, u64); RLIMIT_NLIMITS] = [
    // CPU
    (RLIM_INFINITY, RLIM_INFINITY),
    // FSIZE
    (RLIM_INFINITY, RLIM_INFINITY),
    // DATA
    (RLIM_INFINITY, RLIM_INFINITY),
    // STACK: 8 MiB soft, unlimited hard
    (8 * 1024 * 1024, RLIM_INFINITY),
    // CORE: 0 (no core dumps)
    (0, RLIM_INFINITY),
    // RSS
    (RLIM_INFINITY, RLIM_INFINITY),
    // NPROC: 65536
    (65536, 65536),
    // NOFILE: 1024 soft, 4096 hard (matches Linux defaults)
    (1024, 4096),
    // MEMLOCK: 64 KiB soft/hard (matches Linux unprivileged defaults)
    (65536, 65536),
    // AS: unlimited
    (RLIM_INFINITY, RLIM_INFINITY),
    // LOCKS
    (RLIM_INFINITY, RLIM_INFINITY),
    // SIGPENDING: 7823 (Linux default)
    (7823, 7823),
    // MSGQUEUE: 819200
    (819200, 819200),
    // NICE: 0
    (0, 0),
    // RTPRIO: 0
    (0, 0),
    // RTTIME: unlimited
    (RLIM_INFINITY, RLIM_INFINITY),
];

// ── RlimitSet ────────────────────────────────────────────────────────────────

/// Per-process resource limit table.
/// Inherited on fork/clone; shared between threads in the same thread group
/// (Linux shares rlimits across CLONE_THREAD — we clone-on-fork, which is
/// correct for processes; threads in the same group share via PCB clone).
#[derive(Clone, Debug)]
pub struct RlimitSet {
    /// (soft, hard) for each RLIMIT_* resource.  Index by RLIMIT_* constant.
    limits: [(u64, u64); RLIMIT_NLIMITS],
}

impl Default for RlimitSet {
    fn default() -> Self {
        RlimitSet { limits: DEFAULTS }
    }
}

impl RlimitSet {
    /// Get the (soft, hard) pair for `resource`.
    /// Returns (RLIM_INFINITY, RLIM_INFINITY) for out-of-range indices.
    pub fn get(&self, resource: usize) -> (u64, u64) {
        if resource < RLIMIT_NLIMITS {
            self.limits[resource]
        } else {
            (RLIM_INFINITY, RLIM_INFINITY)
        }
    }

    /// Set the (soft, hard) pair for `resource`.
    ///
    /// Rules enforced (POSIX):
    ///   1. `soft <= hard` must hold.
    ///   2. `hard` may only be raised if `new_hard <= old_hard` OR the caller
    ///      has CAP_SYS_RESOURCE — but we accept any value here and let the
    ///      syscall layer enforce privilege (prlimit64 with pid 0 = self).
    ///
    /// Returns -22 (EINVAL) if soft > hard, 0 on success.
    pub fn set(&mut self, resource: usize, soft: u64, hard: u64) -> isize {
        if resource >= RLIMIT_NLIMITS { return -22; }
        if soft > hard { return -22; }
        self.limits[resource] = (soft, hard);
        0
    }

    /// Returns `true` if opening one more fd would exceed the soft NOFILE limit.
    /// `current_open` should be the number of fds currently open.
    #[inline]
    pub fn exceeds_nofile(&self, current_open: usize) -> bool {
        let (soft, _) = self.limits[RLIMIT_NOFILE];
        soft != RLIM_INFINITY && current_open as u64 >= soft
    }

    /// Returns `true` if mapping `extra_bytes` more would exceed the soft AS limit.
    /// `current_as` should be the process's current virtual address space usage
    /// in bytes (i.e. sum of all VMA sizes).
    #[inline]
    pub fn exceeds_as(&self, current_as: usize, extra_bytes: usize) -> bool {
        let (soft, _) = self.limits[RLIMIT_AS];
        if soft == RLIM_INFINITY { return false; }
        (current_as as u64).saturating_add(extra_bytes as u64) > soft
    }
}

// ── Syscall helpers (called from stubs.rs) ───────────────────────────────────

/// sys_getrlimit / sys_prlimit64 read path: returns (soft, hard) for `resource`.
pub fn getrlimit_for(pid: usize, resource: usize) -> (u64, u64) {
    if pid == 0 {
        let me = crate::proc::scheduler::current_pid();
        crate::proc::scheduler::with_proc(me, |p| p.rlimits.get(resource))
            .unwrap_or((RLIM_INFINITY, RLIM_INFINITY))
    } else {
        crate::proc::scheduler::with_proc(pid, |p| p.rlimits.get(resource))
            .unwrap_or((RLIM_INFINITY, RLIM_INFINITY))
    }
}

/// sys_setrlimit / sys_prlimit64 write path.
/// `pid == 0` means "current process".
pub fn setrlimit_for(pid: usize, resource: usize, soft: u64, hard: u64) -> isize {
    let target = if pid == 0 {
        crate::proc::scheduler::current_pid()
    } else {
        pid
    };
    crate::proc::scheduler::with_proc_mut(target, |p| {
        p.rlimits.set(resource, soft, hard)
    }).unwrap_or(-3)
}
