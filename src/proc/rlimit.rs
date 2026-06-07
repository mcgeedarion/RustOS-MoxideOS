//! Per-process resource limits (getrlimit / setrlimit / prlimit64).
//!
//! Stores one `(soft, hard)` pair per POSIX resource.  The soft limit is
//! the kernel-enforced ceiling; the hard limit is the unprivileged ceiling
//! for the soft limit.  Only root (CAP_SYS_RESOURCE) may raise the hard limit.
//!
//! ## Enforcement status
//!
//!   RLIMIT_CPU     (0)  — CPU time in seconds          ENFORCED  (interrupts:
//! SIGXCPU/SIGKILL)   RLIMIT_FSIZE   (1)  — max file size
//! ENFORCED  (write/writev/pwrite64: SIGXFSZ/EFBIG)   RLIMIT_DATA    (2)  — max
//! data segment size        ENFORCED  (sys_brk: ENOMEM)   RLIMIT_STACK   (3)  —
//! max stack size               ENFORCED  (exec/mmap)   RLIMIT_CORE    (4)  —
//! max core file size           ENFORCED  (mm/core_dump.rs: write gated; 0 = no
//! dump)   RLIMIT_RSS     (5)  — max resident set size        ENFORCED
//! (mm/rss.rs: charge on alloc; hard limit → ENOMEM)   RLIMIT_NPROC   (6)  —
//! max number of processes      ENFORCED  (fork)   RLIMIT_NOFILE  (7)  — max
//! open file descriptors    ENFORCED  (fcntl)   RLIMIT_MEMLOCK (8)  — max
//! locked memory bytes      ENFORCED  (mm/mlock.rs: ENOMEM on mlock/mlockall)
//!   RLIMIT_AS      (9)  — max virtual address space    ENFORCED  (mmap/brk)
//!   RLIMIT_LOCKS   (10) — max file locks               ENFORCED  (fs/flock.rs:
//! ENOLCK)   RLIMIT_SIGPENDING (11) — max pending signals       ENFORCED
//! (kill/tgkill/tkill)   RLIMIT_MSGQUEUE   (12) — max POSIX MQ bytes
//! ENFORCED  (ipc/mq.rs: ENOMEM on mq_open/mq_send)   RLIMIT_NICE    (13) —
//! nice ceiling                 ENFORCED  (syscall/sched.rs: clamped on
//! setpriority/sched_setattr)   RLIMIT_RTPRIO  (14) — RT priority ceiling
//! ENFORCED  (syscall/sched.rs: EPERM if exceeded)   RLIMIT_RTTIME  (15) — max
//! RT CPU time (µs)         ENFORCED  (interrupts/scheduler: SIGXCPU/SIGKILL;
//!                                                                  reset on
//! voluntary block via block_current();                                        
//! reset on sched policy change)

pub const RLIMIT_CPU: usize = 0;
pub const RLIMIT_FSIZE: usize = 1;
pub const RLIMIT_DATA: usize = 2;
pub const RLIMIT_STACK: usize = 3;
pub const RLIMIT_CORE: usize = 4;
pub const RLIMIT_RSS: usize = 5;
pub const RLIMIT_NPROC: usize = 6;
pub const RLIMIT_NOFILE: usize = 7;
pub const RLIMIT_MEMLOCK: usize = 8;
pub const RLIMIT_AS: usize = 9;
pub const RLIMIT_LOCKS: usize = 10;
pub const RLIMIT_SIGPENDING: usize = 11;
pub const RLIMIT_MSGQUEUE: usize = 12;
pub const RLIMIT_NICE: usize = 13;
pub const RLIMIT_RTPRIO: usize = 14;
pub const RLIMIT_RTTIME: usize = 15;
pub const RLIMIT_NLIMITS: usize = 16;

/// Sentinel: unlimited (RLIM_INFINITY).
pub const RLIM_INFINITY: u64 = u64::MAX;

const DEFAULTS: [(u64, u64); RLIMIT_NLIMITS] = [
    (RLIM_INFINITY, RLIM_INFINITY),   // CPU
    (RLIM_INFINITY, RLIM_INFINITY),   // FSIZE
    (RLIM_INFINITY, RLIM_INFINITY),   // DATA
    (8 * 1024 * 1024, RLIM_INFINITY), // STACK: 8 MiB soft
    (0, RLIM_INFINITY),               // CORE: 0 = disabled by default
    (RLIM_INFINITY, RLIM_INFINITY),   // RSS
    (65536, 65536),                   // NPROC
    (1024, 4096),                     // NOFILE
    (65536, 65536),                   // MEMLOCK: 64 KiB
    (RLIM_INFINITY, RLIM_INFINITY),   // AS
    (RLIM_INFINITY, RLIM_INFINITY),   // LOCKS
    (7823, 7823),                     // SIGPENDING
    (819200, 819200),                 // MSGQUEUE: 800 KiB
    (0, 0),                           // NICE: 0 = only nice >= 20 without CAP_SYS_NICE
    (0, 0),                           // RTPRIO: 0 = no RT without CAP_SYS_NICE
    (RLIM_INFINITY, RLIM_INFINITY),   // RTTIME: unlimited
];

#[derive(Clone, Debug)]
pub struct RlimitSet {
    limits: [(u64, u64); RLIMIT_NLIMITS],
}

impl Default for RlimitSet {
    fn default() -> Self {
        RlimitSet { limits: DEFAULTS }
    }
}

impl RlimitSet {
    pub fn get(&self, resource: usize) -> (u64, u64) {
        if resource < RLIMIT_NLIMITS {
            self.limits[resource]
        } else {
            (RLIM_INFINITY, RLIM_INFINITY)
        }
    }

    pub fn set(&mut self, resource: usize, soft: u64, hard: u64) -> isize {
        if resource >= RLIMIT_NLIMITS {
            return -22;
        }
        if soft > hard {
            return -22;
        }
        self.limits[resource] = (soft, hard);
        0
    }

    #[inline]
    pub fn exceeds_nofile(&self, current_open: usize) -> bool {
        let (soft, _) = self.limits[RLIMIT_NOFILE];
        soft != RLIM_INFINITY && current_open as u64 >= soft
    }

    #[inline]
    pub fn exceeds_as(&self, current_as: usize, extra_bytes: usize) -> bool {
        let (soft, _) = self.limits[RLIMIT_AS];
        if soft == RLIM_INFINITY {
            return false;
        }
        (current_as as u64).saturating_add(extra_bytes as u64) > soft
    }

    #[inline]
    pub fn exceeds_stack(&self, requested_bytes: usize) -> bool {
        let (soft, _) = self.limits[RLIMIT_STACK];
        if soft == RLIM_INFINITY {
            return false;
        }
        requested_bytes as u64 > soft
    }

    #[inline]
    pub fn stack_soft(&self) -> u64 {
        self.limits[RLIMIT_STACK].0
    }

    /// Returns true if `new_brk` would push the heap past the soft DATA limit.
    /// `brk_base` is the bottom of the heap (set at exec time).
    #[inline]
    pub fn exceeds_data(&self, brk_base: usize, new_brk: usize) -> bool {
        let (soft, _) = self.limits[RLIMIT_DATA];
        if soft == RLIM_INFINITY {
            return false;
        }
        let heap_size = new_brk.saturating_sub(brk_base) as u64;
        heap_size > soft
    }
}

pub fn getrlimit_for(pid: usize, resource: usize) -> (u64, u64) {
    if pid == 0 {
        let me = crate::proc::scheduler::current_pid_usize();
        crate::proc::scheduler::with_proc(me, |p| p.rlimits.get(resource))
            .unwrap_or((RLIM_INFINITY, RLIM_INFINITY))
    } else {
        crate::proc::scheduler::with_proc(pid, |p| p.rlimits.get(resource))
            .unwrap_or((RLIM_INFINITY, RLIM_INFINITY))
    }
}

pub fn setrlimit_for(pid: usize, resource: usize, soft: u64, hard: u64) -> isize {
    let target = if pid == 0 {
        crate::proc::scheduler::current_pid_usize()
    } else {
        pid
    };
    crate::proc::scheduler::with_proc_mut(target, |p, _pl| p.rlimits.set(resource, soft, hard))
        .unwrap_or(-3)
}
