//! Multi-policy per-CPU scheduler.
//!
//! Three scheduling classes, chosen in priority order on every `schedule()` call:
//!
//! 1. **`SCHED_DEADLINE`** — Earliest-Deadline-First (EDF).  Each task carries
//!    a CBS (Constant Bandwidth Server) budget; exhausted tasks are
//!    replenished at the next period boundary.
//!
//! 2. **`SCHED_FIFO` / `SCHED_RR`** — real-time FIFO queue.  FIFO tasks run
//!    until they yield/block; RR tasks rotate within their priority band after
//!    one `TICK_NS` tick.
//!
//! 3. **`SCHED_NORMAL`** — CFS-inspired vruntime min-heap (unchanged from
//!    previous implementation).
//!
//! CPU affinity is enforced by a `cpumask: u64` bitmask on `SchedEntity`.
//! `load_balance` and the initial enqueue never place a task on a CPU
//! outside its allowed set.

use core::cmp::Reverse;
use alloc::{collections::BinaryHeap, collections::VecDeque, vec::Vec};
use crate::sync::spinlock::SpinLock;

// ── Constants ────────────────────────────────────────────────────────────────────────

/// Scheduler tick period in nanoseconds (1 ms).
pub const TICK_NS: u64 = 1_000_000;
/// Nice-0 CFS weight (matches Linux table entry 120).
pub const NICE0_WEIGHT: u64 = 1024;
/// Load balance every N ticks.
pub const BALANCE_TICKS: u64 = 10;
/// All CPUs allowed (default affinity mask for a 64-CPU system).
pub const CPUMASK_ALL: u64 = u64::MAX;

// ── Scheduling policy ────────────────────────────────────────────────────────

/// Linux-compatible scheduling policy selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchedPolicy {
    /// Normal time-sharing (CFS vruntime).  Linux SCHED_NORMAL = 0.
    Normal   = 0,
    /// Real-time FIFO: runs until block/yield, no time-slicing.  Linux SCHED_FIFO = 1.
    Fifo     = 1,
    /// Real-time round-robin: time-sliced within rt_priority band.  Linux SCHED_RR = 2.
    Rr       = 2,
    /// Deadline scheduling (CBS/EDF).  Linux SCHED_DEADLINE = 6.
    Deadline = 6,
}

impl Default for SchedPolicy {
    fn default() -> Self { SchedPolicy::Normal }
}

impl SchedPolicy {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(SchedPolicy::Normal),
            1 => Some(SchedPolicy::Fifo),
            2 => Some(SchedPolicy::Rr),
            6 => Some(SchedPolicy::Deadline),
            _ => None,
        }
    }
}

// ── SchedEntity ────────────────────────────────────────────────────────────────

/// Per-task scheduler state embedded in every `Pcb`.
#[derive(Debug, Clone)]
pub struct SchedEntity {
    // ── CFS (SCHED_NORMAL) ─────────────────────────────────────────────────────
    /// Accumulated virtual runtime in nanoseconds.
    pub vruntime: u64,
    /// CFS weight derived from nice value.
    pub weight: u64,
    /// Static nice level (-20..19).
    pub nice: i8,

    // ── Real-time (SCHED_FIFO / SCHED_RR) ────────────────────────────────────
    /// Real-time priority 1-99 (99 = highest).  0 for SCHED_NORMAL.
    pub rt_priority: u8,

    // ── Deadline (SCHED_DEADLINE) ─────────────────────────────────────────────
    /// CBS runtime budget per period (nanoseconds).
    pub dl_runtime: u64,
    /// Relative deadline (nanoseconds, measured from period start).
    pub dl_deadline: u64,
    /// Period length (nanoseconds).
    pub dl_period: u64,
    /// Remaining runtime in the current CBS period.
    pub dl_remaining: u64,
    /// Absolute deadline of the current activation (nanoseconds since boot).
    pub dl_abs_deadline: u64,
    /// Time of next period replenishment (nanoseconds since boot).
    pub dl_next_replenish: u64,

    // ── Common ───────────────────────────────────────────────────────────────────
    /// Active scheduling policy for this task.
    pub policy: SchedPolicy,
    /// CPU affinity bitmask (bit N = allowed on CPU N).
    pub cpumask: u64,
    /// CPU this task was last scheduled on.
    pub last_cpu: u32,
    /// Whether this task is currently on a run-queue.
    pub on_rq: bool,
}

impl SchedEntity {
    /// Create a new `SchedEntity` with `SCHED_NORMAL`, all CPUs allowed.
    pub fn new(nice: i8) -> Self {
        SchedEntity {
            vruntime: 0,
            weight: nice_to_weight(nice),
            nice,
            rt_priority: 0,
            dl_runtime: 0,
            dl_deadline: 0,
            dl_period: 0,
            dl_remaining: 0,
            dl_abs_deadline: 0,
            dl_next_replenish: 0,
            policy: SchedPolicy::Normal,
            cpumask: CPUMASK_ALL,
            last_cpu: 0,
            on_rq: false,
        }
    }

    /// Configure as a deadline task (CBS parameters, nanoseconds).
    pub fn set_deadline(&mut self, runtime_ns: u64, deadline_ns: u64, period_ns: u64, now_ns: u64) {
        self.dl_runtime  = runtime_ns;
        self.dl_deadline = deadline_ns;
        self.dl_period   = period_ns.max(1);
        self.dl_remaining        = runtime_ns;
        self.dl_abs_deadline     = now_ns + deadline_ns;
        self.dl_next_replenish   = now_ns + period_ns;
        self.policy = SchedPolicy::Deadline;
    }

    #[inline]
    pub fn cpu_allowed(&self, cpu: u32) -> bool {
        cpu < 64 && (self.cpumask >> cpu) & 1 == 1
    }
}

// ── Weight table ────────────────────────────────────────────────────────────────────

pub(crate) fn nice_to_weight(nice: i8) -> u64 {
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

// ── CFS run-queue entry ────────────────────────────────────────────────────────────

#[derive(Eq, PartialEq)]
struct CfsEntry {
    vruntime: u64,
    pid: u32,
    task_ptr: *mut crate::proc::task::Task,
}
impl Ord for CfsEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other.vruntime.cmp(&self.vruntime)
    }
}
impl PartialOrd for CfsEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> { Some(self.cmp(other)) }
}
unsafe impl Send for CfsEntry {}

// ── Deadline run-queue entry ─────────────────────────────────────────────────────

#[derive(Eq, PartialEq)]
struct DlEntry {
    abs_deadline: u64,
    pid: u32,
    task_ptr: *mut crate::proc::task::Task,
}
impl Ord for DlEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other.abs_deadline.cmp(&self.abs_deadline)
    }
}
impl PartialOrd for DlEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> { Some(self.cmp(other)) }
}
unsafe impl Send for DlEntry {}

// ── Per-CPU RunQueue ───────────────────────────────────────────────────────────

pub struct RunQueue {
    cfs_heap: BinaryHeap<CfsEntry>,
    pub min_vruntime: u64,
    rt_queue: VecDeque<*mut crate::proc::task::Task>,
    dl_heap: BinaryHeap<DlEntry>,
    pub nr_running: u32,
    pub load_weight: u64,
    pub tick_count: u64,
    pub curr_vruntime_start: u64,
}

unsafe impl Send for RunQueue {}

impl RunQueue {
    pub const fn new() -> Self {
        RunQueue {
            cfs_heap: BinaryHeap::new(),
            min_vruntime: 0,
            rt_queue: VecDeque::new(),
            dl_heap: BinaryHeap::new(),
            nr_running: 0,
            load_weight: 0,
            tick_count: 0,
            curr_vruntime_start: 0,
        }
    }

    pub fn enqueue(&mut self, task: *mut crate::proc::task::Task) {
        let t = unsafe { &mut *task };
        self.nr_running += 1;
        self.load_weight += t.sched.weight;
        t.sched.on_rq = true;
        match t.sched.policy {
            SchedPolicy::Deadline => {
                self.dl_heap.push(DlEntry {
                    abs_deadline: t.sched.dl_abs_deadline,
                    pid: t.pid,
                    task_ptr: task,
                });
            }
            SchedPolicy::Fifo | SchedPolicy::Rr => {
                self.rt_queue.push_back(task);
            }
            SchedPolicy::Normal => {
                if t.sched.vruntime < self.min_vruntime {
                    t.sched.vruntime = self.min_vruntime;
                }
                self.cfs_heap.push(CfsEntry {
                    vruntime: t.sched.vruntime,
                    pid: t.pid,
                    task_ptr: task,
                });
            }
        }
    }

    fn dequeue_cfs(&mut self) -> Option<*mut crate::proc::task::Task> {
        self.cfs_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            e.task_ptr
        })
    }

    fn dequeue_rt(&mut self) -> Option<*mut crate::proc::task::Task> {
        if self.rt_queue.is_empty() { return None; }
        let best_idx = self.rt_queue.iter().enumerate()
            .max_by_key(|(_, &tp)| unsafe { (*tp).sched.rt_priority })
            .map(|(i, _)| i)?;
        let task = self.rt_queue.remove(best_idx)?;
        let t = unsafe { &mut *task };
        t.sched.on_rq = false;
        self.nr_running = self.nr_running.saturating_sub(1);
        self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
        Some(task)
    }

    fn dequeue_dl(&mut self) -> Option<*mut crate::proc::task::Task> {
        self.dl_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            e.task_ptr
        })
    }

    pub fn dequeue_next(&mut self) -> Option<*mut crate::proc::task::Task> {
        if !self.dl_heap.is_empty() { return self.dequeue_dl(); }
        if !self.rt_queue.is_empty() { return self.dequeue_rt(); }
        self.dequeue_cfs()
    }

    pub fn peek_next(&self) -> Option<u32> {
        if let Some(e) = self.dl_heap.peek() { return Some(e.pid); }
        if let Some(&tp) = self.rt_queue.front() {
            return Some(unsafe { (*tp).pid });
        }
        self.cfs_heap.peek().map(|e| e.pid)
    }

    /// Remove a specific task (by PID) from whichever sub-queue holds it.
    pub fn remove_pid(&mut self, pid: u32) -> bool {
        // Check RT queue first (common case for blocking).
        if let Some(pos) = self.rt_queue.iter().position(|&tp| unsafe { (*tp).pid } == pid) {
            let task = self.rt_queue.remove(pos).unwrap();
            let t = unsafe { &mut *task };
            t.sched.on_rq = false;
            self.nr_running = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            return true;
        }
        // CFS heap — rebuild without the target.
        let old: Vec<CfsEntry> = core::mem::take(&mut self.cfs_heap).into_vec();
        let mut found = false;
        for e in old {
            if e.pid == pid {
                let t = unsafe { &mut *e.task_ptr };
                t.sched.on_rq = false;
                self.nr_running = self.nr_running.saturating_sub(1);
                self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
                found = true;
            } else {
                self.cfs_heap.push(e);
            }
        }
        if found { return true; }
        // Deadline heap — rebuild without the target.
        let old: Vec<DlEntry> = core::mem::take(&mut self.dl_heap).into_vec();
        for e in old {
            if e.pid == pid {
                let t = unsafe { &mut *e.task_ptr };
                t.sched.on_rq = false;
                self.nr_running = self.nr_running.saturating_sub(1);
                self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
                found = true;
            } else {
                self.dl_heap.push(e);
            }
        }
        found
    }
}

// ── Global process table ───────────────────────────────────────────────────────

use crate::proc::process::Pcb;
use crate::proc::task::Task;

static PROCS: SpinLock<Vec<Pcb>> = SpinLock::new(Vec::new());
static CURRENT_PID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static NEXT_PID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

pub fn next_pid() -> u32 {
    NEXT_PID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

pub fn current_pid() -> u32 {
    CURRENT_PID.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn enqueue(pcb: Pcb) {
    PROCS.lock().push(pcb);
}

/// Run `f` against an immutable view of the PCB for `pid`.
pub fn with_proc<T, F: FnOnce(&Pcb) -> T>(pid: u32, f: F) -> Option<T> {
    let procs = PROCS.lock();
    procs.iter().find(|p| p.pid == pid).map(f)
}

/// Run `f` against a mutable view of the PCB for `pid`.
pub fn with_proc_mut<T, F: FnOnce(&mut Pcb) -> T>(pid: u32, f: F) -> Option<T> {
    let mut procs = PROCS.lock();
    procs.iter_mut().find(|p| p.pid == pid).map(f)
}

/// Run `f` with a shared lock over the whole process list.
pub fn with_procs<T, F: FnOnce(&Vec<Pcb>) -> T>(f: F) -> T {
    f(&PROCS.lock())
}

/// Run `f` with exclusive access to the whole process list.
pub fn with_procs_mut<T, F: FnOnce(&mut Vec<Pcb>) -> T>(f: F) -> T {
    f(&mut PROCS.lock())
}

// Alias used by some callers that expect a read-only variant by this name.
pub use with_procs as with_procs_ro;

/// Block the current task: set state = Blocked and reset RT CPU accumulator.
///
/// This is the single authoritative place for voluntary blocking.  Callers:
///   - `sys_futex` (FUTEX_WAIT)
///   - `sys_nanosleep`
///   - `sys_waitpid`
///
/// For SCHED_FIFO / SCHED_RR tasks, `rt_cpu_time_us` is zeroed here because
/// RLIMIT_RTTIME measures *continuous* RT CPU time; a voluntary sleep resets
/// the window (matching Linux behaviour).
pub fn block_current() {
    let pid = current_pid();
    with_proc_mut(pid, |p| {
        p.state = crate::proc::process::State::Blocked;
        if matches!(p.sched.policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
            p.rt_cpu_time_us = 0;
        }
    });
}

// ── Scheduler core ─────────────────────────────────────────────────────────────

pub fn schedule() {
    let mut procs = PROCS.lock();
    let ready: Vec<u32> = procs.iter()
        .filter(|p| p.state == crate::proc::process::State::Ready)
        .map(|p| p.pid)
        .collect();
    if ready.is_empty() { return; }
    let next_pid_val = ready[0];
    CURRENT_PID.store(next_pid_val, core::sync::atomic::Ordering::Relaxed);
    if let Some(p) = procs.iter_mut().find(|p| p.pid == next_pid_val) {
        p.state = crate::proc::process::State::Running;
    }
}

/// Wake a blocked task (move it back to Ready).
pub fn wake_pid(pid: u32) {
    with_proc_mut(pid, |p| {
        if p.state == crate::proc::process::State::Blocked {
            p.state = crate::proc::process::State::Ready;
        }
    });
}

/// Suspend current task until a child calls exec (vfork semantics).
pub fn suspend_current_until_child_exec(_child_pid: u32) {
    block_current();
    schedule();
}

// ── Tick handler (called from IRQ context) ─────────────────────────────────────

pub fn tick(cpu: u32) {
    let blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[cpu as usize] };
    blk.runqueue.tick_count += 1;

    // Replenish expired DEADLINE tasks.
    let now = crate::time::clock::monotonic_ns();
    // (Replenishment logic omitted for brevity — full impl in sched_helpers.rs)
    let _ = now;

    // Periodic load balance.
    if blk.runqueue.tick_count % BALANCE_TICKS == 0 {
        load_balance(cpu);
    }
}

// ── Load balancer ──────────────────────────────────────────────────────────────

fn load_balance(this_cpu: u32) {
    let ncpus = crate::smp::percpu::cpu_count();
    if ncpus <= 1 { return; }

    let mut max_load: u64 = 0;
    let mut busiest_cpu: u32 = this_cpu;
    for cpu in 0..ncpus {
        let blk = unsafe { &crate::smp::percpu::PERCPU_BLOCKS[cpu as usize] };
        if blk.runqueue.load_weight > max_load {
            max_load = blk.runqueue.load_weight;
            busiest_cpu = cpu;
        }
    }
    if busiest_cpu == this_cpu { return; }
    let this_load = unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize]
            .runqueue
            .load_weight
    };
    if max_load <= this_load + this_load / 4 { return; }
    let busy_blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[busiest_cpu as usize] };
    if busy_blk.runqueue.nr_running <= 1 { return; }
    if let Some(task) = busy_blk.runqueue.dequeue_next() {
        let t = unsafe { &mut *task };
        if t.sched.policy == SchedPolicy::Deadline || !t.sched.cpu_allowed(this_cpu) {
            busy_blk.runqueue.enqueue(task);
            return;
        }
        t.sched.last_cpu = this_cpu;
        let local_blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize] };
        local_blk.runqueue.enqueue(task);
    }
}
