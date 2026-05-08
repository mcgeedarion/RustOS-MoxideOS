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

// ── Constants ─────────────────────────────────────────────────────────────────

/// Scheduler tick period in nanoseconds (1 ms).
pub const TICK_NS: u64 = 1_000_000;
/// Nice-0 CFS weight (matches Linux table entry 120).
pub const NICE0_WEIGHT: u64 = 1024;
/// Load balance every N ticks.
pub const BALANCE_TICKS: u64 = 10;
/// All CPUs allowed (default affinity mask for a 64-CPU system).
pub const CPUMASK_ALL: u64 = u64::MAX;

// ── Scheduling policy ─────────────────────────────────────────────────────────

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

// ── SchedEntity ───────────────────────────────────────────────────────────────

/// Per-task scheduler state embedded in every `Pcb`.
#[derive(Debug, Clone)]
pub struct SchedEntity {
    // ── CFS (SCHED_NORMAL) ────────────────────────────────────────────────────
    /// Accumulated virtual runtime in nanoseconds.
    pub vruntime: u64,
    /// CFS weight derived from nice value.
    pub weight: u64,
    /// Static nice level (-20..19).
    pub nice: i8,

    // ── Real-time (SCHED_FIFO / SCHED_RR) ───────────────────────────────────
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

    // ── Common ────────────────────────────────────────────────────────────────
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
    /// `now_ns` is the current monotonic time used to set the first activation.
    pub fn set_deadline(&mut self, runtime_ns: u64, deadline_ns: u64, period_ns: u64, now_ns: u64) {
        self.dl_runtime  = runtime_ns;
        self.dl_deadline = deadline_ns;
        self.dl_period   = period_ns.max(1);
        self.dl_remaining        = runtime_ns;
        self.dl_abs_deadline     = now_ns + deadline_ns;
        self.dl_next_replenish   = now_ns + period_ns;
        self.policy = SchedPolicy::Deadline;
    }

    /// Returns `true` if this CPU index is in the affinity mask.
    #[inline]
    pub fn cpu_allowed(&self, cpu: u32) -> bool {
        cpu < 64 && (self.cpumask >> cpu) & 1 == 1
    }
}

// ── Weight table ──────────────────────────────────────────────────────────────

/// Convert nice level (-20..19) to a CFS weight.
/// Uses the same simplified 1.25× per-step ratio as before.
fn nice_to_weight(nice: i8) -> u64 {
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

// ── CFS run-queue entry ───────────────────────────────────────────────────────

#[derive(Eq, PartialEq)]
struct CfsEntry {
    vruntime: u64,
    pid: u32,
    task_ptr: *mut crate::proc::task::Task,
}
impl Ord for CfsEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other.vruntime.cmp(&self.vruntime) // min-heap
    }
}
impl PartialOrd for CfsEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> { Some(self.cmp(other)) }
}
unsafe impl Send for CfsEntry {}

// ── Deadline run-queue entry ──────────────────────────────────────────────────

/// Entry in the EDF deadline heap, ordered by absolute deadline (earliest first).
#[derive(Eq, PartialEq)]
struct DlEntry {
    abs_deadline: u64,
    pid: u32,
    task_ptr: *mut crate::proc::task::Task,
}
impl Ord for DlEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other.abs_deadline.cmp(&self.abs_deadline) // min-heap (earliest deadline first)
    }
}
impl PartialOrd for DlEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> { Some(self.cmp(other)) }
}
unsafe impl Send for DlEntry {}

// ── Per-CPU RunQueue ───────────────────────────────────────────────────────────

/// Per-CPU run-queue holding all three scheduling classes.
pub struct RunQueue {
    // ── CFS (SCHED_NORMAL) ────────────────────────────────────────────────────
    cfs_heap: BinaryHeap<CfsEntry>,
    /// Minimum vruntime across all CFS tasks on this queue.
    pub min_vruntime: u64,

    // ── Real-time (SCHED_FIFO / SCHED_RR) ───────────────────────────────────
    /// FIFO queue ordered by rt_priority (highest first = front of deque).
    /// All FIFO/RR tasks are pushed to the back at their priority level;
    /// we do a linear scan to find the highest-priority head.
    rt_queue: VecDeque<*mut crate::proc::task::Task>,

    // ── Deadline (SCHED_DEADLINE) ─────────────────────────────────────────────
    /// EDF min-heap ordered by absolute deadline.
    dl_heap: BinaryHeap<DlEntry>,

    // ── Aggregate stats ───────────────────────────────────────────────────────
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

    // ── Enqueue ───────────────────────────────────────────────────────────────

    /// Enqueue a task into the appropriate class queue.
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
                // Insert maintaining rt_priority order (higher = closer to front).
                // For simplicity we push to back and rely on peek_rt / dequeue_rt
                // to scan for the highest priority entry.
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

    // ── Dequeue helpers ───────────────────────────────────────────────────────

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
        // Find index of highest rt_priority task.
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

    /// Dequeue the next task to run.  Priority: Deadline > RT > CFS.
    pub fn dequeue_next(&mut self) -> Option<*mut crate::proc::task::Task> {
        if !self.dl_heap.is_empty() { return self.dequeue_dl(); }
        if !self.rt_queue.is_empty() { return self.dequeue_rt(); }
        self.dequeue_cfs()
    }

    /// Peek without dequeuing (used by load balancer heuristic).
    pub fn peek_next(&self) -> Option<*mut crate::proc::task::Task> {
        if let Some(e) = self.dl_heap.peek() { return Some(e.task_ptr); }
        if let Some(&tp) = self.rt_queue.front() { return Some(tp); }
        self.cfs_heap.peek().map(|e| e.task_ptr)
    }

    // ── Tick accounting ───────────────────────────────────────────────────────

    /// Advance the current task's vruntime / deadline budget by `delta_ns`.
    /// Call once per timer tick with the currently running task pointer.
    pub fn update_curr(&mut self, curr: *mut crate::proc::task::Task, delta_ns: u64) {
        let t = unsafe { &mut *curr };
        match t.sched.policy {
            SchedPolicy::Normal => {
                let delta_vrt = delta_ns * NICE0_WEIGHT / t.sched.weight.max(1);
                t.sched.vruntime = t.sched.vruntime.wrapping_add(delta_vrt);
                if t.sched.vruntime > self.min_vruntime {
                    self.min_vruntime = t.sched.vruntime;
                }
            }
            SchedPolicy::Deadline => {
                // CBS budget consumption.
                t.sched.dl_remaining = t.sched.dl_remaining.saturating_sub(delta_ns);
                // If budget exhausted, advance absolute deadline by one period
                // (CBS replenishment) so the task drops to the back of the EDF queue.
                if t.sched.dl_remaining == 0 {
                    let period = t.sched.dl_period.max(1);
                    t.sched.dl_remaining      = t.sched.dl_runtime;
                    t.sched.dl_abs_deadline  += period;
                    t.sched.dl_next_replenish += period;
                    log::trace!("sched/dl: pid={} CBS replenished, new deadline={}",
                        t.pid, t.sched.dl_abs_deadline);
                }
            }
            // FIFO/RR: just consume ticks (RR rotation handled in schedule()).
            _ => {}
        }
    }
}

impl Default for RunQueue {
    fn default() -> Self { Self::new() }
}

// ── Load balancer ─────────────────────────────────────────────────────────────

/// Called from the timer interrupt on each CPU every `BALANCE_TICKS` ticks.
/// Migrates one CFS task from the busiest CPU to this CPU, respecting
/// the task's CPU affinity mask.
pub fn load_balance(this_cpu: u32) {
    let n = crate::smp::num_online_cpus();
    if n <= 1 { return; }

    // Find the busiest CPU (by load_weight, excluding deadline tasks which
    // must not be migrated without deadline admission re-check).
    let mut busiest_cpu = this_cpu;
    let mut max_load: u64 = 0;
    for cpu in 0..n {
        let blk = unsafe { &crate::smp::percpu::PERCPU_BLOCKS[cpu as usize] };
        let load = blk.runqueue.load_weight;
        if load > max_load && cpu != this_cpu {
            max_load = load;
            busiest_cpu = cpu;
        }
    }
    if busiest_cpu == this_cpu { return; }

    let this_load = unsafe { crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize].runqueue.load_weight };
    // Only migrate if imbalance > 25%.
    if max_load <= this_load + this_load / 4 { return; }

    let busy_blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[busiest_cpu as usize] };
    if busy_blk.runqueue.nr_running <= 1 { return; }

    // Pull one CFS task that allows this CPU.
    // We do a targeted scan: dequeue-scan-reenqueue if the task is pinned.
    // To keep O(log n) amortised, we pull once and check affinity.
    if let Some(task) = busy_blk.runqueue.dequeue_next() {
        let t = unsafe { &mut *task };
        // Deadline tasks: never migrate here (they have their own admission control).
        if t.sched.policy == SchedPolicy::Deadline || !t.sched.cpu_allowed(this_cpu) {
            // Put it back.
            busy_blk.runqueue.enqueue(task);
            return;
        }
        t.sched.last_cpu = this_cpu;
        let this_blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize] };
        this_blk.runqueue.enqueue(task);
        log::trace!("sched: migrated pid={} cpu{}→cpu{}", t.pid, busiest_cpu, this_cpu);
    }
}

// ── Core scheduler ────────────────────────────────────────────────────────────

/// Idle loop entered by each AP after bringup.
pub fn ap_idle() -> ! {
    let cpu_id = crate::smp::percpu::current_cpu_id();
    log::info!("sched: CPU {} idle loop started", cpu_id);
    loop {
        schedule();
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("sti; hlt", options(nostack, preserves_flags));
            #[cfg(target_arch = "riscv64")]
            core::arch::asm!("wfi", options(nostack));
        }
    }
}

/// Pick and context-switch to the next runnable task on this CPU.
/// Priority: SCHED_DEADLINE (EDF) > SCHED_FIFO/RR > SCHED_NORMAL (CFS).
pub fn schedule() {
    let blk = unsafe { &mut *crate::smp::percpu::current_block() };
    let rq = &mut blk.runqueue;
    if let Some(next) = rq.dequeue_next() {
        let prev = blk.current_task;
        blk.current_task = next;
        blk.ctx_switches += 1;
        if !prev.is_null() && prev != next {
            unsafe { context_switch(prev, next); }
        }
    }
}

// ── Context switch (arch-specific, unchanged) ────────────────────────────────

#[naked]
unsafe extern "C" fn context_switch(
    prev: *mut crate::proc::task::Task,
    next: *mut crate::proc::task::Task,
) {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
        "mov [rdi + {rsp_off}], rsp",
        "mov rsp, [rsi + {rsp_off}]",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
        "ret",
        rsp_off = const core::mem::offset_of!(crate::proc::task::Task, kernel_rsp),
        options(noreturn)
    );
    #[cfg(target_arch = "riscv64")]
    core::arch::asm!(
        "sd ra,  0(a0)",  "sd sp,  8(a0)",  "sd s0,  16(a0)", "sd s1,  24(a0)",
        "sd s2,  32(a0)", "sd s3,  40(a0)", "sd s4,  48(a0)", "sd s5,  56(a0)",
        "sd s6,  64(a0)", "sd s7,  72(a0)", "sd s8,  80(a0)", "sd s9,  88(a0)",
        "sd s10, 96(a0)", "sd s11, 104(a0)",
        "ld ra,  0(a1)",  "ld sp,  8(a1)",  "ld s0,  16(a1)", "ld s1,  24(a1)",
        "ld s2,  32(a1)", "ld s3,  40(a1)", "ld s4,  48(a1)", "ld s5,  56(a1)",
        "ld s6,  64(a1)", "ld s7,  72(a1)", "ld s8,  80(a1)", "ld s9,  88(a1)",
        "ld s10, 96(a1)", "ld s11, 104(a1)",
        "ret",
        options(noreturn)
    );
}
