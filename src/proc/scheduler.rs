//! CFS-inspired per-CPU scheduler with work-stealing load balancer.
//!
//! Each CPU owns a `RunQueue` — a min-heap keyed by `vruntime` (virtual
//! runtime in nanoseconds, weighted by nice value).  The scheduler picks
//! the task with the smallest `vruntime` to run next (O(log n) enqueue,
//! O(log n) dequeue via `BinaryHeap` with `Reverse`).
//!
//! Load balancing runs every `BALANCE_INTERVAL_MS` ms from the timer
//! interrupt on each CPU.  The busiest CPU with > 1 runnable task donates
//! one task to the most idle CPU.

use core::cmp::Reverse;
use alloc::{collections::BinaryHeap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::sync::spinlock::SpinLock;

/// Scheduler tick period in nanoseconds (1 ms).
pub const TICK_NS: u64 = 1_000_000;
/// Nice-0 weight (matches Linux CFS weight table entry 120).
pub const NICE0_WEIGHT: u64 = 1024;
/// Load balance interval (every N scheduler ticks).
pub const BALANCE_TICKS: u64 = 10;

/// Scheduler entity embedded in every `Task`.
#[derive(Debug, Clone)]
pub struct SchedEntity {
    /// Accumulated virtual runtime in nanoseconds.
    pub vruntime: u64,
    /// Weight derived from nice value (higher nice = lower weight).
    pub weight: u64,
    /// Task priority (static nice level, -20..19).
    pub nice: i8,
    /// CPU this task was last scheduled on.
    pub last_cpu: u32,
    /// Whether this task is currently on a run-queue.
    pub on_rq: bool,
}

impl SchedEntity {
    pub fn new(nice: i8) -> Self {
        SchedEntity {
            vruntime: 0,
            weight: nice_to_weight(nice),
            nice,
            last_cpu: 0,
            on_rq: false,
        }
    }
}

/// Convert nice level to CFS weight (simplified linear approximation).
fn nice_to_weight(nice: i8) -> u64 {
    let n = nice.clamp(-20, 19) as i64;
    // weight = 1024 / 1.25^nice  (simplified integer version)
    // For n in [-20, 19] this gives [88761, 15].
    let base: u64 = 1024;
    if n == 0 { return base; }
    if n > 0 {
        // each nice step reduces weight by ~20%
        let mut w = base;
        for _ in 0..n { w = w * 4 / 5; }
        w.max(1)
    } else {
        let mut w = base;
        for _ in 0..(-n) { w = w * 5 / 4; }
        w
    }
}

/// A task handle stored in the run-queue.  Ordered by vruntime (min-heap).
#[derive(Eq, PartialEq)]
struct RqEntry {
    vruntime: u64,
    pid: u32,
    task_ptr: *mut crate::proc::task::Task,
}

impl Ord for RqEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // BinaryHeap is a max-heap; wrap in Reverse for min-heap.
        other.vruntime.cmp(&self.vruntime)
    }
}
impl PartialOrd for RqEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

unsafe impl Send for RqEntry {}

/// Per-CPU run-queue.
pub struct RunQueue {
    heap: BinaryHeap<RqEntry>,
    /// Minimum vruntime across all tasks on this queue (used to seed new tasks).
    pub min_vruntime: u64,
    /// Count of runnable tasks.
    pub nr_running: u32,
    /// Total weight of all runnable tasks (for load calculation).
    pub load_weight: u64,
    /// Tick counter for triggering load balance.
    pub tick_count: u64,
    /// `vruntime` of the currently running task at the moment it was scheduled.
    pub curr_vruntime_start: u64,
}

impl RunQueue {
    pub const fn new() -> Self {
        RunQueue {
            heap: BinaryHeap::new(),
            min_vruntime: 0,
            nr_running: 0,
            load_weight: 0,
            tick_count: 0,
            curr_vruntime_start: 0,
        }
    }

    /// Enqueue a task.  Seeds `vruntime` to `min_vruntime` if it would
    /// otherwise be unfairly behind.
    pub fn enqueue(&mut self, task: *mut crate::proc::task::Task) {
        let t = unsafe { &mut *task };
        if t.sched.vruntime < self.min_vruntime {
            t.sched.vruntime = self.min_vruntime;
        }
        self.load_weight += t.sched.weight;
        self.nr_running += 1;
        t.sched.on_rq = true;
        self.heap.push(RqEntry {
            vruntime: t.sched.vruntime,
            pid: t.pid,
            task_ptr: task,
        });
    }

    /// Pick the task with the lowest vruntime without removing it.
    pub fn peek_next(&self) -> Option<*mut crate::proc::task::Task> {
        self.heap.peek().map(|e| e.task_ptr)
    }

    /// Dequeue and return the task with the lowest vruntime.
    pub fn dequeue_next(&mut self) -> Option<*mut crate::proc::task::Task> {
        self.heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running -= 1;
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            e.task_ptr
        })
    }

    /// Update the currently running task's vruntime by `delta_ns` actual time.
    /// `delta_vruntime = delta_ns * NICE0_WEIGHT / task.weight`
    pub fn update_curr(&mut self, curr: *mut crate::proc::task::Task, delta_ns: u64) {
        let t = unsafe { &mut *curr };
        let delta_vrt = delta_ns * NICE0_WEIGHT / t.sched.weight.max(1);
        t.sched.vruntime = t.sched.vruntime.wrapping_add(delta_vrt);
        // Advance min_vruntime.
        if t.sched.vruntime > self.min_vruntime {
            self.min_vruntime = t.sched.vruntime;
        }
    }
}

impl Default for RunQueue {
    fn default() -> Self { Self::new() }
}

// ───── Load balancer ──────────────────────────────────────────────────────────

/// Called from the timer interrupt on each CPU every `BALANCE_TICKS` ticks.
/// Migrates one task from the busiest CPU to this CPU if the load imbalance
/// exceeds 25%.
pub fn load_balance(this_cpu: u32) {
    let n = crate::smp::num_online_cpus();
    if n <= 1 { return; }

    // Find the busiest CPU.
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

    let this_blk  = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize] };
    let their_load = max_load;
    let our_load   = this_blk.runqueue.load_weight;

    // Only migrate if busiest has > 25% more load.
    if their_load <= our_load + our_load / 4 { return; }

    let busy_blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[busiest_cpu as usize] };
    if busy_blk.runqueue.nr_running <= 1 { return; }

    // Pull one task.
    if let Some(task) = busy_blk.runqueue.dequeue_next() {
        let t = unsafe { &mut *task };
        t.sched.last_cpu = this_cpu;
        this_blk.runqueue.enqueue(task);
        log::trace!("sched: migrated pid={} cpu{}→cpu{}", t.pid, busiest_cpu, this_cpu);
        // Send reschedule IPI to ourselves (already on this CPU, no-op).
    }
}

/// Idle loop entered by each AP after bringup.  Runs the scheduler.
pub fn ap_idle() -> ! {
    let cpu_id = crate::smp::percpu::current_cpu_id();
    log::info!("sched: CPU {} idle loop started", cpu_id);
    loop {
        schedule();
        // If nothing to run, halt until the next interrupt.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("sti; hlt", options(nostack, preserves_flags));
            #[cfg(target_arch = "riscv64")]
            core::arch::asm!("wfi", options(nostack));
        }
    }
}

/// Pick and context-switch to the next runnable task on this CPU.
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

/// Arch-level context switch: save `prev` registers, restore `next` registers.
/// On x86_64 this saves/restores the callee-saved registers and RSP.
#[naked]
unsafe extern "C" fn context_switch(
    prev: *mut crate::proc::task::Task,
    next: *mut crate::proc::task::Task,
) {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        // Save callee-saved regs of `prev` onto its kernel stack.
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Save RSP into prev->kernel_rsp (offset must match Task layout).
        "mov [rdi + {rsp_off}], rsp",
        // Load RSP from next->kernel_rsp.
        "mov rsp, [rsi + {rsp_off}]",
        // Restore callee-saved regs of `next`.
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
        rsp_off = const core::mem::offset_of!(crate::proc::task::Task, kernel_rsp),
        options(noreturn)
    );
    #[cfg(target_arch = "riscv64")]
    core::arch::asm!(
        // Save callee-saved regs of `prev`.
        "sd ra,  0(a0)",
        "sd sp,  8(a0)",
        "sd s0,  16(a0)",
        "sd s1,  24(a0)",
        "sd s2,  32(a0)",
        "sd s3,  40(a0)",
        "sd s4,  48(a0)",
        "sd s5,  56(a0)",
        "sd s6,  64(a0)",
        "sd s7,  72(a0)",
        "sd s8,  80(a0)",
        "sd s9,  88(a0)",
        "sd s10, 96(a0)",
        "sd s11, 104(a0)",
        // Restore callee-saved regs of `next`.
        "ld ra,  0(a1)",
        "ld sp,  8(a1)",
        "ld s0,  16(a1)",
        "ld s1,  24(a1)",
        "ld s2,  32(a1)",
        "ld s3,  40(a1)",
        "ld s4,  48(a1)",
        "ld s5,  56(a1)",
        "ld s6,  64(a1)",
        "ld s7,  72(a1)",
        "ld s8,  80(a1)",
        "ld s9,  88(a1)",
        "ld s10, 96(a1)",
        "ld s11, 104(a1)",
        "ret",
        options(noreturn)
    );
}
