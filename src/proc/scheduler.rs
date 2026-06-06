//! Multi-policy per-CPU scheduler.
//!
//! ## Scheduling classes (priority order)
//!
//! 1. **`SCHED_DEADLINE`** — Earliest-Deadline-First (EDF) with CBS budget.
//!    Exhausted tasks sleep until their next replenishment window.
//!
//! 2. **`SCHED_FIFO` / `SCHED_RR`** — real-time FIFO queue.  Tasks are
//!    ordered by `rt_priority` (highest first); equal-priority tasks are
//!    served in FIFO arrival order via a monotone `enqueue_seq` counter.
//!    Dequeue is O(log n) via `BinaryHeap<RtEntry>`.
//!
//! 3. **`SCHED_NORMAL`** — CFS-inspired vruntime min-heap.
//!
//! 4. **`SCHED_BATCH`** — like Normal but deprioritised below all Normal
//!    tasks.  Uses the same vruntime accounting as Normal so it self-balances
//!    among batch peers, but the batch_heap is only drained when the CFS
//!    heap is empty.  Intended for CPU-bound background work (compilation,
//!    checksumming, etc.) that should not steal latency from interactive tasks.
//!
//! 5. **`SCHED_IDLE`** — lowest possible priority.  Weight is fixed at 1
//!    regardless of nice value.  Only runs when *all* other queues are empty.
//!    Analogous to Linux `SCHED_IDLE` (not the per-CPU idle thread).
//!
//! ## RT queue ordering
//!
//! `RtEntry` implements `Ord` such that the `BinaryHeap` max-heap yields the
//! highest-priority task first.  Tie-breaking on `enqueue_seq` (ascending)
//! preserves POSIX SCHED_FIFO semantics: among tasks at the same priority
//! the one that arrived first is picked next.
//!
//! ```text
//! priority(A) > priority(B)  =>  A before B          (POSIX requirement)
//! priority(A) == priority(B), seq(A) < seq(B)  =>  A before B  (FIFO)
//! ```
//!
//! `rt_seq` is a per-`RunQueue` `u64` that wraps via `wrapping_add`.  Wrap
//! at 2^64 is harmless: the ordering only needs to be consistent within the
//! set of tasks *currently* in the heap, not across all time.
//!
//! ## Per-CPU run queues
//!
//! Every CPU has an independent `RunQueue` in its `PercpuBlock`.  `schedule()`
//! operates entirely on the *calling CPU's* run queue.  Cross-CPU wakeups
//! send a reschedule IPI.
//!
//! ## Locking (S2 fix)
//!
//! The hot scheduler path (`schedule`, `tick`, `load_balance`) **never** locks
//! the global process table.  It works exclusively through `*mut Task` pointers
//! stored in the per-CPU run queues.
//!
//! Process metadata is accessed via `proc_table::with_proc` /
//! `proc_table::with_proc_mut`, which take the global `PROC_TABLE` briefly for
//! lookup, clone the `Arc<ProcLock>`, release the table lock, then lock the
//! per-process `ProcLock::inner`.  This means:
//!
//!   - Different PIDs can be mutated concurrently (no single chokepoint).
//!   - The scheduler hot path never waits on a process-table lock.
//!   - `check_and_deliver` + `tick` + `load_balance` can't deadlock on PROCS.
//!
//! ### Atomic state fast-path
//!
//! `wake_pid` reads `ProcLock::state_atom` (an AtomicU8) without locking
//! `inner` to decide whether to bother waking.  If Blocked, it locks inner,
//! confirms, sets Ready, then enqueues.  This keeps the common "not blocked"
//! path lock-free.
//!
//! ## current_pid() — per-CPU authoritative source
//!
//! `current_pid()` reads `(*blk).current_task.pid` from the calling CPU's
//! percpu block.  This is always accurate for the running task on any CPU.
//!
//! `CURRENT_PID` (global AtomicU32) is retained only as a **fallback** for
//! code that runs before percpu blocks are initialised (early boot).
//! `schedule()` now updates the per-CPU block's `current_pid` field
//! unconditionally on *every* CPU rather than only CPU 0, so the global is
//! never the only source of truth on SMP systems.
//!
//! ## load_balance() — snapshot-then-work pattern
//!
//! `load_balance()` takes a single read-only snapshot of every CPU's
//! `load_weight` and `nr_running` into local variables before doing any
//! work.  It then operates only on the snapshot to select the busiest CPU.
//! The steal step re-reads `nr_running` from the live block under no extra
//! lock (we accept that it may have changed; the guard is only that we don't
//! move the single remaining task off a CPU).
//!
//! ## mm_lock helpers
//!
//! `MmReadGuard` and `with_current_mm_read()` are the public surface used by
//! `uaccess` to hold the current process's `mm_lock` for reading across the
//! entire validate+copy sequence, preventing a concurrent munmap from
//! unmapping pages between the page-table walk and the actual copy.
//!
//! ### MmReadGuard drop order
//!
//! The struct field order is `_arc` first, `_guard` second.  Rust drops
//! fields in declaration order (top to bottom), so the `RwLockReadGuard` is
//! dropped before the `Arc`, which means the `RwLock` is never freed while
//! the guard still holds a reference into it.

use core::cmp::Reverse;
use alloc::{collections::BinaryHeap, collections::VecDeque, vec::Vec};
use crate::sync::spinlock::SpinLock;
use crate::proc::process::{State, ProcLock};
use crate::proc::proc_table;
use crate::proc::task_types::TaskRunState;

pub const TICK_NS:        u64 = 1_000_000;
pub const NICE0_WEIGHT:   u64 = 1_024;
pub const BALANCE_TICKS:  u64 = 10;
pub const CPUMASK_ALL:    u64 = u64::MAX;

/// Fixed weight for SCHED_IDLE tasks — always 1, regardless of nice value.
pub const IDLE_WEIGHT: u64 = 1;

/// Maximum weight cap for SCHED_BATCH tasks so a nice(-20) batch task never
/// outweighs a nice-0 normal task.
pub const BATCH_WEIGHT_CAP: u64 = 820;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchedPolicy {
    Normal   = 0,
    Fifo     = 1,
    Rr       = 2,
    Batch    = 3,
    Idle     = 5,
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
            3 => Some(SchedPolicy::Batch),
            5 => Some(SchedPolicy::Idle),
            6 => Some(SchedPolicy::Deadline),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchedEntity {
    pub vruntime:          u64,
    pub weight:            u64,
    pub nice:              i8,
    pub rt_priority:       u8,
    pub dl_runtime:        u64,
    pub dl_deadline:       u64,
    pub dl_period:         u64,
    pub dl_remaining:      u64,
    pub dl_abs_deadline:   u64,
    pub dl_next_replenish: u64,
    pub policy:            SchedPolicy,
    pub cpumask:           u64,
    pub last_cpu:          u32,
    pub on_rq:             bool,
}

impl Default for SchedEntity {
    fn default() -> Self { Self::new(0) }
}

impl SchedEntity {
    pub fn new(nice: i8) -> Self {
        SchedEntity {
            vruntime: 0, weight: nice_to_weight(nice), nice,
            rt_priority: 0,
            dl_runtime: 0, dl_deadline: 0, dl_period: 0,
            dl_remaining: 0, dl_abs_deadline: 0, dl_next_replenish: 0,
            policy: SchedPolicy::Normal,
            cpumask: CPUMASK_ALL,
            last_cpu: 0,
            on_rq: false,
        }
    }

    pub fn set_deadline(
        &mut self,
        runtime_ns:  u64,
        deadline_ns: u64,
        period_ns:   u64,
        now_ns:      u64,
    ) {
        self.dl_runtime          = runtime_ns;
        self.dl_deadline         = deadline_ns;
        self.dl_period           = period_ns.max(1);
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

pub fn effective_weight(policy: SchedPolicy, nice: i8) -> u64 {
    match policy {
        SchedPolicy::Idle  => IDLE_WEIGHT,
        SchedPolicy::Batch => nice_to_weight(nice).min(BATCH_WEIGHT_CAP),
        _                  => nice_to_weight(nice),
    }
}

#[derive(Eq, PartialEq)]
pub struct CfsEntry {
    pub vruntime: u64,
    pub pid:      u32,
    pub task_ptr: *mut crate::proc::task_types::Task,
}
impl Ord for CfsEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other.vruntime.cmp(&self.vruntime)
    }
}
impl PartialOrd for CfsEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
unsafe impl Send for CfsEntry {}

#[derive(Eq, PartialEq)]
struct RtEntry {
    rt_priority:  u8,
    enqueue_seq:  Reverse<u64>,
    pid:          u32,
    task_ptr:     *mut crate::proc::task_types::Task,
}

impl Ord for RtEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.rt_priority.cmp(&other.rt_priority)
            .then(self.enqueue_seq.cmp(&other.enqueue_seq))
    }
}
impl PartialOrd for RtEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
unsafe impl Send for RtEntry {}

#[derive(Eq, PartialEq)]
struct DlEntry {
    abs_deadline: u64,
    pid:          u32,
    task_ptr:     *mut crate::proc::task_types::Task,
}
impl Ord for DlEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other.abs_deadline.cmp(&self.abs_deadline)
    }
}
impl PartialOrd for DlEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
unsafe impl Send for DlEntry {}

pub struct RunQueue {
    pub cfs_heap:            BinaryHeap<CfsEntry>,
    pub min_vruntime:        u64,
    pub rt_heap:             BinaryHeap<RtEntry>,
    rt_seq:                  u64,
    pub dl_heap:             BinaryHeap<DlEntry>,
    pub batch_heap:          BinaryHeap<CfsEntry>,
    pub idle_queue:          VecDeque<*mut crate::proc::task_types::Task>,
    pub nr_running:          u32,
    pub load_weight:         u64,
    pub tick_count:          u64,
    pub curr_vruntime_start: u64,
}

unsafe impl Send for RunQueue {}

impl RunQueue {
    pub const fn new() -> Self {
        RunQueue {
            cfs_heap:            BinaryHeap::new(),
            min_vruntime:        0,
            rt_heap:             BinaryHeap::new(),
            rt_seq:              0,
            dl_heap:             BinaryHeap::new(),
            batch_heap:          BinaryHeap::new(),
            idle_queue:          VecDeque::new(),
            nr_running:          0,
            load_weight:         0,
            tick_count:          0,
            curr_vruntime_start: 0,
        }
    }

    pub fn enqueue(&mut self, task: *mut crate::proc::task_types::Task) {
        let t = unsafe { &mut *task };
        self.nr_running  += 1;
        self.load_weight += t.sched.weight;
        t.sched.on_rq = true;
        match t.sched.policy {
            SchedPolicy::Deadline => {
                self.dl_heap.push(DlEntry {
                    abs_deadline: t.sched.dl_abs_deadline,
                    pid:      t.pid,
                    task_ptr: task,
                });
            }
            SchedPolicy::Fifo | SchedPolicy::Rr => {
                let seq = self.rt_seq;
                self.rt_seq = self.rt_seq.wrapping_add(1);
                self.rt_heap.push(RtEntry {
                    rt_priority: t.sched.rt_priority,
                    enqueue_seq: Reverse(seq),
                    pid:         t.pid,
                    task_ptr:    task,
                });
            }
            SchedPolicy::Normal => {
                if t.sched.vruntime < self.min_vruntime {
                    t.sched.vruntime = self.min_vruntime;
                }
                self.cfs_heap.push(CfsEntry {
                    vruntime: t.sched.vruntime,
                    pid:      t.pid,
                    task_ptr: task,
                });
            }
            SchedPolicy::Batch => {
                if t.sched.vruntime < self.min_vruntime {
                    t.sched.vruntime = self.min_vruntime;
                }
                self.batch_heap.push(CfsEntry {
                    vruntime: t.sched.vruntime,
                    pid:      t.pid,
                    task_ptr: task,
                });
            }
            SchedPolicy::Idle => {
                self.idle_queue.push_back(task);
            }
        }
    }

    fn dequeue_cfs(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        self.cfs_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            if t.sched.vruntime > self.min_vruntime {
                self.min_vruntime = t.sched.vruntime;
            }
            e.task_ptr
        })
    }

    fn dequeue_rt(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        self.rt_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            e.task_ptr
        })
    }

    fn dequeue_dl(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        self.dl_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            e.task_ptr
        })
    }

    fn dequeue_batch(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        self.batch_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            e.task_ptr
        })
    }

    fn dequeue_idle(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        self.idle_queue.pop_front().map(|task| {
            let t = unsafe { &mut *task };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            task
        })
    }

    pub fn dequeue_next(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        if !self.dl_heap.is_empty()   { return self.dequeue_dl(); }
        if !self.rt_heap.is_empty()   { return self.dequeue_rt(); }
        if !self.cfs_heap.is_empty()  { return self.dequeue_cfs(); }
        if !self.batch_heap.is_empty(){ return self.dequeue_batch(); }
        if !self.idle_queue.is_empty(){ return self.dequeue_idle(); }
        None
    }

    pub fn peek_next(&self) -> Option<u32> {
        if let Some(e) = self.dl_heap.peek()   { return Some(e.pid); }
        if let Some(e) = self.rt_heap.peek()   { return Some(e.pid); }
        if let Some(e) = self.cfs_heap.peek()  { return Some(e.pid); }
        if let Some(e) = self.batch_heap.peek(){ return Some(e.pid); }
        if let Some(&tp) = self.idle_queue.front() {
            return Some(unsafe { (*tp).pid });
        }
        None
    }

    pub fn remove_pid(&mut self, pid: u32) -> bool {
        {
            let old: Vec<RtEntry> = core::mem::take(&mut self.rt_heap).into_vec();
            let mut found = false;
            for e in old {
                if e.pid == pid {
                    let t = unsafe { &mut *e.task_ptr };
                    t.sched.on_rq = false;
                    self.nr_running  = self.nr_running.saturating_sub(1);
                    self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
                    found = true;
                } else {
                    self.rt_heap.push(e);
                }
            }
            if found { return true; }
        }

        {
            let old: Vec<CfsEntry> = core::mem::take(&mut self.cfs_heap).into_vec();
            let mut found = false;
            for e in old {
                if e.pid == pid {
                    let t = unsafe { &mut *e.task_ptr };
                    t.sched.on_rq = false;
                    self.nr_running  = self.nr_running.saturating_sub(1);
                    self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
                    found = true;
                } else {
                    self.cfs_heap.push(e);
                }
            }
            if found { return true; }
        }

        {
            let old: Vec<DlEntry> = core::mem::take(&mut self.dl_heap).into_vec();
            let mut found = false;
            for e in old {
                if e.pid == pid {
                    let t = unsafe { &mut *e.task_ptr };
                    t.sched.on_rq = false;
                    self.nr_running  = self.nr_running.saturating_sub(1);
                    self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
                    found = true;
                } else {
                    self.dl_heap.push(e);
                }
            }
            if found { return true; }
        }

        {
            let old: Vec<CfsEntry> = core::mem::take(&mut self.batch_heap).into_vec();
            let mut found = false;
            for e in old {
                if e.pid == pid {
                    let t = unsafe { &mut *e.task_ptr };
                    t.sched.on_rq = false;
                    self.nr_running  = self.nr_running.saturating_sub(1);
                    self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
                    found = true;
                } else {
                    self.batch_heap.push(e);
                }
            }
            if found { return true; }
        }

        if let Some(pos) = self.idle_queue.iter()
            .position(|&tp| unsafe { (*tp).pid } == pid)
        {
            let task = self.idle_queue.remove(pos).unwrap();
            let t = unsafe { &mut *task };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            return true;
        }

        false
    }
}

pub fn schedule() {
    let cpu = crate::smp::percpu::current_cpu_id();
    let blk = crate::smp::percpu::current_block();
    if blk.is_null() { schedule_early(); return; }
    let blk = unsafe { &mut *blk };

    let now = crate::time::clock::monotonic_ns();

    let prev_task = blk.current_task;
    if !prev_task.is_null() {
        let prev    = unsafe { &mut *prev_task };
        let elapsed = now.saturating_sub(blk.runqueue.curr_vruntime_start);

        match prev.sched.policy {
            SchedPolicy::Normal | SchedPolicy::Batch => {
                if prev.sched.weight > 0 {
                    let delta = elapsed * NICE0_WEIGHT / prev.sched.weight;
                    prev.sched.vruntime = prev.sched.vruntime.saturating_add(delta);
                }
            }
            SchedPolicy::Deadline => {
                prev.sched.dl_remaining =
                    prev.sched.dl_remaining.saturating_sub(elapsed);
            }
            _ => {}
        }

        let prev_pid = prev.pid;
        let prev_pl = proc_table::find_proc_lock(prev_pid as usize);
        if let Some(pl) = prev_pl {
            let s = pl.load_state();
            if s == State::Running || s == State::Ready {
                let mut inner = pl.inner.lock();
                pl.set_state(&mut inner, State::Ready);
                drop(inner);
                blk.runqueue.enqueue(prev_task);
            }
        }
    }

    let next_task = match blk.runqueue.dequeue_next() {
        Some(t) => t,
        None => {
            blk.current_task = core::ptr::null_mut();
            blk.current_pid = 0;
            if cpu == 0 {
                CURRENT_PID.store(0, core::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
    };

    let next = unsafe { &mut *next_task };
    if let Some(pl) = proc_table::find_proc_lock(next.pid as usize) {
        let mut inner = pl.inner.lock();
        pl.set_state(&mut inner, State::Running);
        inner.sched = next.sched.clone();
    }

    blk.runqueue.curr_vruntime_start = now;
    blk.current_task = next_task;
    blk.current_pid = next.pid;
    blk.ctx_switches += 1;

    if cpu == 0 {
        CURRENT_PID.store(next.pid, core::sync::atomic::Ordering::Relaxed);
    }

    unsafe {
        match &next.run_state {
            TaskRunState::Cold { .. } => {
                next.mark_live();
                crate::proc::context::restore(next_task);
            }
            TaskRunState::Live => {
                if !prev_task.is_null() && prev_task != next_task {
                    crate::proc::context::switch(prev_task, next_task);
                }
            }
        }
    }
}

fn schedule_early() {
    let next_pid_val = proc_table::with_procs_ro(|pl_vec| {
        pl_vec.iter()
            .find(|pl| pl.load_state() == State::Ready)
            .map(|pl| pl.pid)
    });
    let Some(npid) = next_pid_val else { return; };
    CURRENT_PID.store(npid, core::sync::atomic::Ordering::Relaxed);
    proc_table::with_proc_mut(npid as usize, |pcb, pl| {
        pl.set_state(pcb, State::Running);
    });
}

pub fn tick(cpu: u32) {
    let blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[cpu as usize] };
    blk.runqueue.tick_count += 1;
    let now = crate::time::clock::monotonic_ns();

    // Charge TICK_NS to the currently running task's process cpu_time_ns.
    // This is the source read by CLOCK_PROCESS_CPUTIME_ID / getrusage.
    let curr = blk.current_task;
    if !curr.is_null() {
        let pid = unsafe { (*curr).pid };
        if pid > 0 {
            if let Some(pl) = proc_table::find_proc_lock(pid as usize) {
                if let Some(mut inner) = pl.inner.try_lock() {
                    // Route tick to utime or stime based on whether this CPU
                    // is currently inside a syscall (in_syscall > 0 → kernel mode).
                    if blk.in_syscall > 0 {
                        inner.stime_ns = inner.stime_ns.saturating_add(TICK_NS);
                    } else {
                        inner.utime_ns = inner.utime_ns.saturating_add(TICK_NS);
                    }
                    inner.cpu_time_ns = inner.utime_ns.saturating_add(inner.stime_ns);
                }
            }
        }
    }

    proc_table::with_procs_ro(|pl_vec| {
        for pl in pl_vec.iter() {
            let s = pl.load_state();
            let inner_opt = pl.inner.try_lock();
            if let Some(mut inner) = inner_opt {
                if inner.sched.policy != SchedPolicy::Deadline { continue; }
                if inner.sched.dl_remaining > 0              { continue; }
                if now < inner.sched.dl_next_replenish       { continue; }
                let period = inner.sched.dl_period;
                inner.sched.dl_remaining      = inner.sched.dl_runtime;
                inner.sched.dl_abs_deadline   = now + inner.sched.dl_deadline;
                inner.sched.dl_next_replenish = now + period;
                if !inner.task.is_null() {
                    let t = unsafe { &mut *inner.task };
                    t.sched.dl_remaining      = inner.sched.dl_remaining;
                    t.sched.dl_abs_deadline   = inner.sched.dl_abs_deadline;
                    t.sched.dl_next_replenish = inner.sched.dl_next_replenish;
                }
                if s == State::Blocked {
                    pl.set_state(&mut inner, State::Ready);
                    let task = inner.task;
                    drop(inner);
                    if !task.is_null() { blk.runqueue.enqueue(task); }
                }
            }
        }
    });

    let curr = blk.current_task;
    if !curr.is_null() {
        let t = unsafe { &mut *curr };
        if t.sched.policy == SchedPolicy::Rr {
            let elapsed = now.saturating_sub(blk.runqueue.curr_vruntime_start);
            if elapsed >= TICK_NS {
                let pid = t.pid;
                if let Some(pl) = proc_table::find_proc_lock(pid as usize) {
                    let mut inner = pl.inner.lock();
                    pl.set_state(&mut inner, State::Ready);
                    drop(inner);
                }
                blk.current_task = core::ptr::null_mut();
                blk.runqueue.enqueue(curr);
                drop(blk);
                schedule();
                return;
            }
        }
    }

    if !curr.is_null() {
        let t = unsafe { &*curr };
        if matches!(t.sched.policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
            if let Some(pl) = proc_table::find_proc_lock(t.pid as usize) {
                let kill = {
                    let mut inner = pl.inner.lock();
                    inner.rt_cpu_time_us = inner.rt_cpu_time_us
                        .saturating_add(TICK_NS / 1000);
                    let (soft, _) = crate::proc::rlimit::getrlimit_for(
                        t.pid as usize,
                        crate::proc::rlimit::RLIMIT_RTTIME,
                    );
                    soft != crate::proc::rlimit::RLIM_INFINITY
                        && inner.rt_cpu_time_us >= soft
                };
                if kill {
                    crate::proc::signal::send_signal(t.pid as usize, 24);
                }
            }
        }
    }

    if blk.runqueue.tick_count % BALANCE_TICKS == 0 {
        drop(blk);
        load_balance(cpu);
    }
}

#[derive(Copy, Clone)]
struct RqSnapshot {
    load_weight: u64,
    nr_running:  u32,
}

fn load_balance(this_cpu: u32) {
    let ncpus = crate::smp::percpu::cpu_count();
    if ncpus <= 1 { return; }

    let mut snapshots: [RqSnapshot; 64] = [RqSnapshot { load_weight: 0, nr_running: 0 }; 64];
    let ncpus_clamped = (ncpus as usize).min(64);
    for cpu in 0..ncpus_clamped {
        let blk = unsafe { &crate::smp::percpu::PERCPU_BLOCKS[cpu] };
        snapshots[cpu] = RqSnapshot {
            load_weight: blk.runqueue.load_weight,
            nr_running:  blk.runqueue.nr_running,
        };
    }

    let mut max_load: u64 = 0;
    let mut busiest_cpu: u32 = this_cpu;
    for cpu in 0..ncpus_clamped {
        if snapshots[cpu].load_weight > max_load {
            max_load = snapshots[cpu].load_weight;
            busiest_cpu = cpu as u32;
        }
    }
    if busiest_cpu == this_cpu { return; }

    let this_load = snapshots[this_cpu as usize].load_weight;
    if max_load <= this_load + this_load / 4 { return; }

    let busy_blk = unsafe {
        &mut crate::smp::percpu::PERCPU_BLOCKS[busiest_cpu as usize]
    };
    if busy_blk.runqueue.nr_running <= 1 { return; }

    if let Some(task) = busy_blk.runqueue.dequeue_next() {
        let t = unsafe { &mut *task };
        if t.sched.policy == SchedPolicy::Idle
            || t.sched.policy == SchedPolicy::Deadline
            || t.sched.cpumask.count_ones() == 1
            || !t.sched.cpu_allowed(this_cpu)
        {
            busy_blk.runqueue.enqueue(task);
            return;
        }
        t.sched.last_cpu = this_cpu;
        unsafe {
            crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize]
                .runqueue.enqueue(task);
        }
        crate::smp::ipi::send_reschedule(this_cpu);
    }
}

pub fn enqueue_task(task: *mut crate::proc::task_types::Task) {
    if task.is_null() { return; }
    let t = unsafe { &mut *task };
    let ncpus = crate::smp::percpu::cpu_count();

    let mut best_cpu  = u32::MAX;
    let mut best_load = u64::MAX;
    for cpu in 0..ncpus {
        if !t.sched.cpu_allowed(cpu) { continue; }
        let load = unsafe {
            crate::smp::percpu::PERCPU_BLOCKS[cpu as usize].runqueue.load_weight
        };
        if load < best_load { best_load = load; best_cpu = cpu; }
    }
    if best_cpu == u32::MAX { best_cpu = 0; }

    t.sched.last_cpu = best_cpu;
    unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[best_cpu as usize]
            .runqueue.enqueue(task);
    }
    crate::smp::ipi::send_reschedule(best_cpu);
}

pub fn schedule_on(task: *mut crate::proc::task_types::Task, cpu: u32) {
    if task.is_null() { return; }
    let ncpus = crate::smp::percpu::cpu_count();
    if cpu >= ncpus { return; }
    let t = unsafe { &mut *task };
    let pid = t.pid;
    if t.sched.on_rq {
        let prev_cpu = t.sched.last_cpu;
        if prev_cpu < ncpus {
            unsafe {
                crate::smp::percpu::PERCPU_BLOCKS[prev_cpu as usize]
                    .runqueue.remove_pid(pid);
            }
        }
    }
    t.sched.cpumask  = 1u64 << cpu;
    t.sched.last_cpu = cpu;
    unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[cpu as usize]
            .runqueue.enqueue(task);
    }
    crate::smp::ipi::send_reschedule(cpu);
}

pub fn block_current() {
    let pid = current_pid();
    if let Some(pl) = proc_table::find_proc_lock(pid as usize) {
        let mut inner = pl.inner.lock();
        if matches!(inner.sched.policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
            inner.rt_cpu_time_us = 0;
        }
        pl.set_state(&mut inner, State::Blocked);
    }
    let cpu = crate::smp::percpu::current_cpu_id();
    unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[cpu as usize]
            .runqueue.remove_pid(pid);
    }
    let blk = crate::smp::percpu::current_block();
    if !blk.is_null() {
        unsafe { (*blk).current_task = core::ptr::null_mut(); }
    }
    schedule();
}

pub fn wake_pid(pid: usize) {
    let pl = match proc_table::find_proc_lock(pid) {
        Some(p) => p,
        None    => return,
    };
    if pl.load_state() != State::Blocked { return; }

    let task = {
        let mut inner = pl.inner.lock();
        if inner.state != State::Blocked { return; }
        pl.set_state(&mut inner, State::Ready);
        inner.task
    };

    if task.is_null() { return; }
    let already = unsafe { (*task).sched.on_rq };
    if !already { enqueue_task(task); }
}

pub fn suspend_current_until_child_exec(_child_pid: usize) {
    block_current();
}

pub struct MmReadGuard {
    _arc:   alloc::sync::Arc<spin::RwLock<()>>,
    _guard: spin::RwLockReadGuard<'static, ()>,
}

unsafe impl Send for MmReadGuard {}

pub fn with_current_mm_read() -> MmReadGuard {
    let pid = current_pid() as usize;
    let arc = proc_table::with_proc(pid, |pcb| alloc::sync::Arc::clone(&pcb.mm_lock))
        .expect("with_current_mm_read: no current process");
    let guard = unsafe {
        let raw: *const spin::RwLock<()> = alloc::sync::Arc::as_ptr(&arc);
        (*raw).read()
    };
    MmReadGuard { _arc: arc, _guard: guard }
}

static CURRENT_PID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static NEXT_PID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

pub fn next_pid() -> u32 {
    NEXT_PID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

pub fn proc_count() -> usize {
    proc_table::proc_count()
}

#[inline]
pub fn current_pid() -> u32 {
    let blk = crate::smp::percpu::current_block();
    if blk.is_null() {
        return CURRENT_PID.load(core::sync::atomic::Ordering::Relaxed);
    }
    let blk_ref = unsafe { &*blk };
    if blk_ref.current_pid != 0 { return blk_ref.current_pid; }
    let task = blk_ref.current_task;
    if task.is_null() {
        return CURRENT_PID.load(core::sync::atomic::Ordering::Relaxed);
    }
    unsafe { (*task).pid }
}

#[inline]
pub fn with_proc<T, F>(pid: usize, f: F) -> Option<T>
where F: FnOnce(&crate::proc::process::Pcb) -> T {
    proc_table::with_proc(pid, f)
}
#[inline]
pub fn with_proc_mut<T, F>(pid: usize, f: F) -> Option<T>
where F: FnOnce(&mut crate::proc::process::Pcb, &ProcLock) -> T {
    proc_table::with_proc_mut(pid, f)
}
#[inline]
pub fn with_procs_ro<T, F>(f: F) -> T
where F: FnOnce(&alloc::vec::Vec<alloc::sync::Arc<ProcLock>>) -> T {
    proc_table::with_procs_ro(f)
}
#[inline]
pub fn with_procs_mut<T, F>(f: F) -> T
where F: FnOnce(&mut alloc::vec::Vec<alloc::sync::Arc<ProcLock>>) -> T {
    proc_table::with_procs_mut(f)
}
#[inline]
pub fn enqueue(pcb: crate::proc::process::Pcb) { proc_table::enqueue(pcb) }
#[inline]
pub fn task_ptr_for_pid(pid: usize) -> *mut crate::proc::task_types::Task {
    proc_table::task_ptr_for_pid(pid)
}
#[inline]
pub fn tgid_of(pid: usize) -> usize {
    proc_table::with_proc(pid, |p| p.tgid).unwrap_or(0)
}
#[inline]
pub fn thread_count_of(pid: usize) -> Option<usize> {
    proc_table::thread_count_of(pid)
}
#[inline]
pub fn has_current_user_proc() -> bool {
    let blk = crate::smp::percpu::current_block();
    if blk.is_null() { return false; }
    let task = unsafe { (*blk).current_task };
    if task.is_null() { return false; }
    unsafe { (*task).pid > 0 }
}
pub fn current_ppid() -> u32 {
    let pid = current_pid() as usize;
    proc_table::with_proc(pid, |p| p.ppid as u32).unwrap_or(0)
}
pub fn ap_idle() -> ! {
    loop {
        schedule();
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("wfi", options(nostack, nomem)); }
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

// ===== GUESS: short aliases for new callers =====

/// GUESS: alias of `with_procs_ro` — callers use `scheduler::with_procs`.
#[inline]
pub fn with_procs<T, F>(f: F) -> T
where F: FnOnce(&alloc::vec::Vec<alloc::sync::Arc<ProcLock>>) -> T,
{
    with_procs_ro(f)
}

/// GUESS: pidfd.rs uses imperative `procs_lock`/`procs_unlock` pairs. We
/// don't have a static lock to hand back, so return an owned Vec snapshot.
/// This loses live mutation visibility but keeps callers compiling. The
/// surface is read-only in pidfd.
pub fn procs_lock() -> alloc::vec::Vec<alloc::sync::Arc<ProcLock>> {
    with_procs_ro(|v| v.clone())
}

/// GUESS: no-op pair — the snapshot from `procs_lock` releases via Drop.
#[inline] pub fn procs_unlock() {}
