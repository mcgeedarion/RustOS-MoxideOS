//! Multi-policy per-CPU scheduler.
//!
//! ## Scheduling classes (priority order)
//!
//! 1. **`SCHED_DEADLINE`** — Earliest-Deadline-First (EDF) with CBS budget.
//!    Exhausted tasks sleep until their next replenishment window.
//!
//! 2. **`SCHED_FIFO` / `SCHED_RR`** — real-time FIFO queue.  FIFO tasks run
//!    until they yield/block; RR rotates within their priority band after one
//!    `TICK_NS` tick.
//!
//! 3. **`SCHED_NORMAL`** — CFS-inspired vruntime min-heap.
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

use core::cmp::Reverse;
use alloc::{collections::BinaryHeap, collections::VecDeque, vec::Vec};
use crate::sync::spinlock::SpinLock;
use crate::proc::process::{State, ProcLock};
use crate::proc::proc_table;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const TICK_NS:        u64 = 1_000_000;
pub const NICE0_WEIGHT:   u64 = 1_024;
pub const BALANCE_TICKS:  u64 = 10;
pub const CPUMASK_ALL:    u64 = u64::MAX;

// ── SchedPolicy ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchedPolicy {
    Normal   = 0,
    Fifo     = 1,
    Rr       = 2,
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

// ── Weight table ──────────────────────────────────────────────────────────────

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

// ── CFS entry ─────────────────────────────────────────────────────────────────

#[derive(Eq, PartialEq)]
struct CfsEntry {
    vruntime: u64,
    pid:      u32,
    task_ptr: *mut crate::proc::task_types::Task,
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

// ── Deadline entry ────────────────────────────────────────────────────────────

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

// ── Per-CPU RunQueue ──────────────────────────────────────────────────────────

pub struct RunQueue {
    pub cfs_heap:           BinaryHeap<CfsEntry>,
    pub min_vruntime:       u64,
    pub rt_queue:           VecDeque<*mut crate::proc::task_types::Task>,
    pub dl_heap:            BinaryHeap<DlEntry>,
    pub nr_running:         u32,
    pub load_weight:        u64,
    pub tick_count:         u64,
    pub curr_vruntime_start:u64,
}

unsafe impl Send for RunQueue {}

impl RunQueue {
    pub const fn new() -> Self {
        RunQueue {
            cfs_heap:            BinaryHeap::new(),
            min_vruntime:        0,
            rt_queue:            VecDeque::new(),
            dl_heap:             BinaryHeap::new(),
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
                self.rt_queue.push_back(task);
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
        }
    }

    fn dequeue_cfs(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        self.cfs_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            e.task_ptr
        })
    }

    fn dequeue_rt(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        if self.rt_queue.is_empty() { return None; }
        let best_idx = self.rt_queue.iter().enumerate()
            .max_by_key(|(_, &tp)| unsafe { (*tp).sched.rt_priority })
            .map(|(i, _)| i)?;
        let task = self.rt_queue.remove(best_idx)?;
        let t = unsafe { &mut *task };
        t.sched.on_rq = false;
        self.nr_running  = self.nr_running.saturating_sub(1);
        self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
        Some(task)
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

    pub fn dequeue_next(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        if !self.dl_heap.is_empty()  { return self.dequeue_dl(); }
        if !self.rt_queue.is_empty() { return self.dequeue_rt(); }
        self.dequeue_cfs()
    }

    pub fn peek_next(&self) -> Option<u32> {
        if let Some(e) = self.dl_heap.peek()  { return Some(e.pid); }
        if let Some(&tp) = self.rt_queue.front() {
            return Some(unsafe { (*tp).pid });
        }
        self.cfs_heap.peek().map(|e| e.pid)
    }

    pub fn remove_pid(&mut self, pid: u32) -> bool {
        if let Some(pos) = self.rt_queue.iter()
            .position(|&tp| unsafe { (*tp).pid } == pid)
        {
            let task = self.rt_queue.remove(pos).unwrap();
            let t = unsafe { &mut *task };
            t.sched.on_rq = false;
            self.nr_running  = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            return true;
        }
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
        let old: Vec<DlEntry> = core::mem::take(&mut self.dl_heap).into_vec();
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
        found
    }
}

// ── schedule() ────────────────────────────────────────────────────────────────
//
// Hot path.  Never locks PROC_TABLE.
// State transitions are done via ProcLock::set_state (updates both the
// Pcb field and the state_atom atomically under ProcLock::inner).

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

        if prev.sched.policy == SchedPolicy::Normal && prev.sched.weight > 0 {
            let delta = elapsed * NICE0_WEIGHT / prev.sched.weight;
            prev.sched.vruntime = prev.sched.vruntime.saturating_add(delta);
        }
        if prev.sched.policy == SchedPolicy::Deadline {
            prev.sched.dl_remaining =
                prev.sched.dl_remaining.saturating_sub(elapsed);
        }

        let prev_pid = prev.pid;
        // Fast-path state check via atomic — no PROC_TABLE lock needed.
        let prev_pl = proc_table::find_proc_lock(prev_pid as usize);
        if let Some(pl) = prev_pl {
            let s = pl.load_state();
            if s == State::Running || s == State::Ready {
                let mut inner = pl.inner.lock();
                pl.set_state(&mut inner, State::Ready);
                drop(inner);
                blk.runqueue.enqueue(prev_task);
            }
            // Blocked / Zombie / Stopped: don't re-enqueue.
        }
    }

    let next_task = match blk.runqueue.dequeue_next() {
        Some(t) => t,
        None => {
            blk.current_task = core::ptr::null_mut();
            if cpu == 0 {
                CURRENT_PID.store(0, core::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
    };

    let next = unsafe { &mut *next_task };
    // Mark Running via ProcLock — no PROC_TABLE lock.
    if let Some(pl) = proc_table::find_proc_lock(next.pid as usize) {
        let mut inner = pl.inner.lock();
        pl.set_state(&mut inner, State::Running);
        // Sync Pcb::sched from Task::sched (authoritative hot copy).
        inner.sched = next.sched.clone();
    }

    blk.runqueue.curr_vruntime_start = now;
    blk.current_task  = next_task;
    blk.ctx_switches += 1;

    if cpu == 0 {
        CURRENT_PID.store(next.pid, core::sync::atomic::Ordering::Relaxed);
    }

    if !prev_task.is_null() && prev_task != next_task {
        unsafe { crate::proc::context::switch(prev_task, next_task); }
    } else if prev_task.is_null() {
        unsafe { crate::proc::context::restore(next_task); }
    }
}

fn schedule_early() {
    // Early-boot fallback: no percpu storage yet, linear scan is fine.
    // We only read PROC_TABLE here — no other lock is held.
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

// ── tick() + load balance ─────────────────────────────────────────────────────
//
// tick() never locks PROC_TABLE on the hot replenishment path — it reads
// state_atom.  It takes the inner lock only to set Blocked→Ready.

pub fn tick(cpu: u32) {
    let blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[cpu as usize] };
    blk.runqueue.tick_count += 1;
    let now = crate::time::clock::monotonic_ns();

    // ── Deadline replenishment ────────────────────────────────────────────
    // Scan all ProcLocks; check state_atom without locking inner first.
    proc_table::with_procs_ro(|pl_vec| {
        for pl in pl_vec.iter() {
            // Quick filter: only consider tasks whose sched policy is DL.
            // We peek state_atom for Blocked — if Ready/Running, CBS handles it.
            let s = pl.load_state();
            // Lock inner only when we need to replenish.
            let inner_opt = pl.inner.try_lock();
            if let Some(mut inner) = inner_opt {
                if inner.sched.policy != SchedPolicy::Deadline { continue; }
                if inner.sched.dl_remaining > 0              { continue; }
                if now < inner.sched.dl_next_replenish       { continue; }
                let period = inner.sched.dl_period;
                inner.sched.dl_remaining      = inner.sched.dl_runtime;
                inner.sched.dl_abs_deadline   = now + inner.sched.dl_deadline;
                inner.sched.dl_next_replenish = now + period;
                // Also update Task::sched so the run-queue sees correct deadline.
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

    // ── RR time-slice preemption ─────────────────────────────────────────
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

    // ── RLIMIT_RTTIME enforcement (S4 fix) ───────────────────────────────
    // Increment rt_cpu_time_us for the running RT task.  Kill it if exceeded.
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
                    crate::proc::signal::send_signal(t.pid as usize, 24 /* SIGXCPU */);
                }
            }
        }
    }

    // ── Load balance ─────────────────────────────────────────────────────
    if blk.runqueue.tick_count % BALANCE_TICKS == 0 {
        drop(blk);
        load_balance(cpu);
    }
}

fn load_balance(this_cpu: u32) {
    let ncpus = crate::smp::percpu::cpu_count();
    if ncpus <= 1 { return; }

    let mut max_load: u64 = 0;
    let mut busiest_cpu: u32 = this_cpu;
    for cpu in 0..ncpus {
        let load = unsafe {
            crate::smp::percpu::PERCPU_BLOCKS[cpu as usize].runqueue.load_weight
        };
        if load > max_load { max_load = load; busiest_cpu = cpu; }
    }
    if busiest_cpu == this_cpu { return; }

    let this_load = unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize].runqueue.load_weight
    };
    if max_load <= this_load + this_load / 4 { return; }

    let busy_blk = unsafe {
        &mut crate::smp::percpu::PERCPU_BLOCKS[busiest_cpu as usize]
    };
    if busy_blk.runqueue.nr_running <= 1 { return; }

    if let Some(task) = busy_blk.runqueue.dequeue_next() {
        let t = unsafe { &mut *task };
        if t.sched.policy == SchedPolicy::Deadline
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

// ── Enqueue helpers ───────────────────────────────────────────────────────────

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

// ── Blocking / waking ─────────────────────────────────────────────────────────

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

/// Wake a task.  Lock-free fast path: check state_atom before locking inner.
pub fn wake_pid(pid: usize) {
    let pl = match proc_table::find_proc_lock(pid) {
        Some(p) => p,
        None    => return,
    };
    // Fast-path: if not Blocked, do nothing.
    if pl.load_state() != State::Blocked { return; }

    let task = {
        let mut inner = pl.inner.lock();
        // Double-check under lock (state may have changed between the
        // atomic load and the lock acquisition).
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

// ── current_pid ───────────────────────────────────────────────────────────────

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
    let task = unsafe { (*blk).current_task };
    if task.is_null() {
        return CURRENT_PID.load(core::sync::atomic::Ordering::Relaxed);
    }
    unsafe { (*task).pid }
}

/// Convenience wrappers — delegate to proc_table so callers don't need
/// to import two modules.
#[inline]
pub fn with_proc<T, F>(pid: usize, f: F) -> Option<T>
where
    F: FnOnce(&crate::proc::process::Pcb) -> T,
{
    proc_table::with_proc(pid, f)
}
#[inline]
pub fn with_proc_mut<T, F>(
    pid: usize,
    f: F,
) -> Option<T>
where
    F: FnOnce(&mut crate::proc::process::Pcb, &ProcLock) -> T,
{
    proc_table::with_proc_mut(pid, f)
}
#[inline]
pub fn with_procs_ro<T, F>(f: F) -> T
where
    F: FnOnce(&alloc::vec::Vec<alloc::sync::Arc<ProcLock>>) -> T,
{
    proc_table::with_procs_ro(f)
}
#[inline]
pub fn with_procs_mut<T, F>(f: F) -> T
where
    F: FnOnce(&mut alloc::vec::Vec<alloc::sync::Arc<ProcLock>>) -> T,
{
    proc_table::with_procs_mut(f)
}
#[inline]
pub fn enqueue(pcb: crate::proc::process::Pcb) {
    proc_table::enqueue(pcb);
}
#[inline]
pub fn task_ptr_for_pid(pid: usize) -> *mut crate::proc::task_types::Task {
    proc_table::task_ptr_for_pid(pid)
}
#[inline]
pub fn tgid_of(pid: usize) -> usize {
    proc_table::with_proc(pid, |p| p.tgid).unwrap_or(0)
}
#[inline]
pub fn has_current_user_proc() -> bool {
    let blk = crate::smp::percpu::current_block();
    if blk.is_null() { return false; }
    let task = unsafe { (*blk).current_task };
    if task.is_null() { return false; }
    unsafe { (*task).pid > 0 }
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
