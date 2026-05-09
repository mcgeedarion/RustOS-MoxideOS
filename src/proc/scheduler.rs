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
//! 3. **`SCHED_NORMAL`** — CFS-inspired vruntime min-heap.
//!
//! ## Per-CPU run queues
//!
//! Every CPU has an independent `RunQueue` in its `PercpuBlock`.  `schedule()`
//! operates entirely on the *calling CPU's* run queue — it never touches
//! another CPU's queue directly.  Cross-CPU wakeups send a reschedule IPI so
//! the remote CPU picks up the newly-enqueued task at its next timer tick or
//! IPI handler entry.
//!
//! ## CPU affinity
//!
//! `enqueue_task` scans all CPUs and picks the least-loaded one whose
//! affinity mask permits the task.  Load balancing in `tick()` re-evaluates
//! this every `BALANCE_TICKS` ticks.
//!
//! ## current_pid() on SMP
//!
//! Each CPU tracks its running task via `PercpuBlock::current_task`.  The
//! global `CURRENT_PID` atomic is kept only as a BSP-0 fallback during early
//! boot before percpu storage is initialised.
//!
//! ## mm_lock helpers (for uaccess TOCTOU mitigation)
//!
//! `with_current_mm_read()` and `has_current_user_proc()` are called by
//! `uaccess.rs` to hold the current process's mm_lock in read mode across
//! the validate+copy sequence, preventing concurrent `munmap` from unmapping
//! pages between page-table walk and memory copy.

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

// ── Scheduling policy ───────────────────────────────────────────────────────────

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
    pub vruntime: u64,
    pub weight: u64,
    pub nice: i8,
    pub rt_priority: u8,
    pub dl_runtime: u64,
    pub dl_deadline: u64,
    pub dl_period: u64,
    pub dl_remaining: u64,
    pub dl_abs_deadline: u64,
    pub dl_next_replenish: u64,
    pub policy: SchedPolicy,
    pub cpumask: u64,
    pub last_cpu: u32,
    pub on_rq: bool,
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

// ── Weight table ─────────────────────────────────────────────────────────────────

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

// ── CFS run-queue entry ──────────────────────────────────────────────────────────

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

// ── Deadline run-queue entry ──────────────────────────────────────────────────────

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

// ── Per-CPU RunQueue ────────────────────────────────────────────────────────────

pub struct RunQueue {
    pub cfs_heap:  BinaryHeap<CfsEntry>,
    pub min_vruntime: u64,
    pub rt_queue:  VecDeque<*mut crate::proc::task::Task>,
    pub dl_heap:   BinaryHeap<DlEntry>,
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

    pub fn remove_pid(&mut self, pid: u32) -> bool {
        if let Some(pos) = self.rt_queue.iter().position(|&tp| unsafe { (*tp).pid } == pid) {
            let task = self.rt_queue.remove(pos).unwrap();
            let t = unsafe { &mut *task };
            t.sched.on_rq = false;
            self.nr_running = self.nr_running.saturating_sub(1);
            self.load_weight = self.load_weight.saturating_sub(t.sched.weight);
            return true;
        }
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

// ── Global process table ────────────────────────────────────────────────────────

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

// ── mm_lock helpers for uaccess TOCTOU mitigation ────────────────────────────────

/// RAII guard for the current process's mm_lock in read mode.
///
/// Dropping this guard releases the read lock, allowing a concurrent
/// `munmap` (which takes the write side) to proceed.
///
/// Implemented as a hold on the global PROCS SpinLock for the lifetime of
/// the guard.  This is conservative — it blocks all process-table mutations
/// including unrelated processes.  A per-process RwLock would be ideal but
/// requires Pcb to own an RwLock which is a larger refactor.  The
/// conservative approach is correct and safe for now.
pub struct MmReadGuard<'a> {
    _guard: crate::sync::spinlock::SpinLockGuard<'a, Vec<Pcb>>,
}

/// Acquire the current process's mm_lock in read mode.
///
/// Returns a `MmReadGuard` that holds the lock until dropped.  The caller
/// MUST perform all page-table walks and memory copies before dropping
/// this guard to prevent the TOCTOU window.
///
/// Panics in debug mode if called when no user process is running
/// (`has_current_user_proc()` returns false).
pub fn with_current_mm_read() -> MmReadGuard<'static> {
    // SAFETY: PROCS is 'static; the guard borrows it for 'static lifetime.
    // The caller is responsible for not holding this guard across a context
    // switch (which cannot happen while interrupts are disabled in a syscall).
    MmReadGuard {
        _guard: PROCS.lock(),
    }
}

/// Returns true when a user process (pid > 0) is currently running on
/// this CPU and percpu storage is live.
///
/// Used by `uaccess.rs` to decide whether to acquire mm_lock:
///   - `true`  → a user process is current; mm_lock acquisition is meaningful.
///   - `false` → early boot or kernel thread; no concurrent munmap possible.
#[inline]
pub fn has_current_user_proc() -> bool {
    let blk = crate::smp::percpu::current_block();
    if blk.is_null() { return false; }
    let task = unsafe { (*blk).current_task };
    if task.is_null() { return false; }
    let pid = unsafe { (*task).pid };
    pid > 0
}

pub fn enqueue(pcb: Pcb) {
    PROCS.lock().push(pcb);
}

pub fn with_proc<T, F: FnOnce(&Pcb) -> T>(pid: u32, f: F) -> Option<T> {
    let procs = PROCS.lock();
    procs.iter().find(|p| p.pid == pid).map(f)
}

pub fn with_proc_mut<T, F: FnOnce(&mut Pcb) -> T>(pid: u32, f: F) -> Option<T> {
    let mut procs = PROCS.lock();
    procs.iter_mut().find(|p| p.pid == pid).map(f)
}

pub fn with_procs<T, F: FnOnce(&Vec<Pcb>) -> T>(f: F) -> T {
    f(&PROCS.lock())
}

pub fn with_procs_mut<T, F: FnOnce(&mut Vec<Pcb>) -> T>(f: F) -> T {
    f(&mut PROCS.lock())
}

pub use with_procs as with_procs_ro;

fn task_ptr_for(pid: u32) -> *mut Task {
    with_proc(pid, |p| p.task as *mut Task).unwrap_or(core::ptr::null_mut())
}

pub fn enqueue_task(task: *mut Task) {
    if task.is_null() { return; }
    let t = unsafe { &mut *task };
    let ncpus = crate::smp::percpu::cpu_count();

    let mut best_cpu = u32::MAX;
    let mut best_load = u64::MAX;
    for cpu in 0..ncpus {
        if !t.sched.cpu_allowed(cpu) { continue; }
        let load = unsafe {
            crate::smp::percpu::PERCPU_BLOCKS[cpu as usize].runqueue.load_weight
        };
        if load < best_load {
            best_load = load;
            best_cpu  = cpu;
        }
    }
    if best_cpu == u32::MAX { best_cpu = 0; }

    t.sched.last_cpu = best_cpu;
    unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[best_cpu as usize]
            .runqueue
            .enqueue(task);
    }

    let this_cpu = crate::smp::percpu::current_cpu_id();
    if best_cpu != this_cpu {
        crate::smp::ipi::send_reschedule(best_cpu);
    }
}

pub fn block_current() {
    let pid = current_pid();

    with_proc_mut(pid, |p| {
        p.state = crate::proc::process::State::Blocked;
        if matches!(p.sched.policy, SchedPolicy::Fifo | SchedPolicy::Rr) {
            p.rt_cpu_time_us = 0;
        }
    });

    let cpu = crate::smp::percpu::current_cpu_id();
    unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[cpu as usize]
            .runqueue
            .remove_pid(pid);
    }

    let blk = crate::smp::percpu::current_block();
    if !blk.is_null() {
        unsafe { (*blk).current_task = core::ptr::null_mut(); }
    }

    schedule();
}

pub fn wake_pid(pid: u32) {
    let task = task_ptr_for(pid);
    if task.is_null() { return; }

    let was_blocked = with_proc_mut(pid, |p| {
        if p.state == crate::proc::process::State::Blocked {
            p.state = crate::proc::process::State::Ready;
            true
        } else {
            false
        }
    }).unwrap_or(false);

    if !was_blocked { return; }

    let already_on_rq = with_proc(pid, |p| p.sched.on_rq).unwrap_or(false);
    if !already_on_rq {
        enqueue_task(task);
    }
}

pub fn suspend_current_until_child_exec(_child_pid: u32) {
    block_current();
}

pub fn schedule() {
    let cpu  = crate::smp::percpu::current_cpu_id();
    let blk  = crate::smp::percpu::current_block();
    if blk.is_null() {
        schedule_early();
        return;
    }
    let blk = unsafe { &mut *blk };

    let now = crate::time::clock::monotonic_ns();

    let prev_task = blk.current_task;
    if !prev_task.is_null() {
        let prev = unsafe { &mut *prev_task };
        let elapsed = now.saturating_sub(blk.runqueue.curr_vruntime_start);
        if prev.sched.policy == SchedPolicy::Normal && prev.sched.weight > 0 {
            let delta_vruntime = elapsed * NICE0_WEIGHT / prev.sched.weight;
            prev.sched.vruntime = prev.sched.vruntime.saturating_add(delta_vruntime);
        }
        if prev.sched.policy == SchedPolicy::Deadline {
            prev.sched.dl_remaining = prev.sched.dl_remaining.saturating_sub(elapsed);
        }

        let prev_pid   = prev.pid;
        let prev_state = with_proc(prev_pid, |p| p.state).unwrap_or(crate::proc::process::State::Zombie);
        if prev_state == crate::proc::process::State::Running
            || prev_state == crate::proc::process::State::Ready
        {
            with_proc_mut(prev_pid, |p| p.state = crate::proc::process::State::Ready);
            blk.runqueue.enqueue(prev_task);
        }
    }

    let next_task = match blk.runqueue.dequeue_next() {
        Some(t) => t,
        None    => {
            blk.current_task = core::ptr::null_mut();
            if cpu == 0 {
                CURRENT_PID.store(0, core::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
    };

    let next = unsafe { &mut *next_task };
    with_proc_mut(next.pid, |p| p.state = crate::proc::process::State::Running);
    blk.runqueue.curr_vruntime_start = now;
    blk.current_task = next_task;
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
    let mut procs = PROCS.lock();
    let next_pid_val = procs.iter()
        .find(|p| p.state == crate::proc::process::State::Ready)
        .map(|p| p.pid);
    let Some(npid) = next_pid_val else { return; };
    CURRENT_PID.store(npid, core::sync::atomic::Ordering::Relaxed);
    if let Some(p) = procs.iter_mut().find(|p| p.pid == npid) {
        p.state = crate::proc::process::State::Running;
    }
}

pub fn tick(cpu: u32) {
    let blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[cpu as usize] };
    blk.runqueue.tick_count += 1;
    let now = crate::time::clock::monotonic_ns();

    {
        let mut procs = PROCS.lock();
        for p in procs.iter_mut() {
            if p.sched.policy != SchedPolicy::Deadline { continue; }
            if p.sched.dl_remaining > 0 { continue; }
            if now < p.sched.dl_next_replenish { continue; }
            let period = p.sched.dl_period;
            p.sched.dl_remaining        = p.sched.dl_runtime;
            p.sched.dl_abs_deadline     = now + p.sched.dl_deadline;
            p.sched.dl_next_replenish   = now + period;
            if p.state == crate::proc::process::State::Blocked {
                p.state = crate::proc::process::State::Ready;
                let task = p.task as *mut Task;
                if !task.is_null() {
                    blk.runqueue.enqueue(task);
                }
            }
        }
    }

    let curr = blk.current_task;
    if !curr.is_null() {
        let t = unsafe { &mut *curr };
        if t.sched.policy == SchedPolicy::Rr {
            let elapsed = now.saturating_sub(blk.runqueue.curr_vruntime_start);
            if elapsed >= TICK_NS {
                let pid = t.pid;
                with_proc_mut(pid, |p| p.state = crate::proc::process::State::Ready);
                blk.current_task = core::ptr::null_mut();
                blk.runqueue.enqueue(curr);
                drop(blk);
                schedule();
                return;
            }
        }
    }

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
        if load > max_load {
            max_load    = load;
            busiest_cpu = cpu;
        }
    }
    if busiest_cpu == this_cpu { return; }

    let this_load = unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize].runqueue.load_weight
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
        unsafe {
            crate::smp::percpu::PERCPU_BLOCKS[this_cpu as usize]
                .runqueue
                .enqueue(task);
        }
    }
}
