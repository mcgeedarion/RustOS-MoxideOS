//! Kernel timer wheel + POSIX interval timers (itimer).
//!
//! ## Timer wheel
//!
//! A simple sorted linked list (BTreeMap keyed by deadline_ns) is used.
//! `expire_timers()` is called from the tick handler and fires all timers
//! whose deadline has passed.  This is O(k log n) where k is the number of
//! expired timers per tick — acceptable for a research kernel.
//!
//! For production use this should be replaced with a hierarchical timer wheel
//! (Linux `hrtimer` style).
//!
//! ## POSIX interval timers  (getitimer / setitimer)
//!
//! Three per-process timers:
//!
//! | Name             | Signal   | Clocks                    |
//! |------------------|----------|---------------------------|
//! | ITIMER_REAL      | SIGALRM  | CLOCK_REALTIME            |
//! | ITIMER_VIRTUAL   | SIGVTALRM| CLOCK_PROCESS_CPUTIME_ID  |
//! | ITIMER_PROF      | SIGPROF  | user + kernel time        |
//!
//! Per-process `ItimerState` is stored in `proc::Task` (integration point).
//!
//! ## clock_nanosleep (kernel helper)
//!
//! `clock_nanosleep()` is a convenience wrapper around
//! `proc::nanosleep::sleep_until_ns` for use by kernel code that already
//! has an absolute monotonic deadline.  Userspace syscalls go through
//! `proc::nanosleep::sys_clock_nanosleep` instead.

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::time::{Timespec, read_monotonic_ns, NSEC_PER_SEC};

/// Passed as `flags` to `clock_nanosleep` and `sys_clock_nanosleep`
/// to indicate the request time is an absolute deadline.
pub const TIMER_ABSTIME: i32 = 1;

pub type TimerCallback = fn(u64); // arg is the timer ID

/// A pending kernel timer.
struct TimerEntry {
    deadline_ns: u64,
    period_ns:   u64,     // 0 = one-shot
    callback:    TimerCallback,
    id:          u64,
}

static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

struct Wheel {
    /// Sorted by deadline.  Multiple timers may share the same deadline
    /// (BTreeMap key = deadline << 20 | id to avoid collisions).
    entries: BTreeMap<u64, TimerEntry>,
}

impl Wheel {
    fn new() -> Self { Wheel { entries: BTreeMap::new() } }

    fn insert(&mut self, deadline_ns: u64, period_ns: u64, cb: TimerCallback) -> u64 {
        let id  = NEXT_TIMER_ID.fetch_add(1, Ordering::SeqCst);
        let key = (deadline_ns << 20).wrapping_add(id & 0xF_FFFF);
        self.entries.insert(key, TimerEntry { deadline_ns, period_ns, callback: cb, id });
        id
    }

    fn cancel(&mut self, id: u64) {
        self.entries.retain(|_, e| e.id != id);
    }

    /// Fire all timers whose deadline ≤ `now_ns`.  Re-arms periodic timers.
    fn expire(&mut self, now_ns: u64) {
        let deadline_max = now_ns << 20 | 0xF_FFFF;
        let fired: alloc::vec::Vec<u64> =
            self.entries.range(..=deadline_max).map(|(&k, _)| k).collect();
        let mut rearms: alloc::vec::Vec<(u64, u64, TimerCallback)> = alloc::vec![];
        for key in fired {
            if let Some(e) = self.entries.remove(&key) {
                (e.callback)(e.id);
                if e.period_ns != 0 {
                    rearms.push((now_ns + e.period_ns, e.period_ns, e.callback));
                }
            }
        }
        for (dl, period, cb) in rearms {
            self.insert(dl, period, cb);
        }
    }
}

static WHEEL: Mutex<Option<Wheel>> = Mutex::new(None);

pub fn init() { *WHEEL.lock() = Some(Wheel::new()); }

/// Add a one-shot timer.  `callback` is called from the tick handler.
/// Returns a timer ID that can be passed to `cancel_timer`.
pub fn add_oneshot(deadline_ns: u64, cb: TimerCallback) -> u64 {
    WHEEL.lock().as_mut().map_or(0, |w| w.insert(deadline_ns, 0, cb))
}

/// Add a periodic timer with initial deadline and interval.
pub fn add_periodic(first_ns: u64, period_ns: u64, cb: TimerCallback) -> u64 {
    WHEEL.lock().as_mut().map_or(0, |w| w.insert(first_ns, period_ns, cb))
}

/// Cancel a timer by its ID.
pub fn cancel_timer(id: u64) {
    if let Some(w) = WHEEL.lock().as_mut() { w.cancel(id); }
}

/// Called from the tick handler (both arches) to expire due timers.
/// Must be called with interrupts disabled or from an IRQ context.
pub fn expire_timers() {
    let now = read_monotonic_ns();
    if let Some(w) = WHEEL.lock().as_mut() { w.expire(now); }
}

/// Kernel-internal helper: sleep until `deadline_ns` on CLOCK_MONOTONIC.
///
/// Used by drivers and kernel threads that already have an absolute
/// monotonic deadline.  Userspace syscalls use
/// `proc::nanosleep::sys_clock_nanosleep` instead.
///
/// Returns `Ok(())` on normal completion, `Err(-EINTR)` if interrupted.
pub fn clock_nanosleep(
    _clk_id: i32,
    _flags:  i32,
    req:     Timespec,
) -> Result<(), isize> {
    if !req.is_valid() { return Err(-22); }
    let delta_ns = req.to_ns();
    if delta_ns == 0 { return Ok(()); }
    // Delegate to the canonical blocking primitive.
    let ret = crate::proc::nanosleep::sleep_ns_internal(delta_ns);
    if ret < 0 { return Err(ret); }
    Ok(())
}

/// `nanosleep(2)` — CLOCK_MONOTONIC relative sleep (kernel helper).
pub fn nanosleep(req: Timespec) -> Result<(), isize> {
    clock_nanosleep(crate::time::clock::CLOCK_MONOTONIC, 0, req)
}

pub const ITIMER_REAL:    u32 = 0; // SIGALRM on expiry
pub const ITIMER_VIRTUAL: u32 = 1; // SIGVTALRM (user-time only)
pub const ITIMER_PROF:    u32 = 2; // SIGPROF   (user + kernel time)

/// The state of one interval timer.
#[derive(Clone, Copy, Default, Debug)]
pub struct ItimerVal {
    /// Interval for periodic re-arm.  Zero = one-shot.
    pub it_interval: Timespec,
    /// Time until next expiry.  Zero = disarmed.
    pub it_value: Timespec,
}

/// Per-process interval timer state (three timers).
pub struct ItimerState {
    pub timers:    [ItimerVal; 3],
    /// Kernel timer IDs (for cancellation).
    timer_ids:     [u64; 3],
    pub task_id:   u64,
}

impl ItimerState {
    pub fn new(task_id: u64) -> Self {
        ItimerState {
            timers:    [ItimerVal::default(); 3],
            timer_ids: [0; 3],
            task_id,
        }
    }

    /// `setitimer(2)` — arm or disarm timer `which`.
    pub fn set(&mut self, which: u32, new: ItimerVal) -> Result<ItimerVal, isize> {
        if which > ITIMER_PROF { return Err(-22); }
        let old = self.timers[which as usize];
        if self.timer_ids[which as usize] != 0 {
            cancel_timer(self.timer_ids[which as usize]);
            self.timer_ids[which as usize] = 0;
        }
        self.timers[which as usize] = new;
        if new.it_value.to_ns() != 0 {
            let deadline = read_monotonic_ns() + new.it_value.to_ns();
            let period   = new.it_interval.to_ns();
            let tid      = self.task_id;
            let w        = which;
            let id = if period != 0 {
                add_periodic(deadline, period, move |_| deliver_itimer_signal(tid, w))
            } else {
                add_oneshot(deadline, move |_| deliver_itimer_signal(tid, w))
            };
            self.timer_ids[which as usize] = id;
        }
        Ok(old)
    }

    /// `getitimer(2)` — read current timer value.
    pub fn get(&self, which: u32) -> Result<ItimerVal, isize> {
        if which > ITIMER_PROF { return Err(-22); }
        Ok(self.timers[which as usize])
    }
}

fn deliver_itimer_signal(task_id: u64, which: u32) {
    let sig = match which {
        ITIMER_REAL    => 14u32, // SIGALRM
        ITIMER_VIRTUAL => 26u32, // SIGVTALRM
        ITIMER_PROF    => 27u32, // SIGPROF
        _              => return,
    };
    crate::proc::signal::send_signal(task_id as usize, sig);
}
