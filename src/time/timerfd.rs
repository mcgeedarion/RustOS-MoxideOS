//! `timerfd` — timer file descriptors.
//!
//! Implements `timerfd_create(2)`, `timerfd_settime(2)`, `timerfd_gettime(2)`
//! and `read(2)` on timerfd fds.
//!
//! ## Linux UAPI
//!
//!   timerfd_create(clk_id, flags)  → fd
//!     flags: TFD_NONBLOCK (0x800) | TFD_CLOEXEC (0x80000)
//!   timerfd_settime(fd, flags, new_value, old_value)  → 0
//!     flags: TFD_TIMER_ABSTIME (1) | TFD_TIMER_CANCEL_ON_SET (2)
//!   timerfd_gettime(fd, curr_value)  → 0
//!   read(fd, buf[8])  → 8  (u64 LE expiration count since last read)
//!
//! ## Storage
//!
//! Each `TimerFd` is identified by a `TimerFdId` and stored in a global
//! `BTreeMap`.  The fd table in `proc::Task` holds `TimerFdId` values;
//! the VFS open-file dispatch calls into this module.

extern crate alloc;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::time::clock;
use crate::time::timer::{add_oneshot, add_periodic, cancel_timer, TIMER_ABSTIME};
use crate::time::{read_monotonic_ns, Timespec};

// ── Flags ──────────────────────────────────────────────────────────────────────────

pub const TFD_NONBLOCK: i32 = 0x0000_0800;
pub const TFD_CLOEXEC: i32 = 0x0008_0000;
pub const TFD_TIMER_ABSTIME: i32 = 1;
pub const TFD_TIMER_CANCEL_ON_SET: i32 = 2;

// ── TimerFd object ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct TimerFdId(pub u64);

static NEXT_TIMERFD_ID: AtomicU64 = AtomicU64::new(1);

pub struct TimerFd {
    pub id: TimerFdId,
    pub clk_id: i32,
    pub nonblock: bool,
    pub cloexec: bool,
    /// Number of expirations since last read.
    expirations: AtomicU64,
    /// Kernel timer ID (0 = not armed).
    timer_id: AtomicU64,
    /// Current itimerspec (it_value = time to next expiry).
    current: Mutex<ItimerSpec>,
}

/// `struct itimerspec` — used by timerfd_settime / gettime.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ItimerSpec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

impl TimerFd {
    fn new(clk_id: i32, flags: i32) -> Self {
        TimerFd {
            id: TimerFdId(NEXT_TIMERFD_ID.fetch_add(1, Ordering::SeqCst)),
            clk_id,
            nonblock: flags & TFD_NONBLOCK != 0,
            cloexec: flags & TFD_CLOEXEC != 0,
            expirations: AtomicU64::new(0),
            timer_id: AtomicU64::new(0),
            current: Mutex::new(ItimerSpec::default()),
        }
    }

    /// Arm or disarm the timer.
    /// Returns previous `ItimerSpec`, or EINVAL on bad input.
    pub fn settime(&self, flags: i32, new: ItimerSpec) -> Result<ItimerSpec, isize> {
        if !new.it_value.is_valid() || !new.it_interval.is_valid() {
            return Err(-22);
        }
        // Disarm existing timer.
        let old_id = self.timer_id.swap(0, Ordering::SeqCst);
        if old_id != 0 {
            cancel_timer(old_id);
        }
        let old_spec = *self.current.lock();
        *self.current.lock() = new;

        if new.it_value.to_ns() == 0 {
            return Ok(old_spec); // disarm
        }

        let deadline_ns = if flags & TFD_TIMER_ABSTIME != 0 {
            // Absolute deadline on `self.clk_id`.
            let now_ns = clock::clock_gettime(self.clk_id)
                .map(|t| t.to_ns())
                .unwrap_or(0);
            let req_ns = new.it_value.to_ns();
            if req_ns <= now_ns {
                return Ok(old_spec);
            }
            read_monotonic_ns() + (req_ns - now_ns)
        } else {
            read_monotonic_ns() + new.it_value.to_ns()
        };

        let tfd_id = self.id.0;
        let period = new.it_interval.to_ns();
        let new_timer = if period != 0 {
            add_periodic(deadline_ns, period, move |_| timerfd_expire(tfd_id))
        } else {
            add_oneshot(deadline_ns, move |_| timerfd_expire(tfd_id))
        };
        self.timer_id.store(new_timer, Ordering::SeqCst);
        Ok(old_spec)
    }

    /// Returns the current armed state.
    pub fn gettime(&self) -> ItimerSpec {
        let spec = *self.current.lock();
        // If armed, compute remaining time.
        let timer_id = self.timer_id.load(Ordering::Relaxed);
        if timer_id == 0 {
            return ItimerSpec {
                it_interval: spec.it_interval,
                it_value: Timespec::ZERO,
            };
        }
        spec
    }

    /// `read(fd, buf[8])` — drain expiration count as little-endian u64.
    /// Blocks (or returns EAGAIN if O_NONBLOCK) until at least one expiration.
    pub fn read(&self) -> Result<u64, isize> {
        loop {
            let count = self.expirations.swap(0, Ordering::SeqCst);
            if count > 0 {
                return Ok(count);
            }
            if self.nonblock {
                return Err(-11);
            } // EAGAIN
            core::hint::spin_loop();
        }
    }
}

/// Called from the timer wheel when a timerfd's deadline fires.
fn timerfd_expire(id: u64) {
    let reg = REGISTRY.lock();
    if let Some(r) = reg.as_ref() {
        if let Some(tfd) = r.get(&TimerFdId(id)) {
            tfd.expirations.fetch_add(1, Ordering::SeqCst);
            // Wake any task blocked in read(fd).
            // crate::proc::wakeup_fd_readers(tfd.id.0);
        }
    }
}

// ── Global registry ────────────────────────────────────────────────────────────────

static REGISTRY: Mutex<Option<BTreeMap<TimerFdId, TimerFd>>> = Mutex::new(None);

pub fn init() {
    *REGISTRY.lock() = Some(BTreeMap::new());
}

/// `timerfd_create(clk_id, flags)` — allocates a new TimerFd.
/// Returns the `TimerFdId` (the fd table entry maps fd → TimerFdId).
pub fn timerfd_create(clk_id: i32, flags: i32) -> Result<TimerFdId, isize> {
    match clk_id {
        clock::CLOCK_REALTIME
        | clock::CLOCK_REALTIME_ALARM
        | clock::CLOCK_MONOTONIC
        | clock::CLOCK_BOOTTIME
        | clock::CLOCK_BOOTTIME_ALARM => {}
        _ => return Err(-22),
    }
    let tfd = TimerFd::new(clk_id, flags);
    let id = tfd.id;
    REGISTRY.lock().as_mut().ok_or(-1isize)?.insert(id, tfd);
    Ok(id)
}

/// `timerfd_settime(fd, flags, new, old)` via `TimerFdId`.
pub fn timerfd_settime(id: TimerFdId, flags: i32, new: ItimerSpec) -> Result<ItimerSpec, isize> {
    let reg = REGISTRY.lock();
    let tfd = reg.as_ref().ok_or(-1isize)?.get(&id).ok_or(-9isize)?; // EBADF
    tfd.settime(flags, new)
}

/// `timerfd_gettime(fd)` via `TimerFdId`.
pub fn timerfd_gettime(id: TimerFdId) -> Result<ItimerSpec, isize> {
    let reg = REGISTRY.lock();
    let tfd = reg.as_ref().ok_or(-1isize)?.get(&id).ok_or(-9isize)?;
    Ok(tfd.gettime())
}

/// `read(fd)` on a timerfd.
pub fn timerfd_read(id: TimerFdId) -> Result<u64, isize> {
    let reg = REGISTRY.lock();
    let tfd = reg.as_ref().ok_or(-1isize)?.get(&id).ok_or(-9isize)?;
    tfd.read()
}

/// Destroy a timerfd when its fd is closed.
pub fn timerfd_close(id: TimerFdId) {
    let mut reg = REGISTRY.lock();
    if let Some(r) = reg.as_mut() {
        if let Some(tfd) = r.remove(&id) {
            let tid = tfd.timer_id.load(Ordering::Relaxed);
            if tid != 0 {
                cancel_timer(tid);
            }
        }
    }
}
