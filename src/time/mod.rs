//! Kernel timekeeping subsystem.
//!
//! ## Architecture
//!
//! ```
//! Clocksource (TSC / HPET / CLINT mtime)
//!        │  raw nanosecond counter
//!        ▼
//! time::clock  ── CLOCK_MONOTONIC  (monotone, never steps)
//!              ── CLOCK_BOOTTIME   (like MONOTONIC, includes suspend)
//!              ── CLOCK_REALTIME   (wall-clock, can be set/adjusted)
//!              ── CLOCK_TAI        (REALTIME + leap-second offset)
//!              ── CLOCK_PROCESS_CPUTIME_ID  (per-process CPU time)
//!              ── CLOCK_THREAD_CPUTIME_ID   (per-thread CPU time)
//!        │
//!        ▼
//! syscalls: clock_gettime / clock_settime / clock_getres /
//!           clock_nanosleep / nanosleep / gettimeofday / time
//! timers:   POSIX interval timers (itimer) + timerfd
//! ```
//!
//! ## Clocksource priority
//!
//! On x86_64: TSC (if invariant) > HPET > APIC timer.
//! On RISC-V:  CLINT `mtime` register (always invariant).
//!
//! The selected clocksource is recorded in `CLOCKSOURCE` at boot.

pub mod clint;
pub mod clock;
pub mod hpet;
pub mod timer;
pub mod timerfd;
pub mod tsc;

extern crate alloc;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use spin::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClockSource {
    Tsc,
    Hpet,
    ClintMtime,
    ApicTimer,
}

static CLOCKSOURCE: Mutex<ClockSource> = Mutex::new(ClockSource::ApicTimer);

pub fn set_clocksource(cs: ClockSource) {
    *CLOCKSOURCE.lock() = cs;
}
pub fn clocksource() -> ClockSource {
    *CLOCKSOURCE.lock()
}

pub const NSEC_PER_SEC: u64 = 1_000_000_000;
pub const NSEC_PER_MSEC: u64 = 1_000_000;
pub const NSEC_PER_USEC: u64 = 1_000;

/// `struct timespec` — matches Linux / POSIX layout exactly (`repr(C)`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    pub const ZERO: Self = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    pub fn from_ns(ns: u64) -> Self {
        Timespec {
            tv_sec: (ns / NSEC_PER_SEC) as i64,
            tv_nsec: (ns % NSEC_PER_SEC) as i64,
        }
    }

    pub fn to_ns(&self) -> u64 {
        (self.tv_sec as u64) * NSEC_PER_SEC + self.tv_nsec as u64
    }

    pub fn add_ns(&self, ns: u64) -> Self {
        Self::from_ns(self.to_ns().saturating_add(ns))
    }

    pub fn sub_ns(&self, ns: u64) -> Self {
        let total = self.to_ns();
        if ns >= total {
            Self::ZERO
        } else {
            Self::from_ns(total - ns)
        }
    }

    /// Normalise: bring tv_nsec into [0, 1_000_000_000).
    pub fn normalise(mut self) -> Self {
        while self.tv_nsec >= NSEC_PER_SEC as i64 {
            self.tv_sec += 1;
            self.tv_nsec -= NSEC_PER_SEC as i64;
        }
        while self.tv_nsec < 0 {
            self.tv_sec -= 1;
            self.tv_nsec += NSEC_PER_SEC as i64;
        }
        self
    }

    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NSEC_PER_SEC as i64
    }
}

/// `struct timeval` — used by `gettimeofday(2)` and select(2).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

impl Timeval {
    pub fn from_timespec(ts: Timespec) -> Self {
        Timeval {
            tv_sec: ts.tv_sec,
            tv_usec: ts.tv_nsec / 1000,
        }
    }
    pub fn to_timespec(&self) -> Timespec {
        Timespec {
            tv_sec: self.tv_sec,
            tv_nsec: self.tv_usec * 1000,
        }
    }
}

// Global monotonic nanosecond counter
// Incremented by the tick handler; read by all clock_gettime paths.

/// Nanoseconds since boot (CLOCK_MONOTONIC base).
/// Updated atomically from the timer interrupt; read lock-free via
/// the `read_monotonic_ns()` function below.
static MONO_NS: AtomicU64 = AtomicU64::new(0);

/// Nanoseconds since boot including suspend time (CLOCK_BOOTTIME).
static BOOT_NS: AtomicU64 = AtomicU64::new(0);

/// Wall-clock offset from MONO_NS in nanoseconds (may be negative).
/// CLOCK_REALTIME = MONO_NS + REALTIME_OFFSET.
static REALTIME_OFFSET_NS: AtomicI64 = AtomicI64::new(0);

/// Leap second offset in seconds added to CLOCK_REALTIME for CLOCK_TAI.
static TAI_OFFSET_S: AtomicI64 = AtomicI64::new(37); // current TAI-UTC as of 2024

/// Called from the tick interrupt handler (APIC / CLINT) every tick.
/// `elapsed_ns` is the number of nanoseconds since the last call.
pub fn tick_advance(elapsed_ns: u64) {
    MONO_NS.fetch_add(elapsed_ns, Ordering::Relaxed);
    BOOT_NS.fetch_add(elapsed_ns, Ordering::Relaxed);
    timer::expire_timers();
}

/// Called when the system resumes from S3 sleep.
/// `suspend_ns` is the estimated time the system spent suspended.
pub fn suspend_resume(suspend_ns: u64) {
    // BOOT_NS includes suspend; MONO_NS does not.
    BOOT_NS.fetch_add(suspend_ns, Ordering::Relaxed);
}

/// Read the monotonic nanosecond counter.
/// On TSC-equipped systems this is refined by `tsc::read_ns()`.
pub fn read_monotonic_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    if *CLOCKSOURCE.lock() == ClockSource::Tsc {
        return tsc::read_ns();
    }
    #[cfg(target_arch = "riscv64")]
    if *CLOCKSOURCE.lock() == ClockSource::ClintMtime {
        return clint::read_ns();
    }
    MONO_NS.load(Ordering::Relaxed)
}

pub fn read_boottime_ns() -> u64 {
    BOOT_NS.load(Ordering::Relaxed)
}

pub fn realtime_offset_ns() -> i64 {
    REALTIME_OFFSET_NS.load(Ordering::Relaxed)
}

pub fn set_realtime_offset_ns(offset: i64) {
    REALTIME_OFFSET_NS.store(offset, Ordering::SeqCst);
}

pub fn tai_offset_s() -> i64 {
    TAI_OFFSET_S.load(Ordering::Relaxed)
}

pub fn set_tai_offset_s(s: i64) {
    TAI_OFFSET_S.store(s, Ordering::SeqCst);
}

/// Initialise the timekeeping subsystem.
/// Must be called after the APIC / CLINT interrupt source is configured.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        if tsc::calibrate() {
            set_clocksource(ClockSource::Tsc);
        } else if hpet::init() {
            set_clocksource(ClockSource::Hpet);
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        if clint::init() {
            set_clocksource(ClockSource::ClintMtime);
        }
    }
    timer::init();
    timerfd::init();
}

// ===== GUESS: short aliases for new callers =====

/// GUESS: alias of `read_monotonic_ns`.
#[inline]
pub fn monotonic_ns() -> u64 {
    read_monotonic_ns()
}

/// GUESS: ns -> ms conversion of monotonic clock.
#[inline]
pub fn monotonic_ms() -> u64 {
    read_monotonic_ns() / 1_000_000
}

/// GUESS: ns -> us "ticks" (microseconds) — best fit for callers that count
/// "ticks" without a specific frequency contract.
#[inline]
pub fn monotonic_ticks() -> u64 {
    read_monotonic_ns() / 1_000
}
