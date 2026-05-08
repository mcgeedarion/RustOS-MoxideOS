//! cgroup cpu controller.
//!
//! Knobs:
//!   cpu.shares            — weight 1..10000, default 1024
//!   cpu.cfs_period_us     — CFS quota period in µs (100000 = 100 ms)
//!   cpu.cfs_quota_us      — CFS quota in µs per period  (-1 = unlimited)
//!   cpu.stat              — read-only: nr_throttled, throttled_time

use spin::Mutex;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};

pub struct CpuCg {
    pub shares:        AtomicI64,
    pub cfs_period_us: AtomicI64,
    pub cfs_quota_us:  AtomicI64,
    /// Read-only accounting.
    pub nr_throttled:  AtomicU64,
    pub throttled_us:  AtomicU64,
}

impl Default for CpuCg {
    fn default() -> Self {
        CpuCg {
            shares:        AtomicI64::new(1024),
            cfs_period_us: AtomicI64::new(100_000),
            cfs_quota_us:  AtomicI64::new(-1),
            nr_throttled:  AtomicU64::new(0),
            throttled_us:  AtomicU64::new(0),
        }
    }
}

impl CpuCg {
    pub fn read(&self, knob: &str) -> Result<i64, isize> {
        match knob {
            "cpu.shares"        => Ok(self.shares.load(Ordering::SeqCst)),
            "cpu.cfs_period_us" => Ok(self.cfs_period_us.load(Ordering::SeqCst)),
            "cpu.cfs_quota_us"  => Ok(self.cfs_quota_us.load(Ordering::SeqCst)),
            "cpu.stat.nr_throttled"  => Ok(self.nr_throttled.load(Ordering::SeqCst) as i64),
            "cpu.stat.throttled_time"=> Ok(self.throttled_us.load(Ordering::SeqCst) as i64),
            _ => Err(-2), // ENOENT
        }
    }

    pub fn write(&self, knob: &str, val: i64) -> Result<(), isize> {
        match knob {
            "cpu.shares" => {
                if val < 1 || val > 10_000 { return Err(-22); }
                self.shares.store(val, Ordering::SeqCst);
                Ok(())
            }
            "cpu.cfs_period_us" => {
                if val < 1_000 || val > 1_000_000 { return Err(-22); }
                self.cfs_period_us.store(val, Ordering::SeqCst);
                Ok(())
            }
            "cpu.cfs_quota_us" => {
                // -1 = unlimited; otherwise must be ≥ 1000 µs.
                if val != -1 && val < 1_000 { return Err(-22); }
                self.cfs_quota_us.store(val, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(-2),
        }
    }

    /// Called from the scheduler when this cgroup's quota is exceeded.
    pub fn throttle(&self, duration_us: u64) {
        self.nr_throttled.fetch_add(1, Ordering::SeqCst);
        self.throttled_us.fetch_add(duration_us, Ordering::SeqCst);
    }

    /// Returns the CFS quota budget remaining in this period in µs,
    /// or i64::MAX if unlimited.
    pub fn quota_remaining(&self, used_us: u64) -> i64 {
        let quota = self.cfs_quota_us.load(Ordering::SeqCst);
        if quota == -1 { return i64::MAX; }
        quota - used_us as i64
    }
}
