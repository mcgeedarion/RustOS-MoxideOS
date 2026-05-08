//! cgroup memory controller.
//!
//! Knobs:
//!   memory.limit_in_bytes   — hard limit (bytes); -1 = unlimited
//!   memory.usage_in_bytes   — current usage (read-only)
//!   memory.failcnt          — number of times the limit was hit
//!   memory.soft_limit_in_bytes — soft advisory limit (no enforcement)
//!   memory.oom_control      — 0 = OOM-kill enabled (default), 1 = disable

use core::sync::atomic::{AtomicI64, AtomicU64, AtomicBool, Ordering};

pub struct MemCg {
    pub limit_bytes:      AtomicI64,
    pub soft_limit_bytes: AtomicI64,
    pub usage_bytes:      AtomicI64,
    pub failcnt:          AtomicU64,
    pub oom_disabled:     AtomicBool,
}

impl Default for MemCg {
    fn default() -> Self {
        MemCg {
            limit_bytes:      AtomicI64::new(-1),
            soft_limit_bytes: AtomicI64::new(-1),
            usage_bytes:      AtomicI64::new(0),
            failcnt:          AtomicU64::new(0),
            oom_disabled:     AtomicBool::new(false),
        }
    }
}

impl MemCg {
    pub fn read(&self, knob: &str) -> Result<i64, isize> {
        match knob {
            "memory.limit_in_bytes"        => Ok(self.limit_bytes.load(Ordering::SeqCst)),
            "memory.soft_limit_in_bytes"   => Ok(self.soft_limit_bytes.load(Ordering::SeqCst)),
            "memory.usage_in_bytes"        => Ok(self.usage_bytes.load(Ordering::SeqCst)),
            "memory.failcnt"               => Ok(self.failcnt.load(Ordering::SeqCst) as i64),
            "memory.oom_control"           => Ok(self.oom_disabled.load(Ordering::SeqCst) as i64),
            _ => Err(-2),
        }
    }

    pub fn write(&self, knob: &str, val: i64) -> Result<(), isize> {
        match knob {
            "memory.limit_in_bytes" => {
                // -1 = unlimited, otherwise must be at least one page.
                if val != -1 && val < 4096 { return Err(-22); }
                self.limit_bytes.store(val, Ordering::SeqCst);
                Ok(())
            }
            "memory.soft_limit_in_bytes" => {
                self.soft_limit_bytes.store(val, Ordering::SeqCst);
                Ok(())
            }
            "memory.oom_control" => {
                self.oom_disabled.store(val != 0, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(-2),
        }
    }

    /// Charge `bytes` of memory to this cgroup.
    /// Returns ENOMEM (-12) if the hard limit is exceeded.
    pub fn charge(&self, bytes: u64) -> Result<(), isize> {
        let limit = self.limit_bytes.load(Ordering::SeqCst);
        let current = self.usage_bytes.fetch_add(bytes as i64, Ordering::SeqCst);
        if limit != -1 && current + bytes as i64 > limit {
            // Roll back the charge and record failure.
            self.usage_bytes.fetch_sub(bytes as i64, Ordering::SeqCst);
            self.failcnt.fetch_add(1, Ordering::SeqCst);
            if !self.oom_disabled.load(Ordering::SeqCst) {
                return Err(-12); // ENOMEM → triggers OOM path
            }
        }
        Ok(())
    }

    pub fn uncharge(&self, bytes: u64) {
        self.usage_bytes.fetch_sub(bytes as i64, Ordering::SeqCst);
    }

    /// Reset the fail counter (echo 0 > memory.failcnt).
    pub fn reset_failcnt(&self) { self.failcnt.store(0, Ordering::SeqCst); }
}
