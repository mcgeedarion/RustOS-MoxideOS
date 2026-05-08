//! cgroup pids controller.
//!
//! Knobs:
//!   pids.max      — maximum number of tasks; -1 = unlimited
//!   pids.current  — current task count (read-only)

use core::sync::atomic::{AtomicI64, Ordering};

pub struct PidsCg {
    pub max:     AtomicI64,
    pub current: AtomicI64,
}

impl Default for PidsCg {
    fn default() -> Self {
        PidsCg {
            max:     AtomicI64::new(-1),  // unlimited
            current: AtomicI64::new(0),
        }
    }
}

impl PidsCg {
    pub fn read(&self, knob: &str) -> Result<i64, isize> {
        match knob {
            "pids.max"     => Ok(self.max.load(Ordering::SeqCst)),
            "pids.current" => Ok(self.current.load(Ordering::SeqCst)),
            _ => Err(-2),
        }
    }

    pub fn write(&self, knob: &str, val: i64) -> Result<(), isize> {
        match knob {
            "pids.max" => {
                if val != -1 && val < 0 { return Err(-22); }
                self.max.store(val, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(-1), // read-only / unknown
        }
    }

    /// Called before clone/fork.  Returns false if at or over the limit.
    pub fn can_fork(&self) -> bool {
        let max = self.max.load(Ordering::SeqCst);
        if max == -1 { return true; }
        self.current.load(Ordering::SeqCst) < max
    }

    pub fn increment(&self) { self.current.fetch_add(1, Ordering::SeqCst); }
    pub fn decrement(&self) { self.current.fetch_sub(1, Ordering::SeqCst); }
}
