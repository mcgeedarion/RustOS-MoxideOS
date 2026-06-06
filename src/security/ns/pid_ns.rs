//! PID namespace.
//!
//! Each `PidNs` owns an independent PID allocator starting at 1.
//! A process has one PID *per namespace* in its ancestry chain; we store
//! only the innermost (leaf) namespace PID here.  The kernel-global PID
//! used for scheduling lives in `proc::Task` and is unchanged.
//!
//! ## Linux syscall semantics modelled
//!
//!   getpid(2) / getppid(2)  — return pid within the calling process's PidNs
//!   clone(CLONE_NEWPID)     — first child gets PID 1 in the new ns
//!   /proc/sys/kernel/pid_max — capped at PID_MAX per namespace

extern crate alloc;
use crate::security::ns::alloc_ns_id;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub const PID_MAX: u32 = 4_194_304; // 2^22, Linux default

/// A single PID namespace.
pub struct PidNs {
    pub id: u64,
    /// The level in the hierarchy (init ns = 0).
    pub level: u32,
    next_pid: AtomicU32,
    /// Map of ns-local PID → kernel task-id for /proc enumeration.
    pid_map: Mutex<BTreeMap<u32, u64>>,
}

impl PidNs {
    pub fn new_init() -> Self {
        PidNs {
            id: alloc_ns_id(),
            level: 0,
            next_pid: AtomicU32::new(1),
            pid_map: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn new_child() -> Self {
        PidNs {
            id: alloc_ns_id(),
            level: 0, // caller can increment
            next_pid: AtomicU32::new(1),
            pid_map: Mutex::new(BTreeMap::new()),
        }
    }

    /// Allocate the next available PID in this namespace.
    /// Returns `Err` if the namespace is exhausted.
    pub fn alloc_pid(&self, task_id: u64) -> Result<u32, &'static str> {
        // Simple linear scan — good enough for a research kernel.
        loop {
            let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
            if pid >= PID_MAX {
                return Err("pid namespace exhausted");
            }
            let mut map = self.pid_map.lock();
            if !map.contains_key(&pid) {
                map.insert(pid, task_id);
                return Ok(pid);
            }
        }
    }

    /// Release a PID back to the namespace (on task exit).
    pub fn free_pid(&self, pid: u32) {
        self.pid_map.lock().remove(&pid);
    }

    /// Look up the kernel task-id for a namespace-local PID.
    pub fn task_id_for(&self, pid: u32) -> Option<u64> {
        self.pid_map.lock().get(&pid).copied()
    }

    /// Iterator-friendly snapshot of all (ns_pid, task_id) pairs.
    pub fn snapshot(&self) -> alloc::vec::Vec<(u32, u64)> {
        self.pid_map.lock().iter().map(|(&p, &t)| (p, t)).collect()
    }

    /// True if no tasks are registered (namespace can be reaped).
    pub fn is_empty(&self) -> bool {
        self.pid_map.lock().is_empty()
    }
}
