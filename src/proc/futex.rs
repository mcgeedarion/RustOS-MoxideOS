//! Futex subsystem — fast userspace mutex primitives.
//!
//! futex_wake_addr(addr, count) wakes up to `count` tasks sleeping on `addr`.
//! Called by exit clear_child_tid and by sys_futex (NR 202).
//!
//! ## Lock ordering (MUST NOT be violated)
//!
//!   WAITERS < scheduler::SCHED
//!
//! i.e. if you need both, acquire WAITERS first and release it before
//! touching the scheduler lock (with_procs / wake_pid / schedule).
//! futex_wait enforces this by releasing WAITERS before calling with_procs.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::proc::{scheduler, process::State};
use crate::uaccess::copy_from_user;

/// Maps futex userspace address → list of blocked pids.
static WAITERS: Mutex<BTreeMap<usize, Vec<usize>>> = Mutex::new(BTreeMap::new());

/// Block the current task on `addr`.
///
/// Atomically checks that `*(addr as *const u32) == expected` before
/// blocking; returns `Err(-11)` (EAGAIN) if the value has already changed.
/// This closes the TOCTOU window between the caller's read and the
/// waiter registration.
pub fn futex_wait(addr: usize, expected: u32) -> Result<(), isize> {
    let pid = scheduler::current_pid();

    // Step 1: check value AND register under WAITERS lock (atomic w.r.t. wakers).
    {
        let mut map = WAITERS.lock();
        // Re-read the futex word while holding WAITERS so a concurrent
        // futex_wake_addr cannot slip between our read and our enqueue.
        // Use copy_from_user instead of read_volatile for consistency
        // with the validated uaccess path.
        let mut val_bytes = [0u8; 4];
        if copy_from_user(&mut val_bytes, addr).is_err() {
            return Err(-14); // EFAULT
        }
        let current = u32::from_ne_bytes(val_bytes);
        if current != expected {
            return Err(-11); // EAGAIN: value changed before we could sleep
        }
        map.entry(addr).or_default().push(pid);
    } // WAITERS lock released here — safe to acquire scheduler lock below

    // Step 2: mark self Blocked (scheduler lock; WAITERS not held — no inversion).
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.state = State::Blocked;
        }
    });

    // Step 3: yield. We will be rescheduled by futex_wake_addr → wake_pid.
    scheduler::schedule();
    Ok(())
}

/// Wake up to `count` tasks waiting on `addr`.
/// Safe to call from any context; does not hold the scheduler lock.
pub fn futex_wake_addr(addr: usize, count: usize) {
    let to_wake: Vec<usize> = {
        let mut map = WAITERS.lock();
        let list = match map.get_mut(&addr) { Some(l) => l, None => return };
        let n = count.min(list.len());
        list.drain(..n).collect()
    };

    for pid in to_wake {
        scheduler::wake_pid(pid);
    }
}

/// sys_futex(uaddr, op, val, timeout, uaddr2, val3) [NR 202]
/// Handles FUTEX_WAIT (0) and FUTEX_WAKE (1).
/// Private variants (op | 128) are handled by the op & 0x7F mask.
pub fn sys_futex(uaddr: usize, op: u32, val: u32,
                 _timeout: usize, _uaddr2: usize, _val3: u32) -> isize {
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAKE: u32 = 1;

    if uaddr < 0x1000 || uaddr >= crate::uaccess::USER_SPACE_END {
        return -14; // EFAULT
    }

    match op & 0x7F {
        FUTEX_WAIT => {
            match futex_wait(uaddr, val) {
                Ok(_)       => 0,
                Err(eagain) => eagain,
            }
        }
        FUTEX_WAKE => {
            futex_wake_addr(uaddr, val as usize);
            0
        }
        _ => -38, // ENOSYS
    }
}
