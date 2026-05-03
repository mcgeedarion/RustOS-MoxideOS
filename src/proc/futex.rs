//! Futex subsystem — fast userspace mutex primitives.
//!
//! futex_wake_addr(addr, count) wakes up to `count` tasks sleeping on `addr`.
//! Called by exit_clear_child_tid and by sys_futex (NR 202).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

/// Maps futex userspace address → list of blocked pids.
static WAITERS: Mutex<BTreeMap<usize, Vec<usize>>> = Mutex::new(BTreeMap::new());

/// Block the current task on `addr` until woken.
pub fn futex_wait(addr: usize) {
    let pid = crate::proc::scheduler::current_pid();
    WAITERS.lock().entry(addr).or_default().push(pid);
    {
        let procs = crate::proc::scheduler::procs_lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.state = crate::proc::process::State::Blocked;
        }
        crate::proc::scheduler::procs_unlock();
    }
    crate::proc::scheduler::schedule();
}

/// Wake up to `count` tasks waiting on `addr`.
pub fn futex_wake_addr(addr: usize, count: usize) {
    let to_wake: Vec<usize> = {
        let mut map = WAITERS.lock();
        let list = match map.get_mut(&addr) { Some(l) => l, None => return };
        let n = count.min(list.len());
        list.drain(..n).collect()
    };
    for pid in to_wake {
        crate::proc::scheduler::wake_pid(pid);
    }
}

/// sys_futex(uaddr, op, val, ...) [NR 202] — FUTEX_WAIT / FUTEX_WAKE.
pub fn sys_futex(uaddr: usize, op: u32, val: u32,
                 _timeout: usize, _uaddr2: usize, _val3: u32) -> isize {
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAKE: u32 = 1;
    match op & 0xF {
        FUTEX_WAIT => {
            if uaddr < 0x1000 { return -14; }
            let current = unsafe { (uaddr as *const u32).read_volatile() };
            if current != val { return -11; } // EAGAIN
            futex_wait(uaddr);
            0
        }
        FUTEX_WAKE => {
            futex_wake_addr(uaddr, val as usize);
            0
        }
        _ => -38,
    }
}
