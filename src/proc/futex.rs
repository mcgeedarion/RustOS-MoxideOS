//! Futex subsystem — fast userspace mutex primitives.
//!
//! ## Ops implemented
//!   FUTEX_WAIT           (0)  — sleep if *uaddr == val
//!   FUTEX_WAKE           (1)  — wake up to val waiters
//!   FUTEX_REQUEUE        (3)  — wake n, requeue rest to uaddr2
//!   FUTEX_CMP_REQUEUE    (4)  — requeue only if *uaddr == val3
//!   FUTEX_WAIT_BITSET    (9)  — like WAIT but stores a bitset mask
//!   FUTEX_WAKE_BITSET    (10) — like WAKE but masks against waiter bitsets
//!
//!   FUTEX_PRIVATE_FLAG   (128) — we strip it (same-process optimisation;
//!                                 private futexes use tgid as the as_id,
//!                                 shared futexes would use a physical page
//!                                 frame number — not yet implemented).
//!
//! ## Futex key
//!   FutexKey = (as_id: usize, uaddr: usize)
//!
//!   For PRIVATE futexes (flag 128 set) as_id = tgid of the calling thread.
//!   For SHARED futexes as_id = tgid as well for now (same correctness for a
//!   single address space; true shared-memory futexes would use the PFN).
//!
//!   This prevents two threads in DIFFERENT processes that happen to map a
//!   futex word at the same virtual address from aliasing each other's wait
//!   queues — the bug that existed when the key was only `uaddr`.
//!
//! ## Lock ordering (MUST NOT be violated)
//!   WAITERS < scheduler::SCHED
//!
//! ## BITSET semantics
//!   FUTEX_BITSET_MATCH_ANY (0xFFFF_FFFF) is the default mask.
//!
//! ## REQUEUE semantics
//!   FUTEX_REQUEUE wakes `val` waiters from uaddr, then moves `val2` remaining
//!   waiters to uaddr2 (same as_id).  CMP_REQUEUE checks *uaddr == val3 first.
//!
//! ## Robust list (NR 273/274)
//!   set_robust_list / get_robust_list store a user-VA head pointer per thread.
//!   On exit, robust_list_on_exit walks the list and wakes one waiter per futex
//!   so that other threads blocking on a dead owner don't spin forever.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::proc::{scheduler, thread, process::State};
use crate::uaccess::{copy_from_user, copy_to_user};

// ── Constants ───────────────────────────────────────────────────────────────────────

pub const FUTEX_WAIT:         u32 = 0;
pub const FUTEX_WAKE:         u32 = 1;
pub const FUTEX_FD:           u32 = 2;  // obsolete; return ENOSYS
pub const FUTEX_REQUEUE:      u32 = 3;
pub const FUTEX_CMP_REQUEUE:  u32 = 4;
pub const FUTEX_WAKE_OP:      u32 = 5;  // not yet implemented
pub const FUTEX_LOCK_PI:      u32 = 6;  // PI not yet implemented
pub const FUTEX_UNLOCK_PI:    u32 = 7;
pub const FUTEX_TRYLOCK_PI:   u32 = 8;
pub const FUTEX_WAIT_BITSET:  u32 = 9;
pub const FUTEX_WAKE_BITSET:  u32 = 10;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_RT:     u32 = 256;

/// Match-any bitset: used by plain WAIT/WAKE (no bitset argument).
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

// ── Futex key ─────────────────────────────────────────────────────────────────────

/// A futex key is (address_space_id, virtual_address).
///
/// `as_id` is the TGID of the thread group that owns the address space.
/// Using the raw virtual address alone as the key would let two unrelated
/// processes that both have a futex word at e.g. 0x601000 alias each other's
/// wait queues — a correctness bug that would cause spurious wakeups.
///
/// For true shared-memory (POSIX) futexes `as_id` would be the physical
/// page frame number; that is not yet implemented.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FutexKey {
    as_id: usize,
    uaddr: usize,
}

impl FutexKey {
    fn new(uaddr: usize) -> Self {
        let pid  = scheduler::current_pid();
        let tgid = thread::tgid_of(pid);
        FutexKey { as_id: if tgid != 0 { tgid } else { pid }, uaddr }
    }

    /// Build a key for `uaddr` in the address space of `pid`.
    /// Used by REQUEUE to build a destination key in the same AS.
    fn for_pid(pid: usize, uaddr: usize) -> Self {
        let tgid = thread::tgid_of(pid);
        FutexKey { as_id: if tgid != 0 { tgid } else { pid }, uaddr }
    }
}

// ── Waiter struct ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Waiter {
    pid:    usize,
    bitset: u32,   // FUTEX_BITSET_MATCH_ANY for plain wait
}

/// Maps FutexKey → list of blocked (pid, bitset) pairs.
static WAITERS: Mutex<BTreeMap<FutexKey, Vec<Waiter>>> = Mutex::new(BTreeMap::new());

// ── Low-level wait / wake ───────────────────────────────────────────────────────

/// Block the current task on `addr` with a bitset mask.
///
/// Atomically checks `*(addr as *const u32) == expected` before queuing.
/// Returns `Err(-EAGAIN)` if the value has already changed.
/// Returns `Err(-EFAULT)` on bad user pointer.
pub fn futex_wait_bitset(addr: usize, expected: u32, bitset: u32) -> Result<(), isize> {
    if bitset == 0 { return Err(-22); } // EINVAL — empty bitset is meaningless

    let pid = scheduler::current_pid();
    let key = FutexKey::new(addr);

    // Step 1: check value AND register under WAITERS lock (atomic w.r.t. wakers).
    {
        let mut map = WAITERS.lock();
        let mut val_bytes = [0u8; 4];
        if copy_from_user(&mut val_bytes, addr).is_err() {
            return Err(-14); // EFAULT
        }
        let current = u32::from_ne_bytes(val_bytes);
        if current != expected {
            return Err(-11); // EAGAIN
        }
        map.entry(key).or_default().push(Waiter { pid, bitset });
    } // WAITERS released — safe to acquire scheduler lock

    // Step 2: mark self Blocked and reset RT budget if applicable.
    scheduler::block_current();

    // Step 3: yield — rescheduled by futex_wake_bitset / futex_wake_addr.
    scheduler::schedule();
    Ok(())
}

/// Plain wait — equivalent to WAIT_BITSET with MATCH_ANY.
pub fn futex_wait(addr: usize, expected: u32) -> Result<(), isize> {
    futex_wait_bitset(addr, expected, FUTEX_BITSET_MATCH_ANY)
}

/// Wake up to `count` tasks waiting on `addr` whose `(waiter.bitset & mask) != 0`.
/// Returns the number of tasks actually woken.
pub fn futex_wake_bitset(addr: usize, count: usize, mask: u32) -> usize {
    if mask == 0 { return 0; }

    let key = FutexKey::new(addr);

    let to_wake: Vec<usize> = {
        let mut map = WAITERS.lock();
        let list = match map.get_mut(&key) { Some(l) => l, None => return 0 };

        let mut woken_indices: Vec<usize> = Vec::new();
        for (i, w) in list.iter().enumerate() {
            if w.bitset & mask != 0 {
                woken_indices.push(i);
                if woken_indices.len() >= count { break; }
            }
        }
        // Remove in reverse order to preserve indices.
        let pids: Vec<usize> = woken_indices.iter().rev().map(|&i| {
            list.remove(i).pid
        }).collect();
        if list.is_empty() { map.remove(&key); }
        pids
    };

    let n = to_wake.len();
    for pid in to_wake { scheduler::wake_pid(pid); }
    n
}

/// Plain wake — equivalent to WAKE_BITSET with MATCH_ANY.
pub fn futex_wake_addr(addr: usize, count: usize) {
    futex_wake_bitset(addr, count, FUTEX_BITSET_MATCH_ANY);
}

// ── Requeue ──────────────────────────────────────────────────────────────────────

/// Move up to `requeue_count` waiters from `src` to `dst` without waking them.
/// Both keys are in the calling thread's address space.
/// Returns the number of waiters moved.
fn futex_requeue_inner(src: FutexKey, dst: FutexKey, requeue_count: usize) -> usize {
    let mut map = WAITERS.lock();
    let to_move: Vec<Waiter> = {
        let src_list = match map.get_mut(&src) { Some(l) => l, None => return 0 };
        let n = requeue_count.min(src_list.len());
        src_list.drain(..n).collect()
    };
    let n = to_move.len();
    if n > 0 {
        map.entry(dst).or_default().extend(to_move);
    }
    n
}

// ── Clear all waiters for a dying thread ─────────────────────────────────────────────

/// Remove `pid` from every futex wait queue.  Called by do_exit.
/// Needed so a killed/crashed thread doesn't leave stale waiter entries.
pub fn futex_clear_pid(pid: usize) {
    let mut map = WAITERS.lock();
    for list in map.values_mut() {
        list.retain(|w| w.pid != pid);
    }
    map.retain(|_, list| !list.is_empty());
}

// ── Robust list on-exit handler ───────────────────────────────────────────────────

/// Called by do_exit to process the robust futex list.
/// Walks the user-space linked list and performs FUTEX_WAKE on each owned futex
/// so that other threads blocking on it don't spin forever.
///
/// The robust list ABI (from `Documentation/locking/robust-futex-ABI.rst`):
///
///   struct robust_list_head {
///       struct robust_list *list.next;   // offset 0  — first held futex or &head.list
///       long               futex_offset; // offset 8  — byte offset from list entry to futex u32
///       struct robust_list *list_op_pending; // offset 16 — a futex being locked/unlocked
///   };
///
/// The futex u32 lives at `(list_entry_va as isize + futex_offset) as usize`.
/// The thread's TID is encoded in bits [30:0] of the futex word; bit 31 is
/// FUTEX_WAITERS.  We zero the word and wake one waiter.
const MAX_ROBUST: usize = 512;

pub fn robust_list_on_exit(pid: usize) {
    let (head_va, len) = match scheduler::with_proc(pid, |p| {
        (p.robust_list_head, p.robust_list_len)
    }) {
        Some(x) => x,
        None    => return,
    };
    if head_va == 0 { return; }
    if len != 24 && len != 16 { return; }

    let futex_offset: isize = {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, head_va + 8).is_err() { return; }
        i64::from_ne_bytes(buf) as isize
    };

    if len == 24 {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, head_va + 16).is_ok() {
            let pending_va = usize::from_ne_bytes(buf);
            if pending_va != 0 && pending_va != head_va {
                wake_robust_futex(pending_va, futex_offset, pid);
            }
        }
    }

    let mut cur_va: usize = {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, head_va).is_err() { return; }
        usize::from_ne_bytes(buf)
    };

    for _ in 0..MAX_ROBUST {
        if cur_va == 0 || cur_va == head_va { break; }
        let next_va: usize = {
            let mut buf = [0u8; 8];
            if copy_from_user(&mut buf, cur_va).is_err() { break; }
            usize::from_ne_bytes(buf)
        };
        wake_robust_futex(cur_va, futex_offset, pid);
        cur_va = next_va;
    }
}

/// Zero the futex word at `(entry_va + futex_offset)` and wake one waiter.
fn wake_robust_futex(entry_va: usize, futex_offset: isize, tid: usize) {
    let futex_va = (entry_va as isize).wrapping_add(futex_offset) as usize;
    if futex_va < 0x1000 || futex_va >= crate::uaccess::USER_SPACE_END { return; }

    let mut buf = [0u8; 4];
    if copy_from_user(&mut buf, futex_va).is_err() { return; }
    let word = u32::from_ne_bytes(buf);
    if (word & 0x3FFF_FFFF) as usize != tid { return; }

    let new_word: u32 = (word & 0x8000_0000) | 0x4000_0000;
    let _ = copy_to_user(futex_va, &new_word.to_ne_bytes());

    if word & 0x8000_0000 != 0 {
        // Use the tid's tgid so the key matches the waiter's key.
        let tgid = thread::tgid_of(tid);
        let as_id = if tgid != 0 { tgid } else { tid };
        let key = FutexKey { as_id, uaddr: futex_va };
        let to_wake: Vec<usize> = {
            let mut map = WAITERS.lock();
            let list = match map.get_mut(&key) { Some(l) => l, None => return };
            if list.is_empty() { return; }
            let w = list.remove(0).pid;
            if list.is_empty() { map.remove(&key); }
            alloc::vec![w]
        };
        for p in to_wake { scheduler::wake_pid(p); }
    }
}

// ── sys_futex [NR 202] ────────────────────────────────────────────────────────────

/// sys_futex(uaddr, op, val, timeout_or_val2, uaddr2, val3)
pub fn sys_futex(uaddr: usize, op: u32, val: u32,
                 timeout_or_val2: usize, uaddr2: usize, val3: u32) -> isize {

    if uaddr < 0x1000 || uaddr >= crate::uaccess::USER_SPACE_END {
        return -14; // EFAULT
    }

    let base_op = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_RT);

    match base_op {
        FUTEX_WAIT => {
            match futex_wait_bitset(uaddr, val, FUTEX_BITSET_MATCH_ANY) {
                Ok(_)  => 0,
                Err(e) => e,
            }
        }

        FUTEX_WAKE => {
            futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY) as isize
        }

        FUTEX_REQUEUE => {
            if uaddr2 < 0x1000 || uaddr2 >= crate::uaccess::USER_SPACE_END {
                return -14;
            }
            let val2   = timeout_or_val2 as u32;
            let pid    = scheduler::current_pid();
            let src    = FutexKey::for_pid(pid, uaddr);
            let dst    = FutexKey::for_pid(pid, uaddr2);
            let woken  = futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            let _req   = futex_requeue_inner(src, dst, val2 as usize);
            woken as isize
        }

        FUTEX_CMP_REQUEUE => {
            if uaddr2 < 0x1000 || uaddr2 >= crate::uaccess::USER_SPACE_END {
                return -14;
            }
            {
                let mut val_bytes = [0u8; 4];
                if copy_from_user(&mut val_bytes, uaddr).is_err() { return -14; }
                if u32::from_ne_bytes(val_bytes) != val3 { return -11; }
            }
            let val2   = timeout_or_val2 as u32;
            let pid    = scheduler::current_pid();
            let src    = FutexKey::for_pid(pid, uaddr);
            let dst    = FutexKey::for_pid(pid, uaddr2);
            let woken  = futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            let _req   = futex_requeue_inner(src, dst, val2 as usize);
            woken as isize
        }

        FUTEX_WAIT_BITSET => {
            if val3 == 0 { return -22; }
            match futex_wait_bitset(uaddr, val, val3) {
                Ok(_)  => 0,
                Err(e) => e,
            }
        }

        FUTEX_WAKE_BITSET => {
            if val3 == 0 { return -22; }
            futex_wake_bitset(uaddr, val as usize, val3) as isize
        }

        FUTEX_FD | FUTEX_WAKE_OP |
        FUTEX_LOCK_PI | FUTEX_UNLOCK_PI | FUTEX_TRYLOCK_PI => -38, // ENOSYS

        _ => -22, // EINVAL
    }
}

// ── sys_set_robust_list [NR 273] / sys_get_robust_list [NR 274] ──────────────────

/// set_robust_list(head, len)  [NR 273]
pub fn sys_set_robust_list(head: usize, len: usize) -> isize {
    if len != 16 && len != 24 { return -22; }
    let pid = scheduler::current_pid();
    if pid == 0 { return -1; }
    scheduler::with_proc_mut(pid, |p| {
        p.robust_list_head = head;
        p.robust_list_len  = len;
    });
    0
}

/// get_robust_list(tid, headp, lenp)  [NR 274]
pub fn sys_get_robust_list(tid: usize, headp: usize, lenp: usize) -> isize {
    let target = if tid == 0 { scheduler::current_pid() } else { tid };
    let (head, len) = match scheduler::with_proc(target, |p| {
        (p.robust_list_head, p.robust_list_len)
    }) {
        Some(x) => x,
        None    => return -3, // ESRCH
    };
    if copy_to_user(headp, &head.to_ne_bytes()).is_err() { return -14; }
    if copy_to_user(lenp,  &len.to_ne_bytes()).is_err()  { return -14; }
    0
}
