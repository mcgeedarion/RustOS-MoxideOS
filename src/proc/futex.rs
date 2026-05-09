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
//!   FUTEX_PRIVATE_FLAG   (128) — stripped (private futexes use tgid as as_id).
//!
//! ## Bug fixes in this revision
//!
//! ### futex_wait_bitset: double schedule() call
//!   `block_current()` already ends with `schedule()`. The extra
//!   `scheduler::schedule()` after it caused the waiter to yield a second
//!   time on each wakeup, potentially skipping the return to userspace.
//!   Removed the redundant call.
//!
//! ### wake_robust_futex: preserved FUTEX_WAITERS bit in written word
//!   The new futex word written on owner death should be `FUTEX_OWNER_DIED`
//!   only (0x4000_0000), with the TID and FUTEX_WAITERS bits cleared.
//!   The old code kept `word & 0x8000_0000` (FUTEX_WAITERS) in the new word,
//!   making other waiters see a still-held futex after the owner died.
//!
//! ### sys_get_robust_list: copy_to_user return type mismatch
//!   `copy_to_user` returns `bool`; `.is_err()` is not valid on bool.
//!   Fixed to `!copy_to_user(...)`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::proc::{scheduler, thread, process::State};
use crate::uaccess::{copy_from_user, copy_to_user};

// ── Constants ───────────────────────────────────────────────────────────────────

pub const FUTEX_WAIT:         u32 = 0;
pub const FUTEX_WAKE:         u32 = 1;
pub const FUTEX_FD:           u32 = 2;
pub const FUTEX_REQUEUE:      u32 = 3;
pub const FUTEX_CMP_REQUEUE:  u32 = 4;
pub const FUTEX_WAKE_OP:      u32 = 5;
pub const FUTEX_LOCK_PI:      u32 = 6;
pub const FUTEX_UNLOCK_PI:    u32 = 7;
pub const FUTEX_TRYLOCK_PI:   u32 = 8;
pub const FUTEX_WAIT_BITSET:  u32 = 9;
pub const FUTEX_WAKE_BITSET:  u32 = 10;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_RT:     u32 = 256;

pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

// Robust-list futex word bit definitions.
const FUTEX_WAITERS:    u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK:   u32 = 0x3FFF_FFFF;

// ── Futex key ───────────────────────────────────────────────────────────────────

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

    fn for_pid(pid: usize, uaddr: usize) -> Self {
        let tgid = thread::tgid_of(pid);
        FutexKey { as_id: if tgid != 0 { tgid } else { pid }, uaddr }
    }
}

// ── Waiter struct ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Waiter {
    pid:    usize,
    bitset: u32,
}

static WAITERS: Mutex<BTreeMap<FutexKey, Vec<Waiter>>> = Mutex::new(BTreeMap::new());

// ── Low-level wait / wake ────────────────────────────────────────────────────────

/// Block the current task on `addr` with a bitset mask.
///
/// Atomically checks `*(addr as *const u32) == expected` before queuing.
/// Returns `Err(-EAGAIN)` if the value has already changed.
pub fn futex_wait_bitset(addr: usize, expected: u32, bitset: u32) -> Result<(), isize> {
    if bitset == 0 { return Err(-22); }

    let pid = scheduler::current_pid();
    let key = FutexKey::new(addr);

    // Atomically read+compare+enqueue under WAITERS lock.
    {
        let mut map = WAITERS.lock();
        let mut val_bytes = [0u8; 4];
        if copy_from_user(&mut val_bytes, addr).is_err() {
            return Err(-14);
        }
        let current = u32::from_ne_bytes(val_bytes);
        if current != expected {
            return Err(-11); // EAGAIN
        }
        map.entry(key).or_default().push(Waiter { pid, bitset });
    }

    // FIX: block_current() already calls schedule() internally.
    // The old code called schedule() again after block_current(), causing
    // the thread to yield a second time after being woken, delaying return.
    scheduler::block_current();
    // Returns here when futex_wake_bitset calls wake_pid() on us.
    Ok(())
}

pub fn futex_wait(addr: usize, expected: u32) -> Result<(), isize> {
    futex_wait_bitset(addr, expected, FUTEX_BITSET_MATCH_ANY)
}

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

pub fn futex_wake_addr(addr: usize, count: usize) {
    futex_wake_bitset(addr, count, FUTEX_BITSET_MATCH_ANY);
}

// ── Requeue ────────────────────────────────────────────────────────────────────

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

// ── Clear all waiters for a dying thread ────────────────────────────────────────

pub fn futex_clear_pid(pid: usize) {
    let mut map = WAITERS.lock();
    for list in map.values_mut() {
        list.retain(|w| w.pid != pid);
    }
    map.retain(|_, list| !list.is_empty());
}

// ── Robust list on-exit handler ──────────────────────────────────────────────────

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
///
/// FIX: The written value must be `FUTEX_OWNER_DIED` only (0x4000_0000),
/// with both the TID bits AND the FUTEX_WAITERS bit cleared.  The old code
/// preserved `word & FUTEX_WAITERS` in the new word, making the futex look
/// still-contested after owner death.  Other threads would see FUTEX_WAITERS
/// set but no owner TID, and could spin or deadlock.
fn wake_robust_futex(entry_va: usize, futex_offset: isize, tid: usize) {
    let futex_va = (entry_va as isize).wrapping_add(futex_offset) as usize;
    if futex_va < 0x1000 || futex_va >= crate::uaccess::USER_SPACE_END { return; }

    let mut buf = [0u8; 4];
    if copy_from_user(&mut buf, futex_va).is_err() { return; }
    let word = u32::from_ne_bytes(buf);

    // Only process futex words owned by this dying thread.
    if (word & FUTEX_TID_MASK) as usize != tid { return; }

    let had_waiters = word & FUTEX_WAITERS != 0;

    // Write FUTEX_OWNER_DIED with TID=0 and FUTEX_WAITERS=0.
    // A waiting thread will see FUTEX_OWNER_DIED and handle recovery.
    let new_word: u32 = FUTEX_OWNER_DIED;
    let _ = copy_to_user(futex_va, &new_word.to_ne_bytes());

    if had_waiters {
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

// ── sys_futex [NR 202] ─────────────────────────────────────────────────────────────

pub fn sys_futex(uaddr: usize, op: u32, val: u32,
                 timeout_or_val2: usize, uaddr2: usize, val3: u32) -> isize {

    if uaddr < 0x1000 || uaddr >= crate::uaccess::USER_SPACE_END {
        return -14;
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
            let val2  = timeout_or_val2 as u32;
            let pid   = scheduler::current_pid();
            let src   = FutexKey::for_pid(pid, uaddr);
            let dst   = FutexKey::for_pid(pid, uaddr2);
            let woken = futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            let _req  = futex_requeue_inner(src, dst, val2 as usize);
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
            let val2  = timeout_or_val2 as u32;
            let pid   = scheduler::current_pid();
            let src   = FutexKey::for_pid(pid, uaddr);
            let dst   = FutexKey::for_pid(pid, uaddr2);
            let woken = futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            let _req  = futex_requeue_inner(src, dst, val2 as usize);
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
        FUTEX_LOCK_PI | FUTEX_UNLOCK_PI | FUTEX_TRYLOCK_PI => -38,

        _ => -22,
    }
}

// ── sys_set_robust_list / sys_get_robust_list ────────────────────────────────────

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

pub fn sys_get_robust_list(tid: usize, headp: usize, lenp: usize) -> isize {
    let target = if tid == 0 { scheduler::current_pid() } else { tid };
    let (head, len) = match scheduler::with_proc(target, |p| {
        (p.robust_list_head, p.robust_list_len)
    }) {
        Some(x) => x,
        None    => return -3,
    };
    // FIX: copy_to_user returns bool, not Result.
    if !copy_to_user(headp, &head.to_ne_bytes()) { return -14; }
    if !copy_to_user(lenp,  &len.to_ne_bytes())  { return -14; }
    0
}
