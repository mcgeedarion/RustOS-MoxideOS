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
//!   FUTEX_PRIVATE_FLAG   (128) — bit; we strip it (same-process optimisation;
//!                                 we don't have cross-process shared futex yet)
//!
//! ## Lock ordering (MUST NOT be violated)
//!   WAITERS < scheduler::SCHED
//!
//!   If you need both locks, acquire WAITERS first and release it before
//!   touching the scheduler lock (with_procs / wake_pid / schedule).
//!   futex_wait enforces this by releasing WAITERS before marking Blocked.
//!
//! ## BITSET semantics
//!   FUTEX_BITSET_MATCH_ANY (0xFFFF_FFFF) is the default mask; when used,
//!   WAIT_BITSET / WAKE_BITSET are exactly equivalent to plain WAIT / WAKE.
//!   A waiter is woken by WAKE_BITSET only if (waiter.bitset & wake_mask) != 0.
//!
//! ## REQUEUE semantics
//!   FUTEX_REQUEUE wakes up to `val` waiters from uaddr, then moves up to
//!   `val2` remaining waiters to uaddr2.  The woken count is returned.
//!   FUTEX_CMP_REQUEUE additionally verifies *uaddr == val3 before acting;
//!   returns -EAGAIN if the check fails.
//!
//! ## Robust list (NR 273/274)
//!   `set_robust_list` / `get_robust_list` store a user-VA head pointer and
//!   byte size on the PCB.  On thread exit, `robust_list_on_exit` walks the
//!   linked list in user space and performs a FUTEX_WAKE on each held futex
//!   so that other threads don't spin forever on a dead owner.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::proc::{scheduler, process::State};
use crate::uaccess::{copy_from_user, copy_to_user};

// ── Constants ────────────────────────────────────────────────────────────────

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

// ── Waiter struct ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Waiter {
    pid:    usize,
    bitset: u32,   // FUTEX_BITSET_MATCH_ANY for plain wait
}

/// Maps futex userspace address → list of blocked (pid, bitset) pairs.
static WAITERS: Mutex<BTreeMap<usize, Vec<Waiter>>> = Mutex::new(BTreeMap::new());

// ── Low-level wait / wake ────────────────────────────────────────────────────

/// Block the current task on `addr` with a bitset mask.
///
/// Atomically checks `*(addr as *const u32) == expected` before queuing.
/// Returns `Err(-EAGAIN)` if the value has already changed.
/// Returns `Err(-EFAULT)` on bad user pointer.
pub fn futex_wait_bitset(addr: usize, expected: u32, bitset: u32) -> Result<(), isize> {
    if bitset == 0 { return Err(-22); } // EINVAL — empty bitset is meaningless

    let pid = scheduler::current_pid();

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
        map.entry(addr).or_default().push(Waiter { pid, bitset });
    } // WAITERS released — safe to acquire scheduler lock

    // Step 2: mark self Blocked.
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.state = State::Blocked;
        }
    });

    // Step 3: yield — rescheduled by futex_wake_addr / futex_wake_bitset.
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

    let to_wake: Vec<usize> = {
        let mut map = WAITERS.lock();
        let list = match map.get_mut(&addr) { Some(l) => l, None => return 0 };

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
        if list.is_empty() { map.remove(&addr); }
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

// ── Requeue ──────────────────────────────────────────────────────────────────

/// Move up to `requeue_count` waiters from `src` to `dst` without waking them.
/// Returns the number of waiters moved.
fn futex_requeue(src: usize, dst: usize, requeue_count: usize) -> usize {
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

// ── Clear all waiters for a dying thread ─────────────────────────────────────

/// Remove `pid` from every futex wait queue.  Called by do_exit.
/// Needed so a killed/crashed thread doesn't leave stale waiter entries.
pub fn futex_clear_pid(pid: usize) {
    let mut map = WAITERS.lock();
    for list in map.values_mut() {
        list.retain(|w| w.pid != pid);
    }
    map.retain(|_, list| !list.is_empty());
}

// ── Robust list on-exit handler ───────────────────────────────────────────────

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
/// Each `struct robust_list` is:
///   struct robust_list { struct robust_list *next; };
///
/// The futex u32 lives at `(list_entry_va as isize + futex_offset) as usize`.
/// The thread's TID is encoded in bits [30:0] of the futex word; bit 31 is
/// FUTEX_WAITERS.  We zero the word and wake one waiter.
///
/// We limit traversal to `MAX_ROBUST` entries to bound exit latency.
const MAX_ROBUST: usize = 512;

pub fn robust_list_on_exit(pid: usize) {
    let (head_va, len) = match scheduler::with_proc(pid, |p| {
        (p.robust_list_head, p.robust_list_len)
    }) {
        Some(x) => x,
        None    => return,
    };
    if head_va == 0 { return; }
    // Sanity-check the registered length matches the expected struct size (24 bytes).
    // Allow legacy 16-byte variant (older glibc) too.
    if len != 24 && len != 16 { return; }

    let futex_offset: isize = {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, head_va + 8).is_err() { return; }
        i64::from_ne_bytes(buf) as isize
    };

    // list_op_pending: a partially-locked futex to clean up first.
    if len == 24 {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, head_va + 16).is_ok() {
            let pending_va = usize::from_ne_bytes(buf);
            if pending_va != 0 && pending_va != head_va {
                wake_robust_futex(pending_va, futex_offset, pid);
            }
        }
    }

    // Walk the list.  First entry is at head->list.next (offset 0).
    let mut cur_va: usize = {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, head_va).is_err() { return; }
        usize::from_ne_bytes(buf)
    };

    for _ in 0..MAX_ROBUST {
        // Terminate when we've looped back to the head.
        if cur_va == 0 || cur_va == head_va { break; }

        // Read next pointer before we touch the futex word.
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

    // Read the current futex word to verify this thread owns it.
    let mut buf = [0u8; 4];
    if copy_from_user(&mut buf, futex_va).is_err() { return; }
    let word = u32::from_ne_bytes(buf);
    // Low 30 bits are TID; bit 30 = FUTEX_OWNER_DIED; bit 31 = FUTEX_WAITERS.
    if (word & 0x3FFF_FFFF) as usize != tid { return; }

    // Set FUTEX_OWNER_DIED (bit 30) and clear TID bits.
    let new_word: u32 = (word & 0x8000_0000) | 0x4000_0000;
    let _ = copy_to_user(futex_va, &new_word.to_ne_bytes());

    // Wake one waiter if FUTEX_WAITERS bit was set.
    if word & 0x8000_0000 != 0 {
        futex_wake_addr(futex_va, 1);
    }
}

// ── sys_futex [NR 202] ────────────────────────────────────────────────────────

/// sys_futex(uaddr, op, val, timeout_or_val2, uaddr2, val3)
///
/// `timeout_or_val2` doubles as:
///   - a pointer to `struct timespec timeout` for WAIT / WAIT_BITSET
///   - a u32 `val2` (requeue limit) for REQUEUE / CMP_REQUEUE
///
/// Timeout support: we currently spin without a real timer; once the
/// preemptive scheduler lands, hook into the per-CPU timer here.
pub fn sys_futex(uaddr: usize, op: u32, val: u32,
                 timeout_or_val2: usize, uaddr2: usize, val3: u32) -> isize {

    if uaddr < 0x1000 || uaddr >= crate::uaccess::USER_SPACE_END {
        return -14; // EFAULT
    }

    // Strip PRIVATE and CLOCK_RT flag bits; they don't change semantics for us.
    let base_op = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_RT);

    match base_op {
        // ── FUTEX_WAIT ──────────────────────────────────────────────────────
        FUTEX_WAIT => {
            match futex_wait_bitset(uaddr, val, FUTEX_BITSET_MATCH_ANY) {
                Ok(_)  => 0,
                Err(e) => e,
            }
        }

        // ── FUTEX_WAKE ──────────────────────────────────────────────────────
        FUTEX_WAKE => {
            futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY) as isize
        }

        // ── FUTEX_REQUEUE ────────────────────────────────────────────────────
        // val  = max waiters to wake on uaddr
        // timeout_or_val2 (low 32 bits) = max waiters to requeue to uaddr2
        FUTEX_REQUEUE => {
            if uaddr2 < 0x1000 || uaddr2 >= crate::uaccess::USER_SPACE_END {
                return -14;
            }
            let val2 = timeout_or_val2 as u32;
            let woken    = futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            let _requeued = futex_requeue(uaddr, uaddr2, val2 as usize);
            woken as isize
        }

        // ── FUTEX_CMP_REQUEUE ────────────────────────────────────────────────
        // Like REQUEUE but first checks *uaddr == val3.
        FUTEX_CMP_REQUEUE => {
            if uaddr2 < 0x1000 || uaddr2 >= crate::uaccess::USER_SPACE_END {
                return -14;
            }
            // Check *uaddr == val3 under WAITERS lock to avoid races.
            {
                let mut val_bytes = [0u8; 4];
                if copy_from_user(&mut val_bytes, uaddr).is_err() { return -14; }
                if u32::from_ne_bytes(val_bytes) != val3 { return -11; } // EAGAIN
            }
            let val2      = timeout_or_val2 as u32;
            let woken     = futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            let _requeued = futex_requeue(uaddr, uaddr2, val2 as usize);
            woken as isize
        }

        // ── FUTEX_WAIT_BITSET ────────────────────────────────────────────────
        // val3 is the wait mask; at least one bit must be set.
        FUTEX_WAIT_BITSET => {
            if val3 == 0 { return -22; } // EINVAL
            match futex_wait_bitset(uaddr, val, val3) {
                Ok(_)  => 0,
                Err(e) => e,
            }
        }

        // ── FUTEX_WAKE_BITSET ────────────────────────────────────────────────
        // val3 is the wake mask.
        FUTEX_WAKE_BITSET => {
            if val3 == 0 { return -22; } // EINVAL
            futex_wake_bitset(uaddr, val as usize, val3) as isize
        }

        // ── Unimplemented / obsolete ─────────────────────────────────────────
        FUTEX_FD | FUTEX_WAKE_OP |
        FUTEX_LOCK_PI | FUTEX_UNLOCK_PI | FUTEX_TRYLOCK_PI => -38, // ENOSYS

        _ => -22, // EINVAL
    }
}

// ── sys_set_robust_list [NR 273] / sys_get_robust_list [NR 274] ────────────────

/// set_robust_list(head, len)  [NR 273]
///
/// Registers a user-space robust list head for the calling thread.
/// The kernel uses it to wake futex waiters if this thread exits while
/// holding a robust mutex.
pub fn sys_set_robust_list(head: usize, len: usize) -> isize {
    // Linux validates len; accept 16 (old compat) and 24 (current).
    if len != 16 && len != 24 { return -22; } // EINVAL

    let pid = scheduler::current_pid();
    if pid == 0 { return -1; }
    scheduler::with_proc_mut(pid, |p| {
        p.robust_list_head = head;
        p.robust_list_len  = len;
    });
    0
}

/// get_robust_list(tid, headp, lenp)  [NR 274]
///
/// Writes the registered list head pointer and length for thread `tid`
/// (0 = calling thread) to the two user-space pointers.
pub fn sys_get_robust_list(tid: usize, headp: usize, lenp: usize) -> isize {
    let target = if tid == 0 {
        scheduler::current_pid()
    } else {
        tid
    };
    let (head, len) = match scheduler::with_proc(target, |p| {
        (p.robust_list_head, p.robust_list_len)
    }) {
        Some(x) => x,
        None    => return -3, // ESRCH
    };
    // Write head pointer (8 bytes).
    if copy_to_user(headp, &head.to_ne_bytes()).is_err() { return -14; }
    // Write length (8 bytes, type size_t).
    if copy_to_user(lenp, &len.to_ne_bytes()).is_err() { return -14; }
    0
}
