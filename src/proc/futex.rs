//! Futex subsystem — fast userspace mutex primitives.
//!
//! ## Ops implemented
//!   FUTEX_WAIT           (0)  — sleep if *uaddr == val; optional timespec timeout
//!   FUTEX_WAKE           (1)  — wake up to val waiters
//!   FUTEX_REQUEUE        (3)  — wake n, requeue rest to uaddr2
//!   FUTEX_CMP_REQUEUE    (4)  — requeue only if *uaddr == val3
//!   FUTEX_WAIT_BITSET    (9)  — like WAIT but stores a bitset mask
//!   FUTEX_WAKE_BITSET    (10) — like WAKE but masks against waiter bitsets
//!   FUTEX_LOCK_PI        (6)  — acquire PI-aware mutex
//!   FUTEX_UNLOCK_PI      (7)  — release PI-aware mutex; restore base priority
//!   FUTEX_TRYLOCK_PI     (8)  — non-blocking PI lock attempt
//!
//!   FUTEX_PRIVATE_FLAG   (128) — stripped (private futexes use tgid as as_id).
//!
//! ## Blocking model
//!
//! Each futex address is backed by a `FutexBucket` containing a `WaitQueue`
//! and a list of `Waiter` records.  `futex_wait_bitset` sleeps via
//! `wq.wait(bitset, cancel, deadline)` instead of `block_current()`.
//!
//! Wakeup sources:
//!   - `futex_wake_bitset` calls `wq.wake(mask)` → O(1) wakeup
//!   - Deadline from the optional `struct timespec *timeout` → `-ETIMEDOUT`
//!   - Signal via `CancellationToken` → `-EINTR`
//!
//! No `core::hint::spin_loop()` exists in this file.
//!
//! ## Priority Inheritance (PI)
//!
//! Unchanged from prior revision.  PI sleep/wake now also goes through
//! the FutexBucket WaitQueue.
//!
//! ## Previous bug fixes (retained)
//!
//!   - futex_wait_bitset: double schedule() call removed.
//!   - wake_robust_futex: FUTEX_OWNER_DIED only.
//!   - sys_get_robust_list: copy_to_user return type fixed.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::proc::{scheduler, thread};
use crate::sync::wait_queue::{WaitQueue, WakeReason, CancellationToken, ReadyMask};
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

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

const FUTEX_WAITERS:    u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK:   u32 = 0x3FFF_FFFF;

/// Maximum PI boost chain depth (mirrors Linux MAX_LOCK_DEPTH).
const PI_CHAIN_LIMIT: usize = 8;

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

#[derive(Clone)]
struct Waiter {
    pid:    usize,
    bitset: u32,
}

/// Per-futex-address bucket: a WaitQueue plus the list of registered waiters.
///
/// The WaitQueue lives here so `futex_wake_bitset` can call `wq.wake(mask)`
/// to unblock exactly the right tasks, and `futex_wait_bitset` can call
/// `wq.wait(bitset, cancel, deadline)` with a deadline and signal sensitivity.
struct FutexBucket {
    wq:      Arc<WaitQueue>,
    waiters: Vec<Waiter>,
}

impl FutexBucket {
    fn new() -> Self {
        FutexBucket { wq: Arc::new(WaitQueue::new()), waiters: Vec::new() }
    }
}

static FUTEX_TABLE: Mutex<BTreeMap<FutexKey, FutexBucket>> = Mutex::new(BTreeMap::new());

#[inline]
fn current_cancel() -> Option<Arc<CancellationToken>> {
    scheduler::task_cancel_token(scheduler::current_pid())
}

/// Read a `struct timespec { i64 secs; i64 nsecs; }` from userspace and
/// convert to a monotonic deadline.  Returns `None` if `va == 0`.
/// Returns `Err(-14)` on a bad pointer and `Err(-22)` on negative or
/// out-of-range nanoseconds.
fn read_deadline(va: usize) -> Result<Option<u64>, isize> {
    if va == 0 { return Ok(None); }
    if !validate_user_ptr(va, 16) { return Err(-14); }
    let mut buf = [0u8; 16];
    copy_from_user(&mut buf, va).map_err(|_| -14isize)?;
    let secs  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let nsecs = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if secs < 0 || nsecs < 0 || nsecs >= 1_000_000_000 { return Err(-22); }
    let wait_ns = (secs as u64) * 1_000_000_000 + nsecs as u64;
    // Zero timeout => deadline already elapsed (poll once and return).
    let deadline = crate::time::monotonic_ns() + wait_ns;
    Ok(Some(deadline))
}

#[derive(Clone)]
struct PiRecord {
    owner_pid: usize,
    waiters:   Vec<usize>, // sorted descending by rt_priority
}

static PI_CHAIN: Mutex<BTreeMap<FutexKey, PiRecord>> = Mutex::new(BTreeMap::new());

fn pi_boost(mut owner_pid: usize, waiter_pid: usize) {
    let waiter_prio = scheduler::with_proc(waiter_pid, |p| p.sched.rt_priority)
        .unwrap_or(0);
    if waiter_prio == 0 { return; }

    for _ in 0..PI_CHAIN_LIMIT {
        let (already_highest, _) =
            scheduler::with_proc_mut(owner_pid, |pcb, _pl| {
                let current = pcb.sched.rt_priority;
                if waiter_prio > current {
                    pcb.sched.rt_priority = waiter_prio;
                    if !pcb.task.is_null() {
                        unsafe { (*pcb.task).sched.rt_priority = waiter_prio; }
                    }
                }
                (waiter_prio <= current, pcb.sched.rt_priority)
            })
            .map(|(already, _)| (already, 0_usize))
            .unwrap_or((true, 0));

        let next_owner: Option<usize> = {
            let chain = PI_CHAIN.lock();
            chain.values().find_map(|rec| {
                if rec.waiters.contains(&owner_pid) { Some(rec.owner_pid) } else { None }
            })
        };

        match next_owner {
            Some(next) if !already_highest => { owner_pid = next; }
            _ => break,
        }
    }
}

fn pi_unboost(owner_pid: usize) {
    let max_remaining: u8 = {
        let chain = PI_CHAIN.lock();
        chain.values()
            .filter(|rec| rec.owner_pid == owner_pid)
            .flat_map(|rec| rec.waiters.iter())
            .filter_map(|&wpid| scheduler::with_proc(wpid, |p| p.sched.rt_priority))
            .max()
            .unwrap_or(0)
    };
    scheduler::with_proc_mut(owner_pid, |pcb, _pl| {
        let base      = pcb.base_rt_priority;
        let effective = base.max(max_remaining);
        pcb.sched.rt_priority = effective;
        if !pcb.task.is_null() {
            unsafe { (*pcb.task).sched.rt_priority = effective; }
        }
    });
}

/// Sleep on a futex if `*addr == expected`.  Returns:
///   `Ok(())` on successful wakeup,
///   `Err(-11)` (EAGAIN) if `*addr != expected` at entry,
///   `Err(-4)`  (EINTR)  if a signal arrived,
///   `Err(-110)`(ETIMEDOUT) if `deadline_ns` elapsed,
///   `Err(-14)` (EFAULT) on bad address,
///   `Err(-22)` (EINVAL) if `bitset == 0`.
pub fn futex_wait_bitset(
    addr:        usize,
    expected:    u32,
    bitset:      u32,
    deadline_ns: Option<u64>,
) -> Result<(), isize> {
    if bitset == 0 { return Err(-22); }

    let pid    = scheduler::current_pid();
    let key    = FutexKey::new(addr);
    let cancel = current_cancel();

    // Clone the WaitQueue Arc *before* dropping the table lock so we can
    // sleep on it without re-acquiring the lock.
    let wq: Arc<WaitQueue> = {
        let mut tbl = FUTEX_TABLE.lock();

        // Check value under the table lock to close the TOCTOU gap between
        // the caller reading *uaddr and us registering as a waiter.
        let mut val_bytes = [0u8; 4];
        if copy_from_user(&mut val_bytes, addr).is_err() {
            return Err(-14);
        }
        if u32::from_ne_bytes(val_bytes) != expected {
            return Err(-11); // EAGAIN — value already changed
        }

        let bucket = tbl.entry(key).or_insert_with(FutexBucket::new);
        bucket.waiters.push(Waiter { pid, bitset });
        bucket.wq.clone()
    };

    // Sleep.  The table lock is not held here.
    let reason = wq.wait(bitset as ReadyMask, cancel.as_deref(), deadline_ns);

    // Remove ourselves from the waiter list regardless of wake reason.
    // (futex_wake_bitset may have already removed us; retain() is idempotent.)
    {
        let mut tbl = FUTEX_TABLE.lock();
        if let Some(bucket) = tbl.get_mut(&key) {
            bucket.waiters.retain(|w| w.pid != pid);
            if bucket.waiters.is_empty() { tbl.remove(&key); }
        }
    }

    match reason {
        WakeReason::Ready(_)  => Ok(()),
        WakeReason::Cancelled => Err(-4),   // EINTR
        WakeReason::Timeout   => Err(-110), // ETIMEDOUT
    }
}

pub fn futex_wait(addr: usize, expected: u32, deadline_ns: Option<u64>) -> Result<(), isize> {
    futex_wait_bitset(addr, expected, FUTEX_BITSET_MATCH_ANY, deadline_ns)
}

/// Wake up to `count` waiters whose bitset overlaps `mask`.
/// Returns the number of tasks woken.
pub fn futex_wake_bitset(addr: usize, count: usize, mask: u32) -> usize {
    if mask == 0 { return 0; }
    let key = FutexKey::new(addr);

    // Collect PIDs to wake, then drop the lock before calling wake().
    let (to_wake, wq): (Vec<usize>, Option<Arc<WaitQueue>>) = {
        let mut tbl = FUTEX_TABLE.lock();
        let bucket  = match tbl.get_mut(&key) { Some(b) => b, None => return 0 };

        let mut indices: Vec<usize> = Vec::new();
        for (i, w) in bucket.waiters.iter().enumerate() {
            if w.bitset & mask != 0 {
                indices.push(i);
                if indices.len() >= count { break; }
            }
        }
        // Remove in reverse index order to keep earlier indices valid.
        let pids: Vec<usize> = indices.iter().rev()
            .map(|&i| bucket.waiters.remove(i).pid)
            .collect();
        let wq_clone = if !pids.is_empty() { Some(bucket.wq.clone()) } else { None };
        if bucket.waiters.is_empty() { tbl.remove(&key); }
        (pids, wq_clone)
    };

    let n = to_wake.len();
    if let Some(wq) = wq {
        // Wake once per waiter.  WaitQueue::wake is edge-triggered:
        // each call unblocks exactly one sleeper.
        for _ in 0..n {
            wq.wake(mask as ReadyMask);
        }
    }
    n
}

pub fn futex_wake_addr(addr: usize, count: usize) {
    futex_wake_bitset(addr, count, FUTEX_BITSET_MATCH_ANY);
}

fn futex_requeue_inner(src: FutexKey, dst: FutexKey, requeue_count: usize) -> usize {
    let mut tbl = FUTEX_TABLE.lock();
    // Move waiters from src to dst.  The dst bucket gets a fresh WaitQueue
    // if it doesn't exist yet; requeued waiters will be woken by the dst
    // wake call that the caller is expected to issue.
    let to_move: Vec<Waiter> = {
        let src_bucket = match tbl.get_mut(&src) { Some(b) => b, None => return 0 };
        let n = requeue_count.min(src_bucket.waiters.len());
        src_bucket.waiters.drain(..n).collect()
    };
    let n = to_move.len();
    if n > 0 {
        tbl.entry(dst).or_insert_with(FutexBucket::new).waiters.extend(to_move);
    }
    // Clean up empty src bucket.
    if tbl.get(&src).map(|b| b.waiters.is_empty()).unwrap_or(false) {
        tbl.remove(&src);
    }
    n
}

/// FUTEX_LOCK_PI — acquire a PI-aware mutex.
pub fn futex_lock_pi(addr: usize) -> isize {
    let tid    = scheduler::current_pid() as usize;
    let key    = FutexKey::new(addr);
    let cancel = current_cancel();
    // PI locks have no user-supplied timeout; use the subsystem ceiling.
    let deadline_ns = crate::time::monotonic_ns() + 5_000_000_000;

    loop {
        let mut word_bytes = [0u8; 4];
        if copy_from_user(&mut word_bytes, addr).is_err() { return -14; }
        let word      = u32::from_ne_bytes(word_bytes);
        let owner_tid = (word & FUTEX_TID_MASK) as usize;

        if owner_tid == 0 {
            let mut chain = PI_CHAIN.lock();
            let mut wb2 = [0u8; 4];
            if copy_from_user(&mut wb2, addr).is_err() { return -14; }
            let word2 = u32::from_ne_bytes(wb2);
            if (word2 & FUTEX_TID_MASK) == 0 {
                let new_word = tid as u32;
                if !copy_to_user(addr, &new_word.to_ne_bytes()) { return -14; }
                chain.remove(&key);
                return 0;
            }
            drop(chain);
        }

        if owner_tid == tid { return -35; } // EDEADLK

        // Contended: register as waiter and boost owner.
        let wq: Arc<WaitQueue> = {
            let mut chain = PI_CHAIN.lock();
            let mut wb3 = [0u8; 4];
            if copy_from_user(&mut wb3, addr).is_err() { return -14; }
            let word3      = u32::from_ne_bytes(wb3);
            let live_owner = (word3 & FUTEX_TID_MASK) as usize;
            if live_owner == 0 { drop(chain); continue; } // owner released, retry

            let flagged = word3 | FUTEX_WAITERS;
            if !copy_to_user(addr, &flagged.to_ne_bytes()) { return -14; }

            let rec = chain.entry(key).or_insert(PiRecord {
                owner_pid: live_owner, waiters: Vec::new(),
            });
            rec.owner_pid = live_owner;
            let my_prio = scheduler::with_proc(tid, |p| p.sched.rt_priority).unwrap_or(0);
            let pos = rec.waiters.partition_point(|&wpid| {
                scheduler::with_proc(wpid, |p| p.sched.rt_priority).unwrap_or(0) >= my_prio
            });
            rec.waiters.insert(pos, tid);
            drop(chain);

            // Register in the non-PI FUTEX_TABLE so wake() reaches us.
            let mut tbl = FUTEX_TABLE.lock();
            let bucket  = tbl.entry(key).or_insert_with(FutexBucket::new);
            bucket.waiters.push(Waiter { pid: tid, bitset: FUTEX_BITSET_MATCH_ANY });
            bucket.wq.clone()
        };

        pi_boost(owner_tid, tid);

        // Sleep via WaitQueue — interruptible and deadline-bounded.
        let reason = wq.wait(
            FUTEX_BITSET_MATCH_ANY as ReadyMask,
            cancel.as_deref(),
            Some(deadline_ns),
        );

        // Remove ourselves from the waiter lists.
        {
            let mut tbl = FUTEX_TABLE.lock();
            if let Some(bucket) = tbl.get_mut(&key) {
                bucket.waiters.retain(|w| w.pid != tid);
                if bucket.waiters.is_empty() { tbl.remove(&key); }
            }
        }
        {
            let mut chain = PI_CHAIN.lock();
            if let Some(rec) = chain.get_mut(&key) {
                rec.waiters.retain(|&w| w != tid);
            }
        }

        match reason {
            WakeReason::Cancelled => return -4,   // EINTR
            WakeReason::Timeout   => return -110, // ETIMEDOUT
            WakeReason::Ready(_)  => return 0,    // owner wrote our TID; done
        }
    }
}

/// FUTEX_TRYLOCK_PI — non-blocking PI lock attempt.
pub fn futex_trylock_pi(addr: usize) -> isize {
    let tid = scheduler::current_pid() as usize;
    let key = FutexKey::new(addr);
    let mut chain = PI_CHAIN.lock();
    let mut wb = [0u8; 4];
    if copy_from_user(&mut wb, addr).is_err() { return -14; }
    let word = u32::from_ne_bytes(wb);
    if (word & FUTEX_TID_MASK) != 0 { return -11; } // EAGAIN
    if !copy_to_user(addr, &(tid as u32).to_ne_bytes()) { return -14; }
    chain.remove(&key);
    0
}

/// FUTEX_UNLOCK_PI — release a PI-aware mutex.
pub fn futex_unlock_pi(addr: usize) -> isize {
    let tid = scheduler::current_pid() as usize;
    let key = FutexKey::new(addr);

    let mut wb = [0u8; 4];
    if copy_from_user(&mut wb, addr).is_err() { return -14; }
    let word = u32::from_ne_bytes(wb);
    if (word & FUTEX_TID_MASK) as usize != tid { return -1; } // EPERM

    let successor: Option<usize>;
    {
        let mut chain = PI_CHAIN.lock();
        match chain.get_mut(&key) {
            None => {
                if !copy_to_user(addr, &0u32.to_ne_bytes()) { return -14; }
                successor = None;
            }
            Some(rec) => {
                if rec.waiters.is_empty() {
                    if !copy_to_user(addr, &0u32.to_ne_bytes()) { return -14; }
                    chain.remove(&key);
                    successor = None;
                } else {
                    let next_pid = rec.waiters.remove(0);
                    let still_contested = !rec.waiters.is_empty();
                    let new_word = (next_pid as u32 & FUTEX_TID_MASK)
                        | if still_contested { FUTEX_WAITERS } else { 0 };
                    if !copy_to_user(addr, &new_word.to_ne_bytes()) { return -14; }
                    rec.owner_pid = next_pid;
                    successor = Some(next_pid);
                }
            }
        }
    } // PI_CHAIN released

    // Remove successor from non-PI FUTEX_TABLE before waking.
    if let Some(spid) = successor {
        let mut tbl = FUTEX_TABLE.lock();
        if let Some(bucket) = tbl.get_mut(&key) {
            bucket.waiters.retain(|w| w.pid != spid);
            if bucket.waiters.is_empty() { tbl.remove(&key); }
        }
    }

    pi_unboost(tid);

    // Wake successor via the FutexBucket WaitQueue.
    if successor.is_some() {
        let wq = {
            let tbl = FUTEX_TABLE.lock();
            tbl.get(&key).map(|b| b.wq.clone())
        };
        // If the bucket was just emptied above we need to wake by PID instead.
        // Fall back to scheduler::wake_pid for the one-shot PI handoff.
        match wq {
            Some(wq) => { wq.wake(FUTEX_BITSET_MATCH_ANY as ReadyMask); }
            None => {
                if let Some(spid) = successor {
                    scheduler::wake_pid(spid);
                }
            }
        }
    }

    0
}

pub fn futex_clear_pid(pid: usize) {
    {
        let mut tbl = FUTEX_TABLE.lock();
        for bucket in tbl.values_mut() {
            bucket.waiters.retain(|w| w.pid != pid);
        }
        tbl.retain(|_, b| !b.waiters.is_empty());
    }
    {
        let mut chain = PI_CHAIN.lock();
        for rec in chain.values_mut() {
            rec.waiters.retain(|&wpid| wpid != pid);
        }
        chain.retain(|_, rec| !rec.waiters.is_empty() || rec.owner_pid != 0);
    }
    pi_unboost(pid);
}

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

fn wake_robust_futex(entry_va: usize, futex_offset: isize, tid: usize) {
    let futex_va = (entry_va as isize).wrapping_add(futex_offset) as usize;
    if futex_va < 0x1000 || futex_va >= crate::uaccess::USER_SPACE_END { return; }

    let mut buf = [0u8; 4];
    if copy_from_user(&mut buf, futex_va).is_err() { return; }
    let word = u32::from_ne_bytes(buf);
    if (word & FUTEX_TID_MASK) as usize != tid { return; }

    let had_waiters = word & FUTEX_WAITERS != 0;
    let _ = copy_to_user(futex_va, &FUTEX_OWNER_DIED.to_ne_bytes());

    if had_waiters {
        let tgid  = thread::tgid_of(tid);
        let as_id = if tgid != 0 { tgid } else { tid };
        let key   = FutexKey { as_id, uaddr: futex_va };
        let wq    = {
            let mut tbl = FUTEX_TABLE.lock();
            let bucket  = match tbl.get_mut(&key) { Some(b) => b, None => return };
            if bucket.waiters.is_empty() { return; }
            bucket.waiters.remove(0); // consume the woken waiter's slot
            if bucket.waiters.is_empty() {
                let wq = bucket.wq.clone();
                tbl.remove(&key);
                wq
            } else {
                bucket.wq.clone()
            }
        };
        wq.wake(FUTEX_BITSET_MATCH_ANY as ReadyMask);
    }
}

pub fn sys_futex(
    uaddr:            usize,
    op:               u32,
    val:              u32,
    timeout_or_val2:  usize,
    uaddr2:           usize,
    val3:             u32,
) -> isize {
    if uaddr < 0x1000 || uaddr >= crate::uaccess::USER_SPACE_END {
        return -14;
    }

    let base_op = op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_RT);

    match base_op {
        FUTEX_WAIT => {
            let deadline = match read_deadline(timeout_or_val2) {
                Ok(d)  => d,
                Err(e) => return e,
            };
            match futex_wait(uaddr, val, deadline) {
                Ok(_)  => 0,
                Err(e) => e,
            }
        }

        FUTEX_WAKE => {
            futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY) as isize
        }

        FUTEX_REQUEUE => {
            if uaddr2 < 0x1000 || uaddr2 >= crate::uaccess::USER_SPACE_END { return -14; }
            let val2  = timeout_or_val2 as u32;
            let pid   = scheduler::current_pid();
            let src   = FutexKey::for_pid(pid, uaddr);
            let dst   = FutexKey::for_pid(pid, uaddr2);
            let woken = futex_wake_bitset(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            let _req  = futex_requeue_inner(src, dst, val2 as usize);
            woken as isize
        }

        FUTEX_CMP_REQUEUE => {
            if uaddr2 < 0x1000 || uaddr2 >= crate::uaccess::USER_SPACE_END { return -14; }
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
            let deadline = match read_deadline(timeout_or_val2) {
                Ok(d)  => d,
                Err(e) => return e,
            };
            match futex_wait_bitset(uaddr, val, val3, deadline) {
                Ok(_)  => 0,
                Err(e) => e,
            }
        }

        FUTEX_WAKE_BITSET => {
            if val3 == 0 { return -22; }
            futex_wake_bitset(uaddr, val as usize, val3) as isize
        }

        FUTEX_LOCK_PI    => futex_lock_pi(uaddr),
        FUTEX_UNLOCK_PI  => futex_unlock_pi(uaddr),
        FUTEX_TRYLOCK_PI => futex_trylock_pi(uaddr),

        FUTEX_FD | FUTEX_WAKE_OP => -38, // ENOSYS

        _ => -22,
    }
}

pub fn sys_set_robust_list(head: usize, len: usize) -> isize {
    if len != 16 && len != 24 { return -22; }
    let pid = scheduler::current_pid();
    if pid == 0 { return -1; }
    scheduler::with_proc_mut(pid, |p, _| {
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
    if !copy_to_user(headp, &head.to_ne_bytes()) { return -14; }
    if !copy_to_user(lenp,  &len.to_ne_bytes())  { return -14; }
    0
}
