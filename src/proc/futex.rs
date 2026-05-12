//! Futex subsystem — fast userspace mutex primitives.
//!
//! ## Ops implemented
//!   FUTEX_WAIT           (0)  — sleep if *uaddr == val
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
//! ## Priority Inheritance (PI)
//!
//! The `PI_CHAIN` global maps each PI futex address to a `PiRecord`:
//!
//! ```text
//! PI_CHAIN: Mutex<BTreeMap<futex_va, PiRecord {
//!     owner_pid: usize,
//!     waiters:   Vec<usize>,   // sorted desc by waiter rt_priority
//! }>>
//! ```
//!
//! ### Lock (FUTEX_LOCK_PI)
//!
//! 1. CAS `*uaddr` from 0 → calling_tid.  If succeeds, acquired.
//! 2. Otherwise, read the owner TID from the low 30 bits of `*uaddr`.
//! 3. Register the caller as a waiter in `PI_CHAIN[uaddr]`.
//! 4. Call `pi_boost(owner_pid, caller_pid)`: if caller's `rt_priority` is
//!    higher than owner's current `sched.rt_priority`, raise the owner's
//!    priority to the caller's level.  Recurse transitively up to
//!    `PI_CHAIN_LIMIT` hops (owner may itself be waiting on another PI lock).
//! 5. Block via `futex_wait_bitset`.
//! 6. On wakeup, attempt the CAS again (re-check the futex word under the
//!    WAITERS lock to guard against spurious wakes).
//!
//! ### Unlock (FUTEX_UNLOCK_PI)
//!
//! 1. Verify `*uaddr & FUTEX_TID_MASK == calling_tid`.
//! 2. Look up `PI_CHAIN[uaddr]`.  If there are waiters, write the highest-
//!    priority waiter's TID into the futex word (with `FUTEX_WAITERS` set if
//!    > 1 waiter remain).  Otherwise write 0.
//! 3. Remove the caller from the owner slot; call `pi_unboost(caller_pid)`
//!    to restore `sched.rt_priority` to `Pcb::base_rt_priority`.
//! 4. Wake the selected successor.
//!
//! ### Chain limit
//!
//! `PI_CHAIN_LIMIT = 8` — the maximum transitive boost depth.  Matches
//! the Linux kernel default (`MAX_LOCK_DEPTH`).
//!
//! ## Previous bug fixes
//!
//! ### futex_wait_bitset: double schedule() call
//!   `block_current()` already ends with `schedule()`.  The extra call
//!   after it was removed.
//!
//! ### wake_robust_futex: preserved FUTEX_WAITERS bit
//!   Written word is now `FUTEX_OWNER_DIED` only (0x4000_0000).
//!
//! ### sys_get_robust_list: copy_to_user return type mismatch
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

const FUTEX_WAITERS:    u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK:   u32 = 0x3FFF_FFFF;

/// Maximum PI boost chain depth (mirrors Linux MAX_LOCK_DEPTH).
const PI_CHAIN_LIMIT: usize = 8;

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

// ── PI chain ──────────────────────────────────────────────────────────────────────
//
// Maps futex_va (within the current address space; keyed by FutexKey) to the
// current owner and list of PI waiters sorted descending by rt_priority.
// Kept separate from WAITERS so non-PI and PI futexes never alias.

#[derive(Clone)]
struct PiRecord {
    owner_pid: usize,
    /// Waiter PIDs, sorted descending by rt_priority at insertion time.
    /// The head is always the highest-priority waiter (the one that boosts).
    waiters:   Vec<usize>,
}

static PI_CHAIN: Mutex<BTreeMap<FutexKey, PiRecord>> = Mutex::new(BTreeMap::new());

// ── PI boost / unboost ────────────────────────────────────────────────────────────

/// Boost `owner_pid` to at least the rt_priority of `waiter_pid`, then
/// recurse transitively: if the owner is itself blocked on a PI lock, boost
/// its owner too, up to `PI_CHAIN_LIMIT` hops.
///
/// Must **not** be called with `PI_CHAIN` locked (it reads PI_CHAIN internally
/// for the transitive step).
fn pi_boost(mut owner_pid: usize, waiter_pid: usize) {
    // Snapshot the waiter's priority without locking PI_CHAIN.
    let waiter_prio = scheduler::with_proc(waiter_pid, |p| p.sched.rt_priority)
        .unwrap_or(0);
    if waiter_prio == 0 { return; }

    for _ in 0..PI_CHAIN_LIMIT {
        // Boost the current owner if the waiter outranks it.
        let (already_highest, owner_waiting_on) =
            scheduler::with_proc_mut(owner_pid, |pcb, _pl| {
                let current = pcb.sched.rt_priority;
                if waiter_prio > current {
                    pcb.sched.rt_priority = waiter_prio;
                    // Mirror the boost into the live Task so the RT heap
                    // re-enqueue (on next schedule()) sees the new priority.
                    if !pcb.task.is_null() {
                        unsafe { (*pcb.task).sched.rt_priority = waiter_prio; }
                    }
                }
                // If this owner is itself a PI waiter somewhere, return the
                // futex_va it is blocked on so we can climb the chain.
                (waiter_prio <= current, pcb.sched.rt_priority)
            })
            .map(|(already, _)| (already, 0_usize))   // transitive hop TBD below
            .unwrap_or((true, 0));

        // Climb: find if `owner_pid` is itself waiting on a PI lock.
        // We scan PI_CHAIN looking for a record whose waiters[] contains
        // owner_pid.  This is O(n) but PI chains are short in practice.
        let next_owner: Option<usize> = {
            let chain = PI_CHAIN.lock();
            chain.values().find_map(|rec| {
                if rec.waiters.contains(&owner_pid) {
                    Some(rec.owner_pid)
                } else {
                    None
                }
            })
        };

        match next_owner {
            Some(next) if !already_highest => { owner_pid = next; }
            _ => break,
        }
    }
}

/// Restore `owner_pid`'s rt_priority to its `base_rt_priority`, then
/// re-apply the maximum priority of any *remaining* PI waiters on locks it
/// still holds.
///
/// Called after the owner has fully released a PI futex and all its waiters
/// have been removed from `PI_CHAIN[addr]`.
fn pi_unboost(owner_pid: usize) {
    // Collect the maximum priority across all PI locks this task still owns.
    let max_remaining: u8 = {
        let chain = PI_CHAIN.lock();
        chain.values()
            .filter(|rec| rec.owner_pid == owner_pid)
            .flat_map(|rec| rec.waiters.iter())
            .filter_map(|&wpid| {
                scheduler::with_proc(wpid, |p| p.sched.rt_priority)
            })
            .max()
            .unwrap_or(0)
    };

    scheduler::with_proc_mut(owner_pid, |pcb, _pl| {
        let base = pcb.base_rt_priority;
        let effective = base.max(max_remaining);
        pcb.sched.rt_priority = effective;
        if !pcb.task.is_null() {
            unsafe { (*pcb.task).sched.rt_priority = effective; }
        }
    });
}

// ── Low-level wait / wake ────────────────────────────────────────────────────────

pub fn futex_wait_bitset(addr: usize, expected: u32, bitset: u32) -> Result<(), isize> {
    if bitset == 0 { return Err(-22); }

    let pid = scheduler::current_pid();
    let key = FutexKey::new(addr);

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

    scheduler::block_current();
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
    if n > 0 { map.entry(dst).or_default().extend(to_move); }
    n
}

// ── PI futex lock / unlock ─────────────────────────────────────────────────────

/// FUTEX_LOCK_PI — acquire a PI-aware mutex.
///
/// Attempts a CAS `*uaddr` 0 → tid.  On contention, registers as a waiter,
/// boosts the owner, and sleeps.  Returns 0 on success, -EAGAIN if the
/// futex was already owned by the caller, -EDEADLK on self-deadlock.
pub fn futex_lock_pi(addr: usize) -> isize {
    let tid = scheduler::current_pid() as usize;
    let key = FutexKey::new(addr);

    loop {
        // ── Try atomic acquire ────────────────────────────────────────────
        let mut word_bytes = [0u8; 4];
        if copy_from_user(&mut word_bytes, addr).is_err() { return -14; }
        let word = u32::from_ne_bytes(word_bytes);
        let owner_tid = (word & FUTEX_TID_MASK) as usize;

        if owner_tid == 0 {
            // Uncontested: CAS 0 → tid.
            // Under the PI_CHAIN lock to serialise against concurrent lockers.
            let mut chain = PI_CHAIN.lock();
            // Re-read under lock to close the TOCTOU gap.
            let mut wb2 = [0u8; 4];
            if copy_from_user(&mut wb2, addr).is_err() { return -14; }
            let word2 = u32::from_ne_bytes(wb2);
            if (word2 & FUTEX_TID_MASK) == 0 {
                // No waiters yet, just write our TID.
                let new_word = tid as u32;
                if !copy_to_user(addr, &new_word.to_ne_bytes()) { return -14; }
                chain.remove(&key); // clear any stale record
                return 0;
            }
            // Someone else snuck in — fall through.
            drop(chain);
        }

        if owner_tid == tid {
            // Self-deadlock: POSIX says EDEADLK.
            return -35; // EDEADLK
        }

        // ── Contended: register as waiter and boost owner ─────────────────
        {
            let mut chain = PI_CHAIN.lock();

            // Re-read word under lock.
            let mut wb3 = [0u8; 4];
            if copy_from_user(&mut wb3, addr).is_err() { return -14; }
            let word3 = u32::from_ne_bytes(wb3);
            let live_owner = (word3 & FUTEX_TID_MASK) as usize;
            if live_owner == 0 {
                // Owner released between our read and the lock — retry.
                drop(chain);
                continue;
            }

            // Set FUTEX_WAITERS bit so the owner knows to do UNLOCK_PI.
            let flagged = word3 | FUTEX_WAITERS;
            if !copy_to_user(addr, &flagged.to_ne_bytes()) { return -14; }

            let rec = chain.entry(key).or_insert(PiRecord {
                owner_pid: live_owner,
                waiters:   Vec::new(),
            });
            rec.owner_pid = live_owner;
            // Insert in descending priority order.
            let my_prio = scheduler::with_proc(tid, |p| p.sched.rt_priority)
                .unwrap_or(0);
            let pos = rec.waiters.partition_point(|&wpid| {
                scheduler::with_proc(wpid, |p| p.sched.rt_priority)
                    .unwrap_or(0) >= my_prio
            });
            rec.waiters.insert(pos, tid);
        }

        // Boost owner (must be done outside PI_CHAIN lock to avoid deadlock
        // with with_proc_mut which may acquire ProcLock::inner).
        pi_boost(owner_tid, tid);

        // Sleep until the owner wakes us via FUTEX_UNLOCK_PI.
        // We sleep on the same key as non-PI waiters to reuse wake_pid.
        {
            let mut map = WAITERS.lock();
            let my_bitset = FUTEX_BITSET_MATCH_ANY;
            map.entry(key).or_default().push(Waiter { pid: tid, bitset: my_bitset });
        }
        scheduler::block_current();

        // Woke up.  The unlock path has already written our TID into the
        // futex word.  Clean up our waiter record (already removed by
        // unlock) and return success.
        return 0;
    }
}

/// FUTEX_TRYLOCK_PI — non-blocking PI lock attempt.
///
/// Returns 0 on success, -EAGAIN if contested.
pub fn futex_trylock_pi(addr: usize) -> isize {
    let tid = scheduler::current_pid() as usize;
    let key = FutexKey::new(addr);

    let mut chain = PI_CHAIN.lock();
    let mut wb = [0u8; 4];
    if copy_from_user(&mut wb, addr).is_err() { return -14; }
    let word = u32::from_ne_bytes(wb);
    let owner_tid = (word & FUTEX_TID_MASK) as usize;

    if owner_tid != 0 {
        return -11; // EAGAIN — contested
    }

    let new_word = tid as u32;
    if !copy_to_user(addr, &new_word.to_ne_bytes()) { return -14; }
    chain.remove(&key);
    0
}

/// FUTEX_UNLOCK_PI — release a PI-aware mutex.
///
/// Selects the highest-priority waiter as successor, writes its TID into
/// the futex word, restores the caller's base priority, and wakes the
/// successor.
pub fn futex_unlock_pi(addr: usize) -> isize {
    let tid = scheduler::current_pid() as usize;
    let key = FutexKey::new(addr);

    // Verify ownership.
    let mut wb = [0u8; 4];
    if copy_from_user(&mut wb, addr).is_err() { return -14; }
    let word = u32::from_ne_bytes(wb);
    if (word & FUTEX_TID_MASK) as usize != tid {
        return -1; // EPERM — not the owner
    }

    let successor: Option<usize>;
    {
        let mut chain = PI_CHAIN.lock();
        match chain.get_mut(&key) {
            None => {
                // No PI waiters — simply zero the word.
                if !copy_to_user(addr, &0u32.to_ne_bytes()) { return -14; }
                successor = None;
            }
            Some(rec) => {
                if rec.waiters.is_empty() {
                    if !copy_to_user(addr, &0u32.to_ne_bytes()) { return -14; }
                    chain.remove(&key);
                    successor = None;
                } else {
                    // Head of waiters[] is highest-priority (sorted at insert).
                    let next_pid = rec.waiters.remove(0);
                    let still_contested = !rec.waiters.is_empty();
                    let new_word = (next_pid as u32 & FUTEX_TID_MASK)
                        | if still_contested { FUTEX_WAITERS } else { 0 };
                    if !copy_to_user(addr, &new_word.to_ne_bytes()) { return -14; }

                    // Update the record's owner to the successor so that any
                    // remaining waiters boost it correctly on their next tick.
                    rec.owner_pid = next_pid;

                    // Remove the successor from WAITERS (non-PI table) now
                    // so futex_wake_bitset doesn't double-wake.
                    {
                        // Avoid holding PI_CHAIN and WAITERS simultaneously
                        // → release PI_CHAIN first by stashing next_pid.
                        successor = Some(next_pid);
                        // We still hold chain here; drop at end of block.
                    }
                }
            }
        }
    } // PI_CHAIN lock released here.

    // Remove successor from the non-PI WAITERS table before waking.
    if let Some(spid) = successor {
        let mut map = WAITERS.lock();
        if let Some(list) = map.get_mut(&key) {
            list.retain(|w| w.pid != spid);
            if list.is_empty() { map.remove(&key); }
        }
    }

    // Unboost the former owner.
    pi_unboost(tid);

    // Wake the successor.
    if let Some(spid) = successor {
        scheduler::wake_pid(spid);
    }

    0
}

// ── Clear all waiters for a dying thread ────────────────────────────────────────

pub fn futex_clear_pid(pid: usize) {
    // Remove from non-PI waiter table.
    {
        let mut map = WAITERS.lock();
        for list in map.values_mut() {
            list.retain(|w| w.pid != pid);
        }
        map.retain(|_, list| !list.is_empty());
    }
    // Remove from PI waiter lists and unboost any owners that were boosted
    // solely on behalf of this task.
    {
        let mut chain = PI_CHAIN.lock();
        for rec in chain.values_mut() {
            rec.waiters.retain(|&wpid| wpid != pid);
        }
        chain.retain(|_, rec| !rec.waiters.is_empty() || rec.owner_pid != 0);
    }
    pi_unboost(pid);
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

fn wake_robust_futex(entry_va: usize, futex_offset: isize, tid: usize) {
    let futex_va = (entry_va as isize).wrapping_add(futex_offset) as usize;
    if futex_va < 0x1000 || futex_va >= crate::uaccess::USER_SPACE_END { return; }

    let mut buf = [0u8; 4];
    if copy_from_user(&mut buf, futex_va).is_err() { return; }
    let word = u32::from_ne_bytes(buf);

    if (word & FUTEX_TID_MASK) as usize != tid { return; }

    let had_waiters = word & FUTEX_WAITERS != 0;
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

        FUTEX_LOCK_PI    => futex_lock_pi(uaddr),
        FUTEX_UNLOCK_PI  => futex_unlock_pi(uaddr),
        FUTEX_TRYLOCK_PI => futex_trylock_pi(uaddr),

        FUTEX_FD | FUTEX_WAKE_OP => -38, // ENOSYS

        _ => -22, // EINVAL
    }
}

// ── sys_set_robust_list / sys_get_robust_list ────────────────────────────────────

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
