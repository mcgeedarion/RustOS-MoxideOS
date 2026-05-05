//! Kernel futex wait-queue implementation.
//!
//! ## Design
//!
//! A single global table maps physical_address(u32 word) -> Vec<FutexWaiter>.
//! Using the physical address means private and shared futexes share the same
//! lookup and fork + CoW automatically collapse to the same key once the page
//! is copied (the PA changes, which is correct: the child's word is a
//! different object after CoW).
//!
//! ## Ops implemented
//!
//!   FUTEX_WAIT          sleep until *uaddr != val or deadline
//!   FUTEX_WAIT_BITSET   same, with a 32-bit wakeup bitmask
//!   FUTEX_WAKE          wake up to N waiters on uaddr
//!   FUTEX_WAKE_BITSET   same, ANDs caller bitset with waiter bitset
//!   FUTEX_REQUEUE       wake N, move M to a second queue
//!   FUTEX_CMP_REQUEUE   same but only if *uaddr == val3
//!   FUTEX_WAKE_OP       wake N on uaddr, conditional wake on uaddr2
//!                       (op side-effect is applied; wake is unconditional)
//!
//! ## Race-freedom
//!
//! The table lock is held while we read *uaddr and insert the waiter.
//! This closes the WAIT/WAKE race: if a WAKE arrives between the user's
//! comparison and the kernel WAIT, the value will have changed and we
//! return EAGAIN rather than sleeping forever.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::arch::Arch;
use crate::arch::api::Paging;

// ── Types ────────────────────────────────────────────────────────────────────

/// A sleeping waiter.
#[derive(Clone)]
struct FutexWaiter {
    pid:         usize,
    bitset:      u32,
    deadline_ns: u64,   // u64::MAX = no timeout
    /// Set to true by futex_wake to signal this waiter without removing
    /// it from the table first (avoids a double-lock in wake).
    woken:       bool,
}

/// Global wait-queue table.  Key = physical address of the futex word.
static FUTEX_TABLE: Mutex<BTreeMap<usize, Vec<FutexWaiter>>> =
    Mutex::new(BTreeMap::new());

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Translate a user virtual address to its physical address for use as
/// the futex table key.  Returns None if the address is not mapped.
fn va_to_key(uaddr: usize) -> Option<usize> {
    let cr3 = Arch::kernel_cr3(); // scheduler always runs with kernel CR3
    // Try the current task's address space first.
    let task_cr3 = crate::proc::scheduler::current_cr3();
    Arch::virt_to_phys(task_cr3, uaddr)
        .or_else(|| Arch::virt_to_phys(cr3, uaddr))
}

/// Read the futex word safely.  Returns None if the address is invalid.
#[inline]
fn read_futex(uaddr: usize) -> Option<u32> {
    if !crate::uaccess::validate_user_ptr(uaddr, 4) { return None; }
    Some(unsafe { (uaddr as *const u32).read_volatile() })
}

// ── FUTEX_WAIT ───────────────────────────────────────────────────────────────

/// Sleep until `*uaddr != val`, the deadline expires, or we are woken.
///
/// `bitset` is `FUTEX_BITSET_MATCH_ANY` (0xFFFF_FFFF) for plain WAIT.
pub fn futex_wait(uaddr: usize, val: u32, bitset: u32, deadline_ns: u64) -> isize {
    if !crate::uaccess::validate_user_ptr(uaddr, 4) { return -14; } // EFAULT

    let key = match va_to_key(uaddr) {
        Some(k) => k,
        None    => return -14,
    };

    let pid = crate::proc::scheduler::current_pid();

    // ── Critical section: check value and enqueue atomically ─────────────
    {
        let mut tbl = FUTEX_TABLE.lock();
        let current = match read_futex(uaddr) {
            Some(v) => v,
            None    => return -14,
        };
        if current != val {
            return -11; // EAGAIN: value already changed before we slept
        }
        let queue = tbl.entry(key).or_insert_with(Vec::new);
        queue.push(FutexWaiter {
            pid,
            bitset,
            deadline_ns,
            woken: false,
        });
    } // lock released

    // ── Wait loop ────────────────────────────────────────────────────────
    loop {
        // Check if we have been woken (flag set by futex_wake).
        let woken = {
            let tbl = FUTEX_TABLE.lock();
            if let Some(queue) = tbl.get(&key) {
                !queue.iter().any(|w| w.pid == pid && !w.woken)
            } else {
                true // queue was fully drained
            }
        };
        if woken {
            // Clean up our entry if still present (wake may have left it).
            let mut tbl = FUTEX_TABLE.lock();
            if let Some(queue) = tbl.get_mut(&key) {
                queue.retain(|w| w.pid != pid);
                if queue.is_empty() { tbl.remove(&key); }
            }
            return 0;
        }

        // Timeout check.
        if crate::time::monotonic_ns() >= deadline_ns {
            let mut tbl = FUTEX_TABLE.lock();
            if let Some(queue) = tbl.get_mut(&key) {
                queue.retain(|w| w.pid != pid);
                if queue.is_empty() { tbl.remove(&key); }
            }
            return -110; // ETIMEDOUT
        }

        // Yield CPU so the waking thread can actually run.
        crate::proc::scheduler::schedule();
    }
}

// ── FUTEX_WAKE ───────────────────────────────────────────────────────────────

/// Wake up to `n` waiters on `uaddr` whose bitset matches.
/// Returns the number of waiters actually woken.
pub fn futex_wake(uaddr: usize, n: u32, bitset: u32) -> isize {
    if !crate::uaccess::validate_user_ptr(uaddr, 4) { return 0; }

    let key = match va_to_key(uaddr) {
        Some(k) => k,
        None    => return 0,
    };

    let mut tbl   = FUTEX_TABLE.lock();
    let mut woken = 0u32;

    if let Some(queue) = tbl.get_mut(&key) {
        for waiter in queue.iter_mut() {
            if woken >= n { break; }
            if waiter.woken { continue; }
            if waiter.bitset & bitset == 0 { continue; }
            waiter.woken = true;
            crate::proc::scheduler::wake_pid(waiter.pid);
            woken += 1;
        }
        // Eagerly remove fully-woken entries.
        queue.retain(|w| !w.woken);
        if queue.is_empty() { tbl.remove(&key); }
    }

    woken as isize
}

// ── FUTEX_REQUEUE / FUTEX_CMP_REQUEUE ────────────────────────────────────────

/// Wake `wake_n` waiters on `uaddr`, then move up to `requeue_n` remaining
/// waiters from `uaddr` to `uaddr2`.
///
/// If `cmp_val` is `Some(v)`, the operation is conditional: it only proceeds
/// if `*uaddr == v` at the time of the call (FUTEX_CMP_REQUEUE).
/// If `cmp_val` is `None`, the requeue is unconditional (FUTEX_REQUEUE).
pub fn futex_requeue(
    uaddr:    usize,
    wake_n:   u32,
    uaddr2:   usize,
    requeue_n: u32,
    cmp_val:  Option<u32>,
) -> isize {
    if !crate::uaccess::validate_user_ptr(uaddr, 4) { return -14; }
    if !crate::uaccess::validate_user_ptr(uaddr2, 4) { return -14; }

    let key1 = match va_to_key(uaddr)  { Some(k) => k, None => return -14 };
    let key2 = match va_to_key(uaddr2) { Some(k) => k, None => return -14 };

    let mut tbl = FUTEX_TABLE.lock();

    // CMP_REQUEUE conditional check.
    if let Some(expected) = cmp_val {
        let current = match read_futex(uaddr) {
            Some(v) => v,
            None    => return -14,
        };
        if current != expected { return -11; } // EAGAIN
    }

    let mut woken = 0u32;
    let mut requeued = 0u32;
    let mut to_requeue: Vec<FutexWaiter> = Vec::new();

    if let Some(queue) = tbl.get_mut(&key1) {
        let mut i = 0;
        while i < queue.len() {
            if woken < wake_n {
                let w = queue.remove(i);
                crate::proc::scheduler::wake_pid(w.pid);
                woken += 1;
                // don't increment i; next element is now at i
            } else if requeued < requeue_n {
                let mut w = queue.remove(i);
                w.woken = false;
                to_requeue.push(w);
                requeued += 1;
            } else {
                break;
            }
        }
        if queue.is_empty() { tbl.remove(&key1); }
    }

    if !to_requeue.is_empty() {
        tbl.entry(key2).or_insert_with(Vec::new).extend(to_requeue);
    }

    woken as isize
}

// ── FUTEX_WAKE_OP ─────────────────────────────────────────────────────────────

/// Apply an atomic operation to `*uaddr2`, then wake up to `wake_n` waiters
/// on `uaddr` and up to `wake2_n` waiters on `uaddr2` if the old value of
/// `*uaddr2` satisfies the comparison encoded in `val3`.
///
/// This is used by glibc/musl `pthread_cond_signal` to combine the lock
/// acquisition with the wakeup in a single syscall.
///
/// The `val3` encoding (Linux ABI):
///   bits 31-28: op   (0=set,1=add,2=or,3=andn,4=xor)
///   bits 27-24: cmp  (0=eq,1=ne,2=lt,3=le,4=gt,5=ge)
///   bits 23-12: oparg
///   bits 11- 0: cmparg
pub fn futex_wake_op(
    uaddr:   usize,
    wake_n:  u32,
    uaddr2:  usize,
    wake2_n: u32,
    val3:    u32,
) -> isize {
    if !crate::uaccess::validate_user_ptr(uaddr2, 4) { return -14; }

    // Decode val3
    let op      = (val3 >> 28) & 0xF;
    let cmp     = (val3 >> 24) & 0xF;
    let oparg   = ((val3 >> 12) & 0xFFF) as u32;
    let cmparg  = (val3 & 0xFFF) as u32;

    // Apply op to *uaddr2
    let old_val = unsafe { (uaddr2 as *const u32).read_volatile() };
    let new_val = match op {
        0 => oparg,
        1 => old_val.wrapping_add(oparg),
        2 => old_val | oparg,
        3 => old_val & !oparg,
        4 => old_val ^ oparg,
        _ => old_val,
    };
    unsafe { (uaddr2 as *mut u32).write_volatile(new_val); }

    // Wake waiters on uaddr1 unconditionally
    let woken1 = futex_wake(uaddr, wake_n, 0xFFFF_FFFF);

    // Wake waiters on uaddr2 if comparison holds
    let cmp_result = match cmp {
        0 => old_val == cmparg,
        1 => old_val != cmparg,
        2 => (old_val as i32) < (cmparg as i32),
        3 => (old_val as i32) <= (cmparg as i32),
        4 => (old_val as i32) > (cmparg as i32),
        5 => (old_val as i32) >= (cmparg as i32),
        _ => false,
    };
    let woken2 = if cmp_result {
        futex_wake(uaddr2, wake2_n, 0xFFFF_FFFF)
    } else {
        0
    };

    woken1 + woken2
}
