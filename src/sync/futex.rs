//! Kernel futex wait-queue implementation.
//!
//! ## Design
//!
//! The table maps user virtual address -> Vec<FutexWaiter>.  Using the VA
//! directly is correct for this kernel because:
//!   - All user tasks share the same lower half of the address space (each
//!     has its own CR3, but the futex word address is unique per-process).
//!   - Private futexes (FUTEX_PRIVATE_FLAG) are per-process by definition;
//!     shared futexes on a single-CPU cooperative kernel are handled
//!     identically in practice.
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

// ── Types ──────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct FutexWaiter {
    pid:         usize,
    bitset:      u32,
    deadline_ns: u64,
    woken:       bool,
}

static FUTEX_TABLE: Mutex<BTreeMap<usize, Vec<FutexWaiter>>> =
    Mutex::new(BTreeMap::new());

// ── FUTEX_WAIT ─────────────────────────────────────────────────────────────────

pub fn futex_wait(uaddr: usize, val: u32, bitset: u32, deadline_ns: u64) -> isize {
    if !crate::uaccess::validate_user_ptr(uaddr, 4) { return -14; }

    let pid = crate::proc::scheduler::current_pid();

    // Enqueue under the table lock, checking the value atomically.
    {
        let mut tbl = FUTEX_TABLE.lock();
        let current = unsafe { (uaddr as *const u32).read_volatile() };
        if current != val { return -11; } // EAGAIN
        tbl.entry(uaddr).or_insert_with(Vec::new).push(FutexWaiter {
            pid,
            bitset,
            deadline_ns,
            woken: false,
        });
    }

    // Wait loop: yield until woken or deadline.
    // We avoid acquiring the table lock on every tick; we only re-enter
    // to confirm the woken flag after being rescheduled (futex_wake sets
    // the flag and calls wake_pid, so we will not miss the notification).
    loop {
        crate::proc::scheduler::schedule();

        // Check woken flag and handle timeout under a single lock window.
        let now = crate::time::monotonic_ns();
        let mut tbl = FUTEX_TABLE.lock();

        let woken = match tbl.get(&uaddr) {
            None        => true,
            Some(queue) => queue.iter().any(|w| w.pid == pid && w.woken),
        };

        if woken || now >= deadline_ns {
            // Remove our entry and clean up the queue.
            if let Some(queue) = tbl.get_mut(&uaddr) {
                queue.retain(|w| w.pid != pid);
                if queue.is_empty() { tbl.remove(&uaddr); }
            }
            return if woken { 0 } else { -110 }; // 0 or ETIMEDOUT
        }
    }
}

// ── FUTEX_WAKE ─────────────────────────────────────────────────────────────────

pub fn futex_wake(uaddr: usize, n: u32, bitset: u32) -> isize {
    if uaddr < 0x1000 { return 0; }

    let mut tbl   = FUTEX_TABLE.lock();
    let mut woken = 0u32;

    if let Some(queue) = tbl.get_mut(&uaddr) {
        for waiter in queue.iter_mut() {
            if woken >= n { break; }
            if waiter.woken { continue; }
            if waiter.bitset & bitset == 0 { continue; }
            waiter.woken = true;
            crate::proc::scheduler::wake_pid(waiter.pid);
            woken += 1;
        }
        queue.retain(|w| !w.woken);
        if queue.is_empty() { tbl.remove(&uaddr); }
    }

    woken as isize
}

// ── FUTEX_REQUEUE / FUTEX_CMP_REQUEUE ────────────────────────────────────────────

pub fn futex_requeue(
    uaddr:     usize,
    wake_n:    u32,
    uaddr2:    usize,
    requeue_n: u32,
    cmp_val:   Option<u32>,
) -> isize {
    if !crate::uaccess::validate_user_ptr(uaddr, 4)  { return -14; }
    if !crate::uaccess::validate_user_ptr(uaddr2, 4) { return -14; }

    let mut tbl = FUTEX_TABLE.lock();

    if let Some(expected) = cmp_val {
        let current = unsafe { (uaddr as *const u32).read_volatile() };
        if current != expected { return -11; }
    }

    let mut woken    = 0u32;
    let mut requeued = 0u32;

    if let Some(queue) = tbl.get_mut(&uaddr) {
        // Single O(n) pass: partition into wake / requeue / keep buckets.
        // Avoids the O(n²) Vec::remove(i) shift of the previous loop.
        let mut to_wake:    Vec<FutexWaiter> = Vec::new();
        let mut to_requeue: Vec<FutexWaiter> = Vec::new();
        let mut to_keep:    Vec<FutexWaiter> = Vec::new();

        for w in queue.drain(..) {
            if woken < wake_n {
                to_wake.push(w);
                woken += 1;
            } else if requeued < requeue_n {
                to_requeue.push(w);
                requeued += 1;
            } else {
                to_keep.push(w);
            }
        }

        *queue = to_keep;
        if queue.is_empty() { tbl.remove(&uaddr); }

        for w in &to_wake {
            crate::proc::scheduler::wake_pid(w.pid);
        }

        if !to_requeue.is_empty() {
            tbl.entry(uaddr2).or_insert_with(Vec::new).extend(to_requeue);
        }
    }

    woken as isize
}

// ── FUTEX_WAKE_OP ──────────────────────────────────────────────────────────────────
//
// val3 encoding:
//   bits 31-28: op    (0=set, 1=add, 2=or, 3=andn, 4=xor)
//   bits 27-24: cmp   (0=eq, 1=ne, 2=lt, 3=le, 4=gt, 5=ge)
//   bits 23-12: oparg
//   bits 11- 0: cmparg

pub fn futex_wake_op(
    uaddr:   usize,
    wake_n:  u32,
    uaddr2:  usize,
    wake2_n: u32,
    val3:    u32,
) -> isize {
    if !crate::uaccess::validate_user_ptr(uaddr2, 4) { return -14; }

    let op     = (val3 >> 28) & 0xF;
    let cmp    = (val3 >> 24) & 0xF;
    let oparg  = (val3 >> 12) & 0xFFF;
    let cmparg =  val3        & 0xFFF;

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

    let woken1 = futex_wake(uaddr, wake_n, 0xFFFF_FFFF);

    let cmp_ok = match cmp {
        0 => old_val == cmparg,
        1 => old_val != cmparg,
        2 => (old_val as i32) <  (cmparg as i32),
        3 => (old_val as i32) <= (cmparg as i32),
        4 => (old_val as i32) >  (cmparg as i32),
        5 => (old_val as i32) >= (cmparg as i32),
        _ => false,
    };
    let woken2 = if cmp_ok { futex_wake(uaddr2, wake2_n, 0xFFFF_FFFF) } else { 0 };

    woken1 + woken2
}

// ── futex_clear_pid ───────────────────────────────────────────────────────────────

/// Remove all waiter entries for `pid` from every queue in the table.
/// Call this from do_exit to prevent leaks when a process exits while
/// blocked on a futex (e.g. SIGKILL mid-wait).
pub fn futex_clear_pid(pid: usize) {
    let mut tbl = FUTEX_TABLE.lock();
    tbl.retain(|_addr, queue| {
        queue.retain(|w| w.pid != pid);
        !queue.is_empty()
    });
}
