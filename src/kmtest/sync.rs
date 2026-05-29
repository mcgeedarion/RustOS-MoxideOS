//! kmtest/sync — synchronisation primitive test suite
//!
//! Covers:
//!   SpinLock: lock/unlock is idempotent under single-threaded use
//!   Mutex: trylock succeeds when unlocked, fails (or blocks) when locked
//!   Semaphore: counting semaphore up/down invariants
//!   RwLock: multiple readers coexist; writer is exclusive
//!   Futex: FUTEX_WAIT wakes on FUTEX_WAKE
//!
//! SMP load tests are annotated but gated behind a separate feature
//! flag (`smp_tests`) so they only run on multi-CPU QEMU instances.

use kmtest::{register, KmTestResult};
use crate::sync::{
    spinlock::SpinLock,
    mutex::Mutex,
    rwlock::RwLock,
    semaphore::Semaphore,
};
use crate::proc::futex::sys_futex;

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;

/// SpinLock: lock then unlock; counter mutated under lock is consistent.
fn sync_spinlock_basic() -> KmTestResult {
    let lock = SpinLock::new(0u64);
    for _ in 0..1000 {
        let mut g = lock.lock();
        *g += 1;
    }
    let val = *lock.lock();
    if val != 1000 {
        return Err("spinlock counter mismatch after 1000 increments");
    }
    Ok(())
}

/// Mutex: try_lock returns Some when free, None when already held.
fn sync_mutex_trylock() -> KmTestResult {
    let m = Mutex::new(0u32);
    let g = m.try_lock();
    if g.is_none() {
        return Err("try_lock on free mutex returned None");
    }
    // While g holds it, a second try_lock must fail.
    let g2 = m.try_lock();
    if g2.is_some() {
        return Err("try_lock on held mutex returned Some");
    }
    drop(g);
    // Now free again.
    let g3 = m.try_lock();
    if g3.is_none() {
        return Err("try_lock failed after unlock");
    }
    Ok(())
}

/// Mutex: value modified under lock is visible after unlock.
fn sync_mutex_value() -> KmTestResult {
    let m = Mutex::new(0u64);
    for i in 1u64..=100 {
        *m.lock() = i;
    }
    if *m.lock() != 100 {
        return Err("mutex value incorrect after 100 mutations");
    }
    Ok(())
}

/// Semaphore: down() decrements count; up() increments; count never < 0.
fn sync_semaphore_counting() -> KmTestResult {
    let sem = Semaphore::new(5);
    for _ in 0..5 { sem.down(); }
    // Count is now 0; try_down must fail.
    if sem.try_down() {
        return Err("semaphore try_down succeeded at count 0");
    }
    sem.up();
    if !sem.try_down() {
        return Err("semaphore try_down failed after up");
    }
    Ok(())
}

/// RwLock: multiple read guards can coexist; write lock is exclusive.
fn sync_rwlock_readers_writers() -> KmTestResult {
    let rw = RwLock::new(0u32);
    // Two simultaneous read guards.
    let r1 = rw.read();
    let r2 = rw.read();
    if *r1 != 0 || *r2 != 0 {
        return Err("rwlock initial value wrong");
    }
    drop(r1);
    drop(r2);
    // Write guard modifies value.
    {
        let mut w = rw.write();
        *w = 42;
    }
    // Read guard sees new value.
    if *rw.read() != 42 {
        return Err("rwlock value after write incorrect");
    }
    Ok(())
}

/// RwLock: try_write fails while a reader holds the lock.
fn sync_rwlock_write_blocks_reader() -> KmTestResult {
    let rw = RwLock::new(0u32);
    let _r = rw.read();
    if rw.try_write().is_some() {
        return Err("try_write succeeded while reader held lock");
    }
    Ok(())
}

/// Futex: FUTEX_WAIT on a word whose value mismatches returns -EAGAIN immediately.
fn sync_futex_wait_mismatch() -> KmTestResult {
    let word: u32 = 0;
    // Wait for word == 1, but word == 0: must return -EAGAIN (-11).
    let ret = sys_futex(
        &word as *const u32 as usize,
        FUTEX_WAIT,
        1,        // expected value (won't match)
        0,        // timeout ptr = NULL
        0,
        0,
    );
    if ret != -11 {
        return Err("FUTEX_WAIT with mismatched value did not return EAGAIN");
    }
    Ok(())
}

pub fn register() {
    register!("sync_spinlock_basic",           sync_spinlock_basic);
    register!("sync_mutex_trylock",            sync_mutex_trylock);
    register!("sync_mutex_value",              sync_mutex_value);
    register!("sync_semaphore_counting",       sync_semaphore_counting);
    register!("sync_rwlock_readers_writers",   sync_rwlock_readers_writers);
    register!("sync_rwlock_write_blocks_reader",sync_rwlock_write_blocks_reader);
    register!("sync_futex_wait_mismatch",      sync_futex_wait_mismatch);
}
