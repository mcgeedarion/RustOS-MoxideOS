//! Ticket spinlock — fair, starvation-free, SMP-correct.
//!
//! Each `lock()` call atomically grabs a ticket number from `next_ticket`.
//! The holder is the CPU whose ticket matches `now_serving`.  On unlock,
//! `now_serving` is incremented, waking the next waiter.
//!
//! Backoff: x86_64 uses `pause` (reduces memory-order speculation).
//!          RISC-V uses `wfi` if in S-mode idle, otherwise spin.

use core::sync::atomic::{AtomicU32, Ordering};
use core::cell::UnsafeCell;

pub struct SpinLock<T> {
    next_ticket:  AtomicU32,
    now_serving:  AtomicU32,
    data:         UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(val: T) -> Self {
        SpinLock {
            next_ticket: AtomicU32::new(0),
            now_serving: AtomicU32::new(0),
            data: UnsafeCell::new(val),
        }
    }

    /// Acquire the lock, returning a guard that releases it on drop.
    #[inline]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        while self.now_serving.load(Ordering::Acquire) != ticket {
            // Backoff hint.
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::asm!("pause", options(nostack, preserves_flags)); }
            #[cfg(target_arch = "riscv64")]
            unsafe { core::arch::asm!("nop",   options(nostack)); }
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }

    /// Try to acquire without blocking.  Returns `None` on contention.
    #[inline]
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let serving = self.now_serving.load(Ordering::Acquire);
        let next    = self.next_ticket.load(Ordering::Relaxed);
        if serving == next {
            // Attempt to grab the ticket.
            if self.next_ticket
                .compare_exchange(next, next + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(SpinLockGuard { lock: self });
            }
        }
        None
    }

    /// Returns `true` if the lock is currently held by anyone.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.now_serving.load(Ordering::Relaxed)
            != self.next_ticket.load(Ordering::Relaxed)
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<'a, T> core::ops::Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T { unsafe { &*self.lock.data.get() } }
}

impl<'a, T> core::ops::DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.lock.data.get() } }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.now_serving.fetch_add(1, Ordering::Release);
    }
}
