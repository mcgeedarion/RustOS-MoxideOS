//! Ticket spinlock — fair, starvation-free, SMP-correct.
//!
//! Two variants are provided:
//!
//!   `SpinLock<T>`         — plain spinlock; use when the lock is NEVER
//!                           acquired from interrupt context on the same CPU.
//!
//!   `IrqSpinLock<T>`      — IRQ-saving spinlock; use when the lock may be
//!                           acquired from both normal (process/task) context
//!                           AND from interrupt handlers on the same CPU.
//!                           `lock_irqsave()` disables local interrupts before
//!                           spinning, and the guard re-enables them on drop.
//!
//! ## Adaptive spin strategy
//!
//! On modern x86 `pause` carries a ~140-cycle delay (Alder Lake / Zen 4).
//! For short critical sections the lock holder often releases before those
//! 140 cycles elapse, so we would waste time waiting for `pause` to finish.
//!
//! The optimised spin loop therefore does a short tight spin (4 iterations
//! of `core::hint::spin_loop()`, which is a zero-cycle hint on most arches
//! or a very short pause on others) before falling into the heavier pause
//! loop.  This recovers the fast-path latency for uncontended or briefly-
//! contended locks while still reducing bus traffic under high contention.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

// ─── SpinLock ────────────────────────────────────────────────────────────────

pub struct SpinLock<T> {
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
    data: UnsafeCell<T>,
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
    /// **Do not use this from interrupt handlers** — use `IrqSpinLock` instead.
    #[inline]
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);

        // ── Fast path: tight spin (no pause) ────────────────────────────
        // Try a short burst first.  If the lock is uncontended or the holder
        // is in a very short critical section, we may get it here without
        // ever paying the ~140-cycle `pause` penalty.
        for _ in 0..4 {
            if self.now_serving.load(Ordering::Acquire) == ticket {
                return SpinLockGuard { lock: self };
            }
            core::hint::spin_loop();
        }

        // ── Slow path: pause loop ────────────────────────────────────────
        // Contention is real.  Switch to `pause` to reduce memory-bus
        // traffic and yield bandwidth to the lock holder.
        while self.now_serving.load(Ordering::Acquire) != ticket {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("pause", options(nostack, preserves_flags));
            }
            #[cfg(target_arch = "riscv64")]
            unsafe {
                core::arch::asm!("nop", options(nostack));
            }
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }

    /// Try to acquire without blocking.  Returns `None` on contention.
    #[inline]
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let serving = self.now_serving.load(Ordering::Acquire);
        let next = self.next_ticket.load(Ordering::Relaxed);
        if serving == next {
            if self
                .next_ticket
                .compare_exchange(next, next + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(SpinLockGuard { lock: self });
            }
        }
        None
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        self.now_serving.load(Ordering::Relaxed) != self.next_ticket.load(Ordering::Relaxed)
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<'a, T> core::ops::Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.now_serving.fetch_add(1, Ordering::Release);
    }
}

// ─── IrqSpinLock ─────────────────────────────────────────────────────────────

pub struct IrqSpinLock<T> {
    inner: SpinLock<T>,
}

unsafe impl<T: Send> Send for IrqSpinLock<T> {}
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

impl<T> IrqSpinLock<T> {
    pub const fn new(val: T) -> Self {
        IrqSpinLock {
            inner: SpinLock::new(val),
        }
    }

    #[inline]
    pub fn lock_irqsave(&self) -> IrqSpinLockGuard<'_, T> {
        let irq_was_enabled = irq_flags_and_disable();
        let guard = self.inner.lock();
        core::mem::forget(guard);
        IrqSpinLockGuard {
            lock: self,
            irq_was_enabled,
        }
    }

    #[inline]
    pub fn try_lock_irqsave(&self) -> Option<IrqSpinLockGuard<'_, T>> {
        let irq_was_enabled = irq_flags_and_disable();
        match self.inner.try_lock() {
            Some(guard) => {
                core::mem::forget(guard);
                Some(IrqSpinLockGuard {
                    lock: self,
                    irq_was_enabled,
                })
            }
            None => {
                if irq_was_enabled {
                    irq_enable();
                }
                None
            }
        }
    }
}

pub struct IrqSpinLockGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    irq_was_enabled: bool,
}

impl<'a, T> core::ops::Deref for IrqSpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.inner.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for IrqSpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.inner.data.get() }
    }
}

impl<'a, T> Drop for IrqSpinLockGuard<'a, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.inner.now_serving.fetch_add(1, Ordering::Release);
        if self.irq_was_enabled {
            irq_enable();
        }
    }
}

// ─── Arch-abstracted IRQ helpers ─────────────────────────────────────────────

#[inline]
fn irq_flags_and_disable() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let flags: usize;
        core::arch::asm!(
            "pushfq",
            "pop {f}",
            "cli",
            f = out(reg) flags,
            options(nostack, preserves_flags)
        );
        flags & (1 << 9) != 0
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let sstatus: usize;
        core::arch::asm!(
            "csrrci {ss}, sstatus, 2",
            ss = out(reg) sstatus,
            options(nostack)
        );
        sstatus & (1 << 1) != 0
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    {
        false
    }
}

#[inline]
fn irq_enable() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sti", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("csrsi sstatus, 2", options(nostack));
    }
}
