//! `mlock(2)` / `munlock(2)` / `mlockall(2)` / `munlockall(2)`
//!
//! ## What this does
//!
//! - Marks VMA ranges as `MAP_LOCKED` so the pager never evicts them.
//!   (We have no swapper yet, so the only real effect is accounting.)
//! - Charges / refunds the per-process **locked-bytes** counter against
//!   `RLIMIT_MEMLOCK`.  The counter is stored in `Pcb::locked_bytes`.
//!
//! ## Linux semantics mirrored
//!
//! - `mlock(addr, len)` — rounds `addr` down to page boundary, `len` up.
//!   Only pages not already locked are counted toward the limit.
//! - `munlock(addr, len)` — unlocks matching pages; refunds the counter.
//! - `mlockall(MCL_CURRENT)` — locks all current VMAs.
//! - `mlockall(MCL_FUTURE)` — sets a flag; subsequent `mmap` calls auto-lock.
//! - `munlockall()` — clears MCL_FUTURE, unlocks everything.
//!
//! ## RLIMIT_MEMLOCK
//!
//! The soft limit is the ceiling for unprivileged processes.  CAP_IPC_LOCK
//! (or CAP_SYS_ADMIN on old kernels) bypasses the limit; we model this by
//! checking `pcb.caps.has(CAP_IPC_LOCK)`.

extern crate alloc;

use crate::proc::scheduler::{current_pid, with_proc_mut};
use crate::proc::rlimit::RLIMIT_MEMLOCK;

const PAGE_SIZE: usize = 4096;

// MCL_* flags (Linux values)
pub const MCL_CURRENT: u32 = 1;
pub const MCL_FUTURE:  u32 = 2;
pub const MCL_ONFAULT: u32 = 4;

// errno constants
const ENOMEM: isize = -12;
const EINVAL: isize = -22;
const ESRCH:  isize = -3;

// ── helpers ───────────────────────────────────────────────────────────────────────

fn page_align_down(addr: usize) -> usize { addr & !(PAGE_SIZE - 1) }

/// Page-align `len` upward.  Returns `None` on overflow.
fn page_align_up_checked(len: usize) -> Option<usize> {
    if len == 0 { return Some(0); }
    len.checked_add(PAGE_SIZE - 1).map(|v| v & !(PAGE_SIZE - 1))
}

/// Compute the page-aligned (base, len) for a (addr, len) range.
/// Returns None if addr+len overflows or the resulting aligned len overflows.
fn align_range(addr: usize, len: usize) -> Option<(usize, usize)> {
    let base     = page_align_down(addr);
    let tail     = addr - base;               // bytes from base to addr
    let full_len = len.checked_add(tail)?;    // total span in bytes
    let plen     = page_align_up_checked(full_len)?;
    let _end     = base.checked_add(plen)?;   // verify [base, base+plen) doesn't wrap
    Some((base, plen))
}

/// Charge `bytes` against the process's locked-bytes counter.
/// Returns ENOMEM if the soft limit would be exceeded (unless privileged).
fn charge_lock_bytes(bytes: usize) -> isize {
    if bytes == 0 { return 0; }
    let pid = current_pid();
    with_proc_mut(pid, |p| {
        let (soft, _) = p.rlimits.get(RLIMIT_MEMLOCK);
        let privileged = p.caps.has(crate::security::Cap::IpcLock);
        if !privileged {
            let new_total = p.locked_bytes.saturating_add(bytes as u64);
            if soft != crate::proc::rlimit::RLIM_INFINITY && new_total > soft {
                return ENOMEM;
            }
        }
        p.locked_bytes = p.locked_bytes.saturating_add(bytes as u64);
        0isize
    }).unwrap_or(ESRCH)
}

fn discharge_lock_bytes(bytes: usize) {
    if bytes == 0 { return; }
    let pid = current_pid();
    let _ = with_proc_mut(pid, |p| {
        p.locked_bytes = p.locked_bytes.saturating_sub(bytes as u64);
    });
}

// ── mlock ────────────────────────────────────────────────────────────────────────────

/// `sys_mlock(addr, len)` — NR 149
pub fn sys_mlock(addr: usize, len: usize) -> isize {
    sys_mlock2(addr, len, 0)
}

/// `sys_mlock2(addr, len, flags)` — NR 325
/// `flags` may include `MLOCK_ONFAULT`; we treat it identically to 0 for now.
pub fn sys_mlock2(addr: usize, len: usize, _flags: u32) -> isize {
    let (base, plen) = match align_range(addr, len) {
        Some(r) => r,
        None    => return EINVAL, // address-space overflow
    };
    if plen == 0 { return 0; }
    let end = base + plen; // safe: align_range verified no wrap

    let pid = current_pid();

    // ── Step 1: dry run — count newly-lockable bytes without touching flags.
    //
    // We check the limit BEFORE marking any VMAs so there is no window
    // where another observer sees locked==true on pages whose charge was
    // subsequently rejected (TOCTOU fix).
    let newly_locked = with_proc_mut(pid, |p| {
        let mut n: usize = 0;
        for vma in p.vmas.iter() {
            let vstart = vma.start.max(base);
            let vend   = vma.end.min(end);
            if vstart < vend && !vma.locked {
                n += vend - vstart;
            }
        }
        n
    }).unwrap_or(0);

    if newly_locked == 0 { return 0; }

    // ── Step 2: charge against RLIMIT_MEMLOCK.
    let rc = charge_lock_bytes(newly_locked);
    if rc < 0 { return rc; }

    // ── Step 3: charge accepted — now mark the VMAs.
    let _ = with_proc_mut(pid, |p| {
        for vma in p.vmas.iter_mut() {
            let vstart = vma.start.max(base);
            let vend   = vma.end.min(end);
            if vstart < vend && !vma.locked {
                vma.locked = true;
            }
        }
    });

    0
}

// ── munlock ───────────────────────────────────────────────────────────────────────────

/// `sys_munlock(addr, len)` — NR 150
pub fn sys_munlock(addr: usize, len: usize) -> isize {
    let (base, plen) = match align_range(addr, len) {
        Some(r) => r,
        None    => return EINVAL,
    };
    if plen == 0 { return 0; }
    let end = base + plen;

    let pid = current_pid();
    let freed = with_proc_mut(pid, |p| {
        let mut bytes: usize = 0;
        for vma in p.vmas.iter_mut() {
            let vstart = vma.start.max(base);
            let vend   = vma.end.min(end);
            if vstart >= vend { continue; }
            if vma.locked {
                bytes += vend - vstart;
                vma.locked = false;
            }
        }
        bytes
    }).unwrap_or(0);

    discharge_lock_bytes(freed);
    0
}

// ── mlockall ─────────────────────────────────────────────────────────────────────────

/// `sys_mlockall(flags)` — NR 151
pub fn sys_mlockall(flags: u32) -> isize {
    if flags == 0 || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
        return EINVAL;
    }
    let pid = current_pid();

    if flags & MCL_FUTURE != 0 {
        let _ = with_proc_mut(pid, |p| { p.mcl_future = true; });
    }

    if flags & MCL_CURRENT != 0 {
        // ── Step 1: dry run — count newly-lockable bytes and save pre-call state.
        let (newly_locked, saved_bytes) = with_proc_mut(pid, |p| {
            let saved = p.locked_bytes;
            let mut bytes: usize = 0;
            for vma in p.vmas.iter() {
                if !vma.locked {
                    bytes += vma.end - vma.start;
                }
            }
            (bytes, saved)
        }).unwrap_or((0, 0));

        if newly_locked > 0 {
            // ── Step 2: charge against RLIMIT_MEMLOCK.
            let rc = charge_lock_bytes(newly_locked);
            if rc < 0 {
                // Roll back: restore exactly the pre-call locked_bytes value
                // (not zero — that would wipe pre-existing locked regions).
                let _ = with_proc_mut(pid, |p| {
                    for vma in p.vmas.iter_mut() { vma.locked = false; }
                    p.mcl_future  = false;
                    p.locked_bytes = saved_bytes; // restore, not zero
                });
                return rc;
            }

            // ── Step 3: charge accepted — mark all VMAs.
            let _ = with_proc_mut(pid, |p| {
                for vma in p.vmas.iter_mut() {
                    if !vma.locked {
                        vma.locked = true;
                    }
                }
            });
        }
    }
    0
}

// ── munlockall ─────────────────────────────────────────────────────────────────────

/// `sys_munlockall()` — NR 152
pub fn sys_munlockall() -> isize {
    let pid = current_pid();
    let _ = with_proc_mut(pid, |p| {
        p.mcl_future   = false;
        p.locked_bytes = 0;
        for vma in p.vmas.iter_mut() { vma.locked = false; }
    });
    0
}
