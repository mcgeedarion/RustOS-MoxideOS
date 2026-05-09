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

// ── helpers ───────────────────────────────────────────────────────────────────

fn page_align_down(addr: usize) -> usize { addr & !(PAGE_SIZE - 1) }
fn page_align_up(len: usize) -> usize {
    if len == 0 { 0 } else { (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1) }
}

/// Returns true if the caller holds CAP_IPC_LOCK (bypasses RLIMIT_MEMLOCK).
fn has_ipc_lock_cap() -> bool {
    let pid = current_pid();
    with_proc_mut(pid, |p| p.caps.has(crate::security::Cap::IpcLock))
        .unwrap_or(false)
}

/// Charge `bytes` against the process's locked-bytes counter.
/// Returns -ENOMEM if the soft limit would be exceeded (unless privileged).
fn charge_lock_bytes(bytes: usize) -> isize {
    if bytes == 0 { return 0; }
    let pid = current_pid();
    with_proc_mut(pid, |p| {
        let (soft, _) = p.rlimits.get(RLIMIT_MEMLOCK);
        let privileged = p.caps.has(crate::security::Cap::IpcLock);
        if !privileged {
            let new_total = p.locked_bytes.saturating_add(bytes as u64);
            if soft != crate::proc::rlimit::RLIM_INFINITY && new_total > soft {
                return -12isize; // ENOMEM
            }
        }
        p.locked_bytes = p.locked_bytes.saturating_add(bytes as u64);
        0isize
    }).unwrap_or(-3) // ESRCH
}

fn discharge_lock_bytes(bytes: usize) {
    if bytes == 0 { return; }
    let pid = current_pid();
    let _ = with_proc_mut(pid, |p| {
        p.locked_bytes = p.locked_bytes.saturating_sub(bytes as u64);
    });
}

// ── mlock ─────────────────────────────────────────────────────────────────────

/// `sys_mlock(addr, len)` — NR 149
pub fn sys_mlock(addr: usize, len: usize) -> isize {
    sys_mlock2(addr, len, 0)
}

/// `sys_mlock2(addr, len, flags)` — NR 325
/// `flags` may include `MLOCK_ONFAULT`; we treat it identically to 0 for now.
pub fn sys_mlock2(addr: usize, len: usize, _flags: u32) -> isize {
    let base  = page_align_down(addr);
    let plen  = page_align_up(len + (addr - base));
    if plen == 0 { return 0; }
    let end   = base.checked_add(plen).unwrap_or(usize::MAX);

    let pid = current_pid();

    // Count bytes not yet locked in this range.
    let newly_locked = with_proc_mut(pid, |p| {
        let mut new_bytes: usize = 0;
        for vma in p.vmas.iter_mut() {
            let vstart = vma.start.max(base);
            let vend   = vma.end.min(end);
            if vstart >= vend { continue; }
            if !vma.locked {
                new_bytes += vend - vstart;
                vma.locked = true;
            }
        }
        new_bytes
    }).unwrap_or(0);

    if newly_locked == 0 { return 0; }
    let rc = charge_lock_bytes(newly_locked);
    if rc < 0 {
        // Roll back VMA flags.
        let _ = with_proc_mut(pid, |p| {
            for vma in p.vmas.iter_mut() {
                let vstart = vma.start.max(base);
                let vend   = vma.end.min(end);
                if vstart >= vend { continue; }
                vma.locked = false;
            }
        });
        return rc;
    }
    0
}

// ── munlock ───────────────────────────────────────────────────────────────────

/// `sys_munlock(addr, len)` — NR 150
pub fn sys_munlock(addr: usize, len: usize) -> isize {
    let base = page_align_down(addr);
    let plen = page_align_up(len + (addr - base));
    if plen == 0 { return 0; }
    let end  = base.checked_add(plen).unwrap_or(usize::MAX);

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

// ── mlockall ──────────────────────────────────────────────────────────────────

/// `sys_mlockall(flags)` — NR 151
pub fn sys_mlockall(flags: u32) -> isize {
    if flags == 0 || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
        return -22; // EINVAL
    }
    let pid = current_pid();

    if flags & MCL_FUTURE != 0 {
        let _ = with_proc_mut(pid, |p| { p.mcl_future = true; });
    }

    if flags & MCL_CURRENT != 0 {
        // Lock every VMA that isn't already locked.
        let newly_locked = with_proc_mut(pid, |p| {
            let mut bytes: usize = 0;
            for vma in p.vmas.iter_mut() {
                if !vma.locked {
                    bytes += vma.end - vma.start;
                    vma.locked = true;
                }
            }
            bytes
        }).unwrap_or(0);

        if newly_locked > 0 {
            let rc = charge_lock_bytes(newly_locked);
            if rc < 0 {
                // Roll back.
                let _ = with_proc_mut(pid, |p| {
                    for vma in p.vmas.iter_mut() { vma.locked = false; }
                    p.mcl_future = false;
                    p.locked_bytes = 0;
                });
                return rc;
            }
        }
    }
    0
}

// ── munlockall ────────────────────────────────────────────────────────────────

/// `sys_munlockall()` — NR 152
pub fn sys_munlockall() -> isize {
    let pid = current_pid();
    let _ = with_proc_mut(pid, |p| {
        p.mcl_future  = false;
        p.locked_bytes = 0;
        for vma in p.vmas.iter_mut() { vma.locked = false; }
    });
    0
}
