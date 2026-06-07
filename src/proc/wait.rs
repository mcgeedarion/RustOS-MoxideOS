//! waitpid / wait4 and process-exit / process-stop notification.
//!
//! ## wstatus bit layout (matches Linux / POSIX):
//!
//!   Normal exit:   `(exit_code & 0xFF) << 8`          — WIFEXITED true
//!   Signal kill:   `(signum & 0x7F) | (core << 7)`    — WIFSIGNALED true
//!   Stopped:       `(stopsig << 8) | 0x7F`             — WIFSTOPPED true
//!   Continued:     `0xFFFF`                             — WIFCONTINUED true
//!
//! ## Locking notes (post-S2)
//!
//!   - `with_procs_ro` returns a snapshot `Vec<Arc<ProcLock>>`. `ProcLock`
//!     exposes `pid` and `tgid` directly.  `ppid`, `pgid`, `state`,
//!     `exit_code`, `cpu_time_ns` require locking `ProcLock::inner`.
//!   - The scan loop takes each inner lock once per iteration.  There is no
//!     try_lock pre-filter (that pattern caused TOCTOU double-lock on SMP).
//!   - `with_procs_mut` is used only for structural mutations (reap/state
//!     change) and is held for the minimum time.

use crate::proc::process::State;
use crate::proc::scheduler;
use crate::uaccess::{copy_to_user, copy_to_user_value};

#[inline]
pub fn encode_exit(code: i32) -> i32 {
    (code & 0xFF) << 8
}

#[inline]
pub fn encode_signal(signum: u32, coredump: bool) -> i32 {
    ((signum & 0x7F) | if coredump { 0x80 } else { 0 }) as i32
}

#[inline]
pub fn encode_stop(stopsig: u32) -> i32 {
    ((stopsig & 0xFF) << 8) as i32 | 0x7F
}

pub const WSTATUS_CONTINUED: i32 = 0xFFFF;

pub const WNOHANG: u32 = 1;
pub const WUNTRACED: u32 = 2;
pub const WCONTINUED: u32 = 8;
pub const WNOWAIT: u32 = 0x01000000;

const RUSAGE_SIZE: usize = 144;

fn write_rusage(va: usize, utime_ns: u64, stime_ns: u64) {
    if va == 0 {
        return;
    }
    let mut buf = [0u8; RUSAGE_SIZE];
    // ru_utime (bytes 0..16)
    let us = utime_ns / 1_000_000_000;
    let uus = (utime_ns % 1_000_000_000) / 1_000;
    buf[0..8].copy_from_slice(&us.to_ne_bytes());
    buf[8..16].copy_from_slice(&uus.to_ne_bytes());
    // ru_stime (bytes 16..32)
    let ss = stime_ns / 1_000_000_000;
    let sus = (stime_ns % 1_000_000_000) / 1_000;
    buf[16..24].copy_from_slice(&ss.to_ne_bytes());
    buf[24..32].copy_from_slice(&sus.to_ne_bytes());
    let _ = crate::uaccess::copy_to_user_value(va, &buf);
}

pub fn notify_exit(exited_pid: usize) {
    let (ppid, exit_signal) =
        scheduler::with_proc(exited_pid, |p| (p.ppid, p.exit_signal)).unwrap_or((0, 17));
    if ppid == 0 {
        return;
    }

    // Wake the parent's thread group — any thread can collect the child.
    scheduler::wake_pid(ppid);

    if exit_signal != 0 {
        // SIGCHLD (or custom exit_signal) is group-directed: deliver to the
        // parent's process group, not just the ppid TID.
        let parent_tgid = {
            let t = crate::proc::thread::tgid_of(ppid);
            if t != 0 {
                t
            } else {
                ppid
            }
        };
        crate::proc::signal::send_signal_group(parent_tgid, exit_signal as i32);
    }
}

pub fn notify_stop(stopped_pid: usize, stopsig: u32) {
    scheduler::with_proc_mut(stopped_pid, |p, pl| {
        p.exit_code = encode_stop(stopsig);
        pl.set_state(p, State::Stopped);
    });

    let ppid = scheduler::with_proc(stopped_pid, |p| p.ppid).unwrap_or(0);
    if ppid == 0 {
        return;
    }
    scheduler::wake_pid(ppid);

    const SIGCHLD: usize = 17;
    const SA_NOCLDSTOP: u32 = 1;

    let nocldstop = scheduler::with_proc(ppid, |p| {
        let h = p.signal_handlers.lock();
        h.flags
            .get(SIGCHLD)
            .map(|&f| f & SA_NOCLDSTOP != 0)
            .unwrap_or(false)
    })
    .unwrap_or(false);

    if !nocldstop {
        // Group-directed: any unblocked thread in the parent may handle it.
        let parent_tgid = {
            let t = crate::proc::thread::tgid_of(ppid);
            if t != 0 {
                t
            } else {
                ppid
            }
        };
        crate::proc::signal::send_signal_group(parent_tgid, SIGCHLD as i32);
    }
}

pub fn notify_continue(cont_pid: usize) {
    scheduler::with_proc_mut(cont_pid, |p, pl| {
        p.exit_code = WSTATUS_CONTINUED;
        pl.set_state(p, State::Continued);
    });
    let ppid = scheduler::with_proc(cont_pid, |p| p.ppid).unwrap_or(0);
    if ppid != 0 {
        scheduler::wake_pid(ppid);
    }
}

#[inline]
fn matches_pid(p_pid: usize, p_pgid: usize, wait_pid: isize) -> bool {
    match wait_pid {
        -1 => true,
        0 => true,
        n if n > 0 => p_pid == n as usize,
        n => p_pgid == (-n) as usize,
    }
}

enum WaitHit {
    Harvested {
        child_pid: usize,
        wstatus: i32,
        utime_ns: u64,
        stime_ns: u64,
    },
    /// Matching children exist but none are in a waitable state yet.
    HasLiving,
    /// No child matches the requested pid/pgid at all.
    NoChild,
}

pub fn sys_waitpid(pid: isize, wstatus_va: usize, options: u32) -> isize {
    sys_wait4_impl(pid, wstatus_va, options, 0)
}

pub fn sys_wait4(pid: isize, wstatus_va: usize, options: u32, rusage_va: usize) -> isize {
    sys_wait4_impl(pid, wstatus_va, options, rusage_va)
}

fn sys_wait4_impl(pid: isize, wstatus_va: usize, options: u32, rusage_va: usize) -> isize {
    let caller = scheduler::current_pid();
    let wnohang = options & WNOHANG != 0;
    let wuntraced = options & WUNTRACED != 0;
    let wcont = options & WCONTINUED != 0;
    let nowait = options & WNOWAIT != 0;

    loop {
        // Snapshot Arc vec; table lock released before we touch any inner lock.
        let hit = scheduler::with_procs_ro(|pl_vec| {
            let mut any_child = false;

            for pl in pl_vec.iter() {
                // Single lock call — no try_lock pre-filter (TOCTOU / deadlock risk).
                let inner = pl.inner.lock();
                let p_pid = inner.pid;
                let p_ppid = inner.ppid;
                let p_pgid = inner.pgid;
                let p_state = inner.state;

                if p_ppid != caller {
                    continue;
                }
                if !matches_pid(p_pid, p_pgid, pid) {
                    continue;
                }

                // At least one matching child found.
                any_child = true;

                match p_state {
                    State::Zombie => {
                        return WaitHit::Harvested {
                            child_pid: p_pid,
                            wstatus: inner.exit_code,
                            utime_ns: inner.utime_ns,
                            stime_ns: inner.stime_ns,
                        };
                    },
                    State::Stopped if wuntraced => {
                        return WaitHit::Harvested {
                            child_pid: p_pid,
                            wstatus: inner.exit_code,
                            utime_ns: inner.utime_ns,
                            stime_ns: inner.stime_ns,
                        };
                    },
                    State::Continued if wcont => {
                        return WaitHit::Harvested {
                            child_pid: p_pid,
                            wstatus: WSTATUS_CONTINUED,
                            utime_ns: inner.utime_ns,
                            stime_ns: inner.stime_ns,
                        };
                    },
                    _ => {},
                }
                // Drop inner lock before moving to the next entry.
                drop(inner);
            }

            if any_child {
                WaitHit::HasLiving
            } else {
                WaitHit::NoChild
            }
        });

        match hit {
            WaitHit::Harvested {
                child_pid,
                wstatus,
                utime_ns,
                stime_ns,
            } => {
                if !nowait {
                    scheduler::with_proc_mut(child_pid, |p, pl| {
                        match p.state {
                            State::Zombie => { /* reap below */ },
                            State::Stopped => {
                                pl.set_state(p, State::StopReported);
                            },
                            State::Continued => {
                                pl.set_state(p, State::Ready);
                                p.exit_code = 0;
                            },
                            _ => {},
                        }
                    });
                    // Remove zombie from table.
                    let is_zombie = scheduler::with_proc(child_pid, |p| p.state == State::Zombie)
                        .unwrap_or(false);
                    if is_zombie {
                        scheduler::with_procs_mut(|pl_vec| {
                            if let Some(idx) =
                                pl_vec.iter().position(|pl| pl.pid as usize == child_pid)
                            {
                                pl_vec.swap_remove(idx);
                            }
                        });
                    }
                }

                if wstatus_va != 0 {
                    let _ = crate::uaccess::copy_to_user_value(wstatus_va, &wstatus.to_ne_bytes());
                }
                write_rusage(rusage_va, utime_ns, stime_ns);
                return child_pid as isize;
            },

            // POSIX: WNOHANG + matching children exist but none waitable -> 0.
            WaitHit::HasLiving => {
                if wnohang {
                    return 0;
                }
                scheduler::block_current();
                if crate::proc::signal::has_pending_signal(caller) {
                    return -4; // EINTR
                }
            },

            WaitHit::NoChild => return -10, // ECHILD
        }
    }
}

#[inline]
pub fn wifexited(ws: i32) -> bool {
    (ws & 0x7F) == 0
}
#[inline]
pub fn wexitstatus(ws: i32) -> i32 {
    (ws >> 8) & 0xFF
}
#[inline]
pub fn wifsignaled(ws: i32) -> bool {
    let l = ws & 0x7F;
    l != 0 && l != 0x7F
}
#[inline]
pub fn wtermsig(ws: i32) -> i32 {
    ws & 0x7F
}
#[inline]
pub fn wcoredump(ws: i32) -> bool {
    ws & 0x80 != 0
}
#[inline]
pub fn wifstopped(ws: i32) -> bool {
    (ws & 0xFF) == 0x7F
}
#[inline]
pub fn wstopsig(ws: i32) -> i32 {
    (ws >> 8) & 0xFF
}
#[inline]
pub fn wifcontinued(ws: i32) -> bool {
    ws == WSTATUS_CONTINUED
}
