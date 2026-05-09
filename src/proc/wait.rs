//! waitpid / wait4 and process-exit / process-stop notification.
//!
//! ## wstatus bit layout (matches Linux / POSIX):
//!
//!   Normal exit:   `(exit_code & 0xFF) << 8`          — WIFEXITED true
//!   Signal kill:   `(signum & 0x7F) | (core << 7)`    — WIFSIGNALED true
//!   Stopped:       `(stopsig << 8) | 0x7F`             — WIFSTOPPED true
//!   Continued:     `0xFFFF`                             — WIFCONTINUED true
//!
//! ## Bug fixes in this revision
//!
//! ### Zombie processes were never reaped (swap_remove on shared ref)
//!   The scan loop called `with_procs(|procs| { procs.swap_remove(idx) })`,
//!   but `with_procs` passes `&Vec<Pcb>` (shared), not `&mut Vec<Pcb>`.
//!   `swap_remove` on a shared reference is a compile error (or, on an
//!   older draft that somehow compiled, a no-op).  Every zombie stayed in
//!   PROCS forever (zombie leak + process table growth).
//!   Fixed: split into a read-only scan pass followed by a separate
//!   `with_procs_mut` reap pass guarded by `!nowait`.
//!
//! ### notify_stop used signal_handlers.get() which doesn't exist
//!   `SignalHandlers` is a plain struct with fixed-size arrays, not a
//!   collection. `.get(idx)` is undefined on it.  Fixed by direct array
//!   indexing: `p.signal_handlers.flags[SIGCHLD as usize]`.
//!
//! ### wait loop called block_current() then schedule() again
//!   `block_current()` already ends with `schedule()` internally.
//!   The extra `scheduler::schedule()` after it caused the thread to
//!   yield twice per wakeup iteration.  Removed the redundant call.

use crate::proc::process::State;
use crate::proc::scheduler;
use crate::uaccess::copy_to_user;

// ── wstatus encoding ──────────────────────────────────────────────────────────────

#[inline]
pub fn encode_exit(code: i32) -> i32 { (code & 0xFF) << 8 }

#[inline]
pub fn encode_signal(signum: u32, coredump: bool) -> i32 {
    ((signum & 0x7F) | if coredump { 0x80 } else { 0 }) as i32
}

#[inline]
pub fn encode_stop(stopsig: u32) -> i32 {
    ((stopsig & 0xFF) << 8) as i32 | 0x7F
}

pub const WSTATUS_CONTINUED: i32 = 0xFFFF;

// ── option flags ───────────────────────────────────────────────────────────────

pub const WNOHANG:    u32 = 1;
pub const WUNTRACED:  u32 = 2;
pub const WCONTINUED: u32 = 8;
pub const WNOWAIT:    u32 = 0x01000000;

// ── rusage ───────────────────────────────────────────────────────────────────

const RUSAGE_SIZE: usize = 144;

fn write_rusage(va: usize, cpu_ns: u64) {
    if va == 0 { return; }
    let mut buf = [0u8; RUSAGE_SIZE];
    let tv_sec  = cpu_ns / 1_000_000_000;
    let tv_usec = (cpu_ns % 1_000_000_000) / 1_000;
    buf[0..8].copy_from_slice(&tv_sec.to_ne_bytes());
    buf[8..16].copy_from_slice(&tv_usec.to_ne_bytes());
    let _ = copy_to_user(va, &buf);
}

// ── notify_exit ────────────────────────────────────────────────────────────────

pub fn notify_exit(exited_pid: usize) {
    let (ppid, exit_signal) = scheduler::with_proc(exited_pid, |p| (p.ppid, p.exit_signal))
        .unwrap_or((0, 17));
    if ppid == 0 { return; }
    scheduler::wake_pid(ppid);
    if exit_signal != 0 {
        crate::proc::signal::send_signal(ppid, exit_signal);
    }
}

// ── notify_stop ────────────────────────────────────────────────────────────────

pub fn notify_stop(stopped_pid: usize, stopsig: u32) {
    scheduler::with_proc_mut(stopped_pid, |p| {
        p.exit_code = encode_stop(stopsig);
    });

    let ppid = scheduler::with_proc(stopped_pid, |p| p.ppid).unwrap_or(0);
    if ppid == 0 { return; }
    scheduler::wake_pid(ppid);

    const SIGCHLD: usize = 17;
    const SA_NOCLDSTOP: u32 = 1;

    // FIX: SignalHandlers has no .get() method; access the arrays directly.
    let nocldstop = scheduler::with_proc(ppid, |p| {
        p.signal_handlers.flags[SIGCHLD] & SA_NOCLDSTOP != 0
    }).unwrap_or(false);

    if !nocldstop {
        crate::proc::signal::send_signal(ppid, SIGCHLD as i32);
    }
}

// ── notify_continue ─────────────────────────────────────────────────────────────

pub fn notify_continue(cont_pid: usize) {
    scheduler::with_proc_mut(cont_pid, |p| {
        p.exit_code = WSTATUS_CONTINUED;
        p.state = State::Continued;
    });
    let ppid = scheduler::with_proc(cont_pid, |p| p.ppid).unwrap_or(0);
    if ppid != 0 { scheduler::wake_pid(ppid); }
}

// ── pid / pgid match predicate ──────────────────────────────────────────────────────

#[inline]
fn matches_pid(p_pid: usize, p_pgid: usize, wait_pid: isize) -> bool {
    match wait_pid {
        -1       => true,
        0        => true,
        n if n > 0 => p_pid == n as usize,
        n        => p_pgid == (-n) as usize,
    }
}

// ── one-shot scan result ────────────────────────────────────────────────────────────

enum WaitScan {
    Harvested { child_pid: usize, wstatus: i32, cpu_ns: u64 },
    HasLiving,
    NoChild,
}

// ── sys_waitpid / sys_wait4 ──────────────────────────────────────────────────────────

pub fn sys_waitpid(pid: isize, wstatus_va: usize, options: u32) -> isize {
    sys_wait4_impl(pid, wstatus_va, options, 0)
}

pub fn sys_wait4(pid: isize, wstatus_va: usize, options: u32, rusage_va: usize) -> isize {
    sys_wait4_impl(pid, wstatus_va, options, rusage_va)
}

fn sys_wait4_impl(pid: isize, wstatus_va: usize, options: u32, rusage_va: usize) -> isize {
    let caller    = scheduler::current_pid();
    let wnohang   = options & WNOHANG    != 0;
    let wuntraced = options & WUNTRACED  != 0;
    let wcont     = options & WCONTINUED != 0;
    let nowait    = options & WNOWAIT    != 0;

    loop {
        // ── Read-only scan pass ───────────────────────────────────────────────────
        // FIX: previously used with_procs (shared ref) and called swap_remove
        // on it, which cannot compile/mutate. Now we do a pure read scan here
        // and a separate mutable reap below.
        let scan = scheduler::with_procs(|procs| {
            // 1. Zombie
            if let Some(idx) = procs.iter().position(|p| {
                p.ppid == caller
                    && p.state == State::Zombie
                    && matches_pid(p.pid, p.pgid, pid)
            }) {
                let cpu_ns    = procs[idx].cpu_time_ns;
                let wstatus   = procs[idx].exit_code;
                let child_pid = procs[idx].pid;
                return WaitScan::Harvested { child_pid, wstatus, cpu_ns };
            }

            // 2. WUNTRACED: stopped child
            if wuntraced {
                if let Some(idx) = procs.iter().position(|p| {
                    p.ppid == caller
                        && p.state == State::Stopped
                        && matches_pid(p.pid, p.pgid, pid)
                }) {
                    let cpu_ns    = procs[idx].cpu_time_ns;
                    let wstatus   = procs[idx].exit_code;
                    let child_pid = procs[idx].pid;
                    return WaitScan::Harvested { child_pid, wstatus, cpu_ns };
                }
            }

            // 3. WCONTINUED: continued child
            if wcont {
                if let Some(idx) = procs.iter().position(|p| {
                    p.ppid == caller
                        && p.state == State::Continued
                        && matches_pid(p.pid, p.pgid, pid)
                }) {
                    let cpu_ns    = procs[idx].cpu_time_ns;
                    let child_pid = procs[idx].pid;
                    return WaitScan::Harvested { child_pid, wstatus: WSTATUS_CONTINUED, cpu_ns };
                }
            }

            // 4. Any living matching child?
            let any_child = procs.iter().any(|p| {
                p.ppid == caller && matches_pid(p.pid, p.pgid, pid)
            });
            if any_child { WaitScan::HasLiving } else { WaitScan::NoChild }
        });

        match scan {
            WaitScan::Harvested { child_pid, wstatus, cpu_ns } => {
                // ── Mutable reap / state-transition pass ─────────────────────
                if !nowait {
                    scheduler::with_procs_mut(|procs| {
                        if let Some(idx) = procs.iter().position(|p| p.pid == child_pid) {
                            match procs[idx].state {
                                State::Zombie => {
                                    // Reap: remove from process table.
                                    procs.swap_remove(idx);
                                }
                                State::Stopped => {
                                    // Transition to StopReported so we don't
                                    // re-report the same stop event.
                                    procs[idx].state = State::StopReported;
                                }
                                State::Continued => {
                                    // Back to runnable after reporting.
                                    procs[idx].state = State::Ready;
                                    procs[idx].exit_code = 0;
                                }
                                _ => {}
                            }
                        }
                    });
                }

                if wstatus_va != 0 {
                    let _ = copy_to_user(wstatus_va, &wstatus.to_ne_bytes());
                }
                write_rusage(rusage_va, cpu_ns);
                return child_pid as isize;
            }

            WaitScan::NoChild => return -10, // ECHILD

            WaitScan::HasLiving => {
                if wnohang { return 0; }

                // FIX: block_current() already calls schedule() internally.
                // The old code called schedule() again after it, causing the
                // thread to yield twice per wakeup iteration.
                scheduler::block_current();
                // Returns here when wake_pid() makes us runnable again.

                // If a signal is pending, return EINTR.
                let sig_pending = crate::proc::signal::has_pending_signal(caller);
                if sig_pending { return -4; } // EINTR
            }
        }
    }
}

// ── wstatus decode helpers ───────────────────────────────────────────────────────────

#[inline] pub fn wifexited(ws: i32)    -> bool { (ws & 0x7F) == 0 }
#[inline] pub fn wexitstatus(ws: i32)  -> i32  { (ws >> 8) & 0xFF }
#[inline] pub fn wifsignaled(ws: i32)  -> bool { let l = ws & 0x7F; l != 0 && l != 0x7F }
#[inline] pub fn wtermsig(ws: i32)     -> i32  { ws & 0x7F }
#[inline] pub fn wcoredump(ws: i32)    -> bool { ws & 0x80 != 0 }
#[inline] pub fn wifstopped(ws: i32)   -> bool { (ws & 0xFF) == 0x7F }
#[inline] pub fn wstopsig(ws: i32)     -> i32  { (ws >> 8) & 0xFF }
#[inline] pub fn wifcontinued(ws: i32) -> bool { ws == WSTATUS_CONTINUED }
