//! waitpid / wait4 and process-exit notification.

use crate::proc::process::State;
use crate::proc::scheduler;
use crate::uaccess::copy_to_user;

pub const WNOHANG:   u32 = 1;
pub const WUNTRACED: u32 = 2;

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

// ── pid match predicate ───────────────────────────────────────────────────────

#[inline]
fn matches_pid(p_pid: usize, wait_pid: isize) -> bool {
    match wait_pid {
        -1 | 0 => true,
        n if n > 0 => p_pid == n as usize,
        _ => true,
    }
}

// ── sys_waitpid [NR 7 / NR 61] ─────────────────────────────────────────────────

/// One-shot result of a single scan of the process list.
enum WaitScan {
    /// Found a zombie: already removed from the list, carries (pid, exit_code).
    Reaped(usize, i32),
    /// No zombie yet, but at least one living child exists — caller should block.
    HasLiving,
    /// No child at all matching the criteria.
    NoChild,
}

pub fn sys_waitpid(pid: isize, wstatus_va: usize, options: u32) -> isize {
    let caller  = scheduler::current_pid();
    let wnohang = options & WNOHANG != 0;

    loop {
        // ── Single O(n) scan: find-or-check atomically in one lock window ─────
        //
        // Combining the zombie search and the has_child check into one
        // with_procs closure:
        //   1. Prevents double-reap: a sibling sharing the same tgid cannot
        //      steal the zombie between find and remove (B2).
        //   2. Cuts per-iteration lock acquisitions from 2 to 1 and the
        //      scan count from 2×O(n) to 1×O(n) (M4).
        let scan = scheduler::with_procs(|procs| {
            // Look for a matching zombie first.
            if let Some(idx) = procs.iter().position(|p| {
                p.ppid == caller
                    && p.state == State::Zombie
                    && matches_pid(p.pid, pid)
            }) {
                // Remove while still inside the lock — atomic find + reap.
                let reaped = procs.swap_remove(idx);
                return WaitScan::Reaped(reaped.pid, reaped.exit_code);
            }

            // No zombie: check whether any living child matches.
            let any_child = procs.iter().any(|p| {
                p.ppid == caller && matches_pid(p.pid, pid)
            });

            if any_child { WaitScan::HasLiving } else { WaitScan::NoChild }
        });

        match scan {
            WaitScan::Reaped(child_pid, exit_code) => {
                if wstatus_va != 0 {
                    let wstatus: i32 = if exit_code >= 0 {
                        (exit_code & 0xFF) << 8
                    } else {
                        ((-exit_code) & 0x7F) as i32
                    };
                    let _ = copy_to_user(wstatus_va, &wstatus.to_ne_bytes());
                }
                return child_pid as isize;
            }

            WaitScan::NoChild => return -10, // ECHILD

            WaitScan::HasLiving => {
                if wnohang { return 0; }

                // Block self, yield, re-mark Ready on wakeup.
                // block_current() resets rt_cpu_time_us for RT tasks per
                // RLIMIT_RTTIME semantics — waiting for a child is voluntary.
                scheduler::block_current();
                scheduler::schedule();
                scheduler::with_proc_mut(caller, |p| {
                    if p.state == State::Blocked { p.state = State::Ready; }
                });
            }
        }
    }
}

// ── wstatus decode helpers ────────────────────────────────────────────────────

#[inline] pub fn wifexited(ws: i32)   -> bool { (ws & 0x7F) == 0 }
#[inline] pub fn wexitstatus(ws: i32) -> i32  { (ws >> 8) & 0xFF }
#[inline] pub fn wifsignaled(ws: i32) -> bool { (ws & 0x7F) != 0 && (ws & 0x7F) != 0x7F }
#[inline] pub fn wtermsig(ws: i32)    -> i32  { ws & 0x7F }
