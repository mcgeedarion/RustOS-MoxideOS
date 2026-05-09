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

// ── sys_waitpid [NR 7 / NR 61] ─────────────────────────────────────────────────

pub fn sys_waitpid(pid: isize, wstatus_va: usize, options: u32) -> isize {
    let caller  = scheduler::current_pid();
    let wnohang = options & WNOHANG != 0;

    loop {
        // ── Look for a matching zombie and reap atomically in one lock window ──
        // Using with_procs (mutable) so find + swap_remove happen without
        // releasing the lock between them — prevents double-reap by threads
        // sharing the same tgid.
        let found: Option<(usize, i32)> = scheduler::with_procs(|procs| {
            let idx = procs.iter().position(|p| {
                p.ppid == caller
                    && p.state == State::Zombie
                    && match pid {
                        -1 | 0 => true,
                        n if n > 0 => p.pid == n as usize,
                        _ => true,
                    }
            });
            idx.map(|i| (procs[i].pid, procs[i].exit_code))
        });

        if let Some((child_pid, exit_code)) = found {
            if wstatus_va != 0 {
                let wstatus: i32 = if exit_code >= 0 {
                    (exit_code & 0xFF) << 8
                } else {
                    ((-exit_code) & 0x7F) as i32
                };
                let _ = copy_to_user(wstatus_va, &wstatus.to_ne_bytes());
            }

            // Reap: O(log n) remove via remove_pid — handles swap_remove +
            // pid_idx fixup + current pointer adjustment atomically.
            scheduler::remove_pid(child_pid);
            return child_pid as isize;
        }

        // ── No zombie found ────────────────────────────────────────────────────
        if wnohang { return 0; }

        // has_child requires a full scan — must check all procs by ppid.
        let has_child = scheduler::with_procs(|procs| {
            procs.iter().any(|p| {
                p.ppid == caller
                    && match pid {
                        -1 | 0 => true,
                        n if n > 0 => p.pid == n as usize,
                        _ => true,
                    }
            })
        });
        if !has_child { return -10; } // ECHILD

        // Block self, yield, re-mark Ready.
        // block_current() resets rt_cpu_time_us for RT tasks per RLIMIT_RTTIME
        // semantics — waiting for a child is a voluntary sleep.
        scheduler::block_current();
        scheduler::schedule();
        scheduler::with_proc_mut(caller, |p| {
            if p.state == State::Blocked { p.state = State::Ready; }
        });
    }
}

// ── wstatus decode helpers ────────────────────────────────────────────────────────

#[inline] pub fn wifexited(ws: i32)   -> bool { (ws & 0x7F) == 0 }
#[inline] pub fn wexitstatus(ws: i32) -> i32  { (ws >> 8) & 0xFF }
#[inline] pub fn wifsignaled(ws: i32) -> bool { (ws & 0x7F) != 0 && (ws & 0x7F) != 0x7F }
#[inline] pub fn wtermsig(ws: i32)    -> i32  { ws & 0x7F }
