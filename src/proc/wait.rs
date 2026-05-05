//! waitpid / wait4 and process-exit notification.

use crate::proc::scheduler;
use crate::proc::process::State;
use crate::uaccess::copy_to_user;

pub const WNOHANG:   u32 = 1;
pub const WUNTRACED: u32 = 2;

// ── notify_exit ────────────────────────────────────────────────────────────

pub fn notify_exit(exited_pid: usize) {
    let (ppid, exit_signal) = scheduler::with_procs(|procs| {
        procs.iter()
            .find(|p| p.pid == exited_pid)
            .map(|p| (p.ppid, p.exit_signal))
            .unwrap_or((0, 17))
    });
    if ppid == 0 { return; }
    scheduler::wake_pid(ppid);
    if exit_signal != 0 {
        crate::proc::signal::send_signal(ppid, exit_signal);
    }
}

// ── sys_waitpid [NR 7 / NR 61] ───────────────────────────────────────────

pub fn sys_waitpid(pid: isize, wstatus_va: usize, options: u32) -> isize {
    let caller  = scheduler::current_pid();
    let wnohang = options & WNOHANG != 0;

    loop {
        // ── Look for a matching zombie ─────────────────────────────────────────
        let found: Option<(usize, i32)> = scheduler::with_procs(|procs| {
            procs.iter().find(|p| {
                p.ppid == caller
                    && p.state == State::Zombie
                    && match pid {
                        -1 | 0 => true,
                        n if n > 0 => p.pid == n as usize,
                        _          => true,
                    }
            }).map(|p| (p.pid, p.exit_code))
        });

        if let Some((child_pid, exit_code)) = found {
            // ── Write wstatus (bounds-checked) ─────────────────────────────────
            if wstatus_va != 0 {
                let wstatus: i32 = if exit_code >= 0 {
                    (exit_code & 0xFF) << 8
                } else {
                    ((-exit_code) & 0x7F) as i32
                };
                let _ = copy_to_user(wstatus_va, &wstatus.to_ne_bytes());
            }

            // ── Reap: remove zombie PCB (two-step to avoid deadlock) ──────────
            // Step 1: find the index and remove under with_procs.
            let removed_idx = scheduler::with_procs(|procs| {
                if let Some(idx) = procs.iter().position(|p| p.pid == child_pid) {
                    procs.remove(idx);
                    Some(idx)
                } else { None }
            });
            // Step 2: fix scheduler's current pointer OUTSIDE with_procs,
            // because fix_current_after_remove also acquires SCHED.lock().
            if let Some(idx) = removed_idx {
                scheduler::fix_current_after_remove(idx);
            }

            return child_pid as isize;
        }

        // ── No zombie found ──────────────────────────────────────────────────
        if wnohang { return 0; }

        let has_child = scheduler::with_procs(|procs| {
            procs.iter().any(|p| {
                p.ppid == caller
                    && match pid {
                        -1 | 0 => true,
                        n if n > 0 => p.pid == n as usize,
                        _          => true,
                    }
            })
        });
        if !has_child { return -10; } // ECHILD

        // Block self before yielding so the scheduler skips us until
        // notify_exit → wake_pid transitions us back to Ready.
        // Without this, schedule() would return immediately on a
        // single-CPU kernel and busy-spin starving the child.
        scheduler::with_procs(|procs| {
            let me = procs.iter_mut().find(|p| p.pid == caller);
            if let Some(p) = me { p.state = State::Blocked; }
        });
        scheduler::schedule();
        // Re-mark Ready so the loop can run again after we're woken.
        scheduler::with_procs(|procs| {
            let me = procs.iter_mut().find(|p| p.pid == caller);
            if let Some(p) = me {
                if p.state == State::Blocked { p.state = State::Ready; }
            }
        });
    }
}

// ── wstatus decode helpers ─────────────────────────────────────────────────

#[inline] pub fn wifexited(ws: i32)   -> bool { (ws & 0x7F) == 0 }
#[inline] pub fn wexitstatus(ws: i32) -> i32  { (ws >> 8) & 0xFF }
#[inline] pub fn wifsignaled(ws: i32) -> bool { (ws & 0x7F) != 0 && (ws & 0x7F) != 0x7F }
#[inline] pub fn wtermsig(ws: i32)    -> i32  { ws & 0x7F }
