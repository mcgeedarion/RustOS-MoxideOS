//! waitpid / wait4 and process-exit notification.
//!
//! ## notify_exit(pid)
//!   Called by do_exit.  Wakes the parent + sends exit_signal (SIGCHLD by
//!   default) so the parent's check_pending_signal loop picks it up at the
//!   next syscall boundary.
//!
//! ## sys_waitpid(pid, wstatus_va, options)  [NR 7 / NR 61]
//!   Behaviour matches Linux waitpid(2):
//!     pid == -1   wait for any child
//!     pid >  0    wait for that specific child
//!     pid == 0    wait for any child in the same process group (treated as -1)
//!     pid < -1    same process-group wait (treated as -1 for now)
//!
//!   options bits honoured:
//!     WNOHANG (1)  return 0 immediately if no zombie is ready
//!
//!   wstatus encoding (Linux ABI):
//!     Normal exit:   (exit_code & 0xFF) << 8          WIFEXITED = true
//!     Killed by sig: (sig & 0x7F)                     WIFSIGNALED = true
//!     (exit_code < 0 means the task was killed by signal -exit_code)
//!
//!   On successful reap:
//!     1. Write wstatus to wstatus_va if non-NULL.
//!     2. Remove the zombie PCB from the scheduler run-list (pid freed).
//!     3. Return child_pid.

use crate::proc::scheduler;
use crate::proc::process::State;

pub const WNOHANG:   u32 = 1;
pub const WUNTRACED: u32 = 2;

// ── notify_exit ──────────────────────────────────────────────────────────────

/// Called by do_exit after the zombie state is set.
/// Wakes the parent and delivers the child's exit_signal (normally SIGCHLD).
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

// ── sys_waitpid ──────────────────────────────────────────────────────────────

/// sys_waitpid(pid, wstatus_va, options) → child_pid / -errno  [NR 7 / NR 61]
pub fn sys_waitpid(pid: isize, wstatus_va: usize, options: u32) -> isize {
    let caller  = scheduler::current_pid();
    let wnohang = options & WNOHANG != 0;

    loop {
        // ── Look for a matching zombie ─────────────────────────────────────
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
            // ── Write wstatus (Linux ABI encoding) ──────────────────────
            if wstatus_va > 0x1000 {
                let wstatus: i32 = if exit_code >= 0 {
                    (exit_code & 0xFF) << 8  // WIFEXITED: code in bits 15:8
                } else {
                    ((-exit_code) & 0x7F) as i32  // WIFSIGNALED: signal in bits 6:0
                };
                unsafe { (wstatus_va as *mut i32).write_volatile(wstatus); }
            }

            // ── Reap: remove zombie PCB from the run list ────────────────
            // Kernel stack was already freed by do_exit.
            // Removing the PCB Vec element releases the allocation
            // and makes the pid eligible for reuse.
            scheduler::with_procs(|procs| {
                if let Some(idx) = procs.iter().position(|p| p.pid == child_pid) {
                    procs.remove(idx);
                    scheduler::fix_current_after_remove(idx);
                }
            });

            return child_pid as isize;
        }

        // ── No zombie found ─────────────────────────────────────────────
        if wnohang { return 0; }

        // Check whether the caller has any child at all.
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

        // Yield — do_exit will wake us via notify_exit → wake_pid.
        scheduler::schedule();
    }
}

// ── wstatus decode helpers ────────────────────────────────────────────────

#[inline] pub fn wifexited(ws: i32)   -> bool { (ws & 0x7F) == 0 }
#[inline] pub fn wexitstatus(ws: i32) -> i32  { (ws >> 8) & 0xFF }
#[inline] pub fn wifsignaled(ws: i32) -> bool { (ws & 0x7F) != 0 && (ws & 0x7F) != 0x7F }
#[inline] pub fn wtermsig(ws: i32)    -> i32  { ws & 0x7F }
