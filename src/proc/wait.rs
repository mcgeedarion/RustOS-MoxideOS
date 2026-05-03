//! waitpid / wait4 and process-exit notification.
//!
//! notify_exit(pid) wakes any tasks blocked in waitpid for that pid.
//! sys_waitpid is the backing implementation for NR 7 and NR 61.

use crate::proc::scheduler;
use crate::proc::process::State;

/// Wake the parent of `exited_pid`.
/// Called by pidfd_send_signal SIGKILL and do_exit paths.
pub fn notify_exit(exited_pid: usize) {
    let ppid = {
        let procs = scheduler::procs_lock();
        let p = procs.iter().find(|p| p.pid == exited_pid).map(|p| p.ppid);
        scheduler::procs_unlock();
        p
    };
    if let Some(parent_pid) = ppid {
        scheduler::wake_pid(parent_pid);
    }
}

/// sys_waitpid(pid, wstatus_va, options) -> child_pid / -errno  [NR 7 / NR 61]
///
/// Blocks until a child matching `pid` becomes a zombie.
/// pid == -1: wait for any child.  options: 0 = blocking.
pub fn sys_waitpid(pid: isize, wstatus_va: usize, _options: u32) -> isize {
    let caller = scheduler::current_pid();

    loop {
        let procs = scheduler::procs_lock();
        let result = procs.iter().find(|p| {
            let pid_match = pid == -1 || p.pid == pid as usize;
            pid_match && p.ppid == caller && p.state == State::Zombie
        }).map(|p| (p.pid, p.exit_code));
        scheduler::procs_unlock();

        if let Some((child_pid, exit_code)) = result {
            if wstatus_va != 0 && wstatus_va > 0x1000 {
                // WIFEXITED: encode exit_code in bits 15:8
                let wstatus: i32 = (exit_code.abs() & 0xFF) << 8;
                unsafe { (wstatus_va as *mut i32).write_volatile(wstatus); }
            }
            return child_pid as isize;
        }

        // No zombie yet: yield and retry
        scheduler::schedule();

        // After one yield check if any child even exists
        let procs = scheduler::procs_lock();
        let any_child = procs.iter().any(|p| {
            (pid == -1 || p.pid == pid as usize) && p.ppid == caller
        });
        scheduler::procs_unlock();
        if !any_child { return -10; } // ECHILD
    }
}
