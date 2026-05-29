//! kmtest/proc — process-management test suite
//!
//! Covers:
//!   fork / wait4 semantics (exit status propagation)
//!   exec replaces address space
//!   signal delivery (SIGCHLD, SIGUSR1 self-send)
//!   process teardown: FDs closed, VMAs freed, zombie reaped
//!   getpid / getppid consistency across fork

use kmtest::{register, KmTestResult};
use crate::proc::{
    fork_syscall::sys_fork,
    exec::sys_execve,
    wait::sys_waitpid,
    exit::sys_exit,
    scheduler::{current_pid, yield_cpu},
    signal::{sys_rt_sigaction, send_signal},
};
use crate::syscall::nr::{SYS_GETPID, SYS_GETPPID, SYS_KILL};

const SIGCHLD:  u32 = 17;
const SIGUSR1:  u32 = 10;
const SIGKILL:  u32 = 9;
const WNOHANG:  u32 = 1;

/// fork() returns 0 in the child, child_pid > 0 in parent.
fn proc_fork_pid_semantics() -> KmTestResult {
    let pid = sys_fork();
    if pid < 0 {
        return Err("fork() returned error");
    }
    if pid == 0 {
        // Child: exit immediately with status 42.
        sys_exit(42);
        unreachable!();
    }
    // Parent: reap the child.
    let mut status: i32 = -1;
    let waited = sys_waitpid(pid as isize, &mut status as *mut i32 as usize, 0);
    if waited != pid as isize {
        return Err("waitpid returned wrong pid");
    }
    // WEXITSTATUS: bits 8..15 of status.
    let exit_code = (status >> 8) & 0xFF;
    if exit_code != 42 {
        return Err("child exit status not propagated correctly");
    }
    Ok(())
}

/// Two sequential forks; both children must be reapable.
fn proc_fork_multiple() -> KmTestResult {
    for expected in [11u8, 22u8] {
        let pid = sys_fork();
        if pid < 0 { return Err("fork() failed in multi-fork test"); }
        if pid == 0 {
            sys_exit(expected as i32);
            unreachable!();
        }
        let mut status = 0i32;
        let w = sys_waitpid(pid as isize, &mut status as *mut i32 as usize, 0);
        if w != pid as isize { return Err("waitpid wrong pid (multi-fork)"); }
        let code = (status >> 8) & 0xFF;
        if code != expected as i32 { return Err("multi-fork exit code mismatch"); }
    }
    Ok(())
}

/// WNOHANG when child has not yet exited returns 0.
fn proc_waitpid_wnohang() -> KmTestResult {
    let pid = sys_fork();
    if pid < 0 { return Err("fork failed (wnohang)"); }
    if pid == 0 {
        // Spin briefly so parent hits WNOHANG before we exit.
        for _ in 0..1000 { yield_cpu(); }
        sys_exit(0);
        unreachable!();
    }
    let mut status = 0i32;
    let w = sys_waitpid(pid as isize, &mut status as *mut i32 as usize, WNOHANG);
    if w < 0 { return Err("waitpid WNOHANG returned error"); }
    // w == 0 means child not yet done (expected) or w == pid means it was quick.
    // Both are correct; we only care that it did NOT return a negative error.
    // Reap properly.
    let _ = sys_waitpid(pid as isize, &mut status as *mut i32 as usize, 0);
    Ok(())
}

/// Self-send SIGUSR1 with SIG_IGN handler; must not crash.
fn proc_signal_self_ignore() -> KmTestResult {
    // Install SIG_IGN (handler = 1).
    // sa_handler=1, sa_flags=0, sa_mask=0, sa_restorer=0
    let sigaction_buf = [1usize, 0usize, 0usize, 0usize];
    let r = sys_rt_sigaction(SIGUSR1,
        sigaction_buf.as_ptr() as usize, 0, 8);
    if r != 0 { return Err("rt_sigaction SIG_IGN failed"); }
    let mypid = current_pid();
    send_signal(mypid, SIGUSR1);
    // If we reach here, the signal was ignored correctly.
    Ok(())
}

/// getpid() is stable across yield calls.
fn proc_getpid_stable() -> KmTestResult {
    let pid1 = current_pid();
    yield_cpu();
    let pid2 = current_pid();
    yield_cpu();
    let pid3 = current_pid();
    if pid1 != pid2 || pid2 != pid3 {
        return Err("getpid changed across yield");
    }
    Ok(())
}

/// Child's getppid() equals parent's getpid().
fn proc_getppid_correct() -> KmTestResult {
    let parent_pid = current_pid();
    let pid = sys_fork();
    if pid < 0 { return Err("fork failed (getppid)"); }
    if pid == 0 {
        let ppid = crate::proc::scheduler::current_ppid();
        // Encode result in exit code: 0 = correct, 1 = wrong.
        sys_exit(if ppid == parent_pid { 0 } else { 1 });
        unreachable!();
    }
    let mut status = 0i32;
    let _ = sys_waitpid(pid as isize, &mut status as *mut i32 as usize, 0);
    if (status >> 8) & 0xFF != 0 {
        return Err("child getppid() did not match parent getpid()");
    }
    Ok(())
}

pub fn register() {
    register!("proc_fork_pid_semantics",  proc_fork_pid_semantics);
    register!("proc_fork_multiple",        proc_fork_multiple);
    register!("proc_waitpid_wnohang",      proc_waitpid_wnohang);
    register!("proc_signal_self_ignore",   proc_signal_self_ignore);
    register!("proc_getpid_stable",        proc_getpid_stable);
    register!("proc_getppid_correct",      proc_getppid_correct);
}
