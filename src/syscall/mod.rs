//! x86-64 Linux syscall dispatch table for rustos.
//!
//! Called from arch/x86_64/syscall.rs -> syscall_rust_entry.
//!
//! ## Wired syscalls
//!    NR   7  waitpid           -> proc::wait::sys_waitpid
//!    NR  12  brk               -> mm::mmap::sys_brk
//!    NR  13  rt_sigaction      -> proc::signal::sys_rt_sigaction
//!    NR  14  rt_sigprocmask    -> proc::signal::sys_rt_sigprocmask
//!    NR  15  rt_sigreturn      -> handled in syscall_rust_entry (frame ptr)
//!    NR  59  execve            -> proc::exec::sys_execve (handled in syscall_rust_entry)
//!    NR  60  exit              -> proc::exit::sys_exit
//!    NR  61  wait4             -> proc::wait::sys_waitpid (compat)
//!    NR 218  set_tid_address   -> arch::x86_64::syscall::sys_set_tid_address
//!    NR 231  exit_group        -> proc::exit::sys_exit_group
//!    NR 424  pidfd_send_signal -> fs::pidfd::sys_pidfd_send_signal
//!    NR 434  pidfd_open        -> fs::pidfd::sys_pidfd_open
//!    NR 435  clone3            -> proc::clone::sys_clone3
//!    NR 438  pidfd_getfd       -> fs::pidfd::sys_pidfd_getfd

#![allow(unused_variables, unused_imports)]
extern crate alloc;

use crate::fs::vfs;
use crate::fs::fcntl;

include!("p0_gaps.rs");
include!("socket_gaps.rs");

/// Primary syscall dispatch.
/// nr = rax; a-f = rdi, rsi, rdx, r10, r8, r9.
pub fn dispatch(nr: usize, a: usize, b: usize, c: usize,
                d: usize, e: usize, f: usize) -> isize {
    match nr {
        7   => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        12  => crate::mm::mmap::sys_brk(a),
        13  => crate::proc::signal::sys_rt_sigaction(a as u32, b, c, d),
        14  => crate::proc::signal::sys_rt_sigprocmask(a as u32, b, c, d),
        // NR 15 rt_sigreturn handled in syscall_rust_entry (needs frame ptr)
        // NR 59 execve handled in syscall_rust_entry (needs frame ptr)
        60  => crate::proc::exit::sys_exit(a as i32),
        61  => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        218 => crate::arch::x86_64::syscall::sys_set_tid_address(a),
        231 => crate::proc::exit::sys_exit_group(a as i32),
        424 => crate::fs::pidfd::sys_pidfd_send_signal(a, b as u32, c, d as u32),
        434 => crate::fs::pidfd::sys_pidfd_open(a, b as u32),
        435 => crate::proc::clone::sys_clone3(a, b),
        438 => crate::fs::pidfd::sys_pidfd_getfd(a, b, c as u32),
        149 => sys_mlock_impl(a, b),
        150 => sys_munlock_impl(a, b),
        90  => sys_chmod_impl(a, b as u32),
        91  => sys_fchmod_impl(a, b as u32),
        92  => sys_chown_impl(a, b as u32, c as u32),
        94  => sys_fchown_impl(a, b as u32, c as u32),
        280 => sys_utimensat_impl(a as i32, b, c, d as i32),
        101 => sys_ptrace_impl(a as i32, b as i32, c, d),
        165 => sys_mount_impl(a, b, c, d as u64, e),
        103 => sys_syslog_impl(a as i32, b, c as i32),
        _   => -38,
    }
}
