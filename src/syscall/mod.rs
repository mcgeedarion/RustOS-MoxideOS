//! x86-64 Linux syscall dispatch table for rustos.
//!
//! Called from arch/x86_64/syscall.rs -> syscall_rust_entry.
//!
//! ## Wired syscalls
//!    NR   0  read              -> fs::io_syscalls::sys_read
//!    NR   1  write             -> fs::io_syscalls::sys_write
//!    NR   2  open              -> fs::io_syscalls::sys_open
//!    NR   3  close             -> fs::io_syscalls::sys_close
//!    NR   4  stat              -> fs::stat_syscalls::sys_stat
//!    NR   5  fstat             -> fs::stat_syscalls::sys_fstat
//!    NR   6  lstat             -> fs::stat_syscalls::sys_lstat
//!    NR   7  waitpid           -> proc::wait::sys_waitpid
//!    NR   8  lseek             -> fs::stat_syscalls::sys_lseek
//!    NR   9  mmap              -> mm::mmap::sys_mmap
//!    NR  10  mprotect          -> mm::mmap::sys_mprotect
//!    NR  11  munmap            -> mm::mmap::sys_munmap
//!    NR  12  brk               -> mm::mmap::sys_brk
//!    NR  13  rt_sigaction      -> proc::signal::sys_rt_sigaction
//!    NR  14  rt_sigprocmask    -> proc::signal::sys_rt_sigprocmask
//!    NR  15  rt_sigreturn      -> handled in syscall_rust_entry (frame ptr)
//!    NR  16  ioctl             -> fs::ioctl::sys_ioctl
//!    NR  17  pread64           -> fs::io_syscalls::sys_pread64
//!    NR  20  writev            -> fs::io_syscalls::sys_writev
//!    NR  21  access            -> fs::stat_syscalls::sys_access
//!    NR  33  dup2              -> fs::io_syscalls::sys_dup2
//!    NR  35  nanosleep         -> proc::nanosleep::sys_nanosleep
//!    NR  39  getpid            -> scheduler::current_pid()
//!    NR  57  fork              -> proc::fork_syscall::sys_fork
//!    NR  59  execve            -> handled in syscall_rust_entry (frame ptr)
//!    NR  60  exit              -> proc::exit::sys_exit
//!    NR  61  wait4             -> proc::wait::sys_waitpid (compat)
//!    NR  72  fcntl             -> fs::fcntl::sys_fcntl
//!    NR  79  getcwd            -> fs::stat_syscalls::sys_getcwd
//!    NR  80  chdir             -> fs::stat_syscalls::sys_chdir
//!    NR  82  rename            -> fs::stat_syscalls::sys_rename
//!    NR  83  mkdir             -> fs::stat_syscalls::sys_mkdir
//!    NR  87  unlink            -> fs::stat_syscalls::sys_unlink
//!    NR 110  getppid           -> scheduler::ppid_of(current_pid())
//!    NR 158  arch_prctl        -> arch::x86_64::syscall::sys_arch_prctl
//!    NR 186  gettid            -> proc::thread::sys_gettid
//!    NR 218  set_tid_address   -> arch::x86_64::syscall::sys_set_tid_address
//!    NR 228  clock_gettime     -> proc::nanosleep::sys_clock_gettime
//!    NR 231  exit_group        -> proc::exit::sys_exit_group
//!    NR 269  faccessat         -> fs::stat_syscalls::sys_faccessat
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
        // ── filesystem I/O ────────────────────────────────────────────────
        0   => crate::fs::io_syscalls::sys_read(a, b, c),
        1   => crate::fs::io_syscalls::sys_write(a, b, c),
        2   => crate::fs::io_syscalls::sys_open(a, b as u32, c as u32),
        3   => crate::fs::io_syscalls::sys_close(a),
        17  => crate::fs::io_syscalls::sys_pread64(a, b, c, d as i64),
        20  => crate::fs::io_syscalls::sys_writev(a, b, c),
        33  => crate::fs::io_syscalls::sys_dup2(a, b),
        16  => crate::fs::ioctl::sys_ioctl(a, b, c),
        72  => crate::fs::fcntl::sys_fcntl(a, b as i32, c),
        // ── stat / path ops ───────────────────────────────────────────────
        4   => crate::fs::stat_syscalls::sys_stat(a, b),
        5   => crate::fs::stat_syscalls::sys_fstat(a, b),
        6   => crate::fs::stat_syscalls::sys_lstat(a, b),
        8   => crate::fs::stat_syscalls::sys_lseek(a, b as i64, c as i32),
        21  => crate::fs::stat_syscalls::sys_access(a, b as u32),
        79  => crate::fs::stat_syscalls::sys_getcwd(a, b),
        80  => crate::fs::stat_syscalls::sys_chdir(a),
        82  => crate::fs::stat_syscalls::sys_rename(a, b),
        83  => crate::fs::stat_syscalls::sys_mkdir(a, b as u32),
        87  => crate::fs::stat_syscalls::sys_unlink(a),
        269 => crate::fs::stat_syscalls::sys_faccessat(a as i32, b, c as u32),
        // ── memory ────────────────────────────────────────────────────────
        9   => crate::mm::mmap::sys_mmap(a, b, c as u32, d as u32, e, f),
        10  => crate::mm::mmap::sys_mprotect(a, b, c as u32),
        11  => crate::mm::mmap::sys_munmap(a, b),
        12  => crate::mm::mmap::sys_brk(a),
        149 => sys_mlock_impl(a, b),
        150 => sys_munlock_impl(a, b),
        // ── process / signals ─────────────────────────────────────────────
        7   => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        13  => crate::proc::signal::sys_rt_sigaction(a as u32, b, c, d),
        14  => crate::proc::signal::sys_rt_sigprocmask(a as u32, b, c, d),
        // NR 15 rt_sigreturn handled in syscall_rust_entry (needs frame ptr)
        35  => crate::proc::nanosleep::sys_nanosleep(a, b),
        39  => crate::proc::scheduler::current_pid() as isize,
        57  => crate::proc::fork_syscall::sys_fork(),
        // NR 59 execve handled in syscall_rust_entry (needs frame ptr)
        60  => crate::proc::exit::sys_exit(a as i32),
        61  => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        110 => crate::proc::scheduler::ppid_of(crate::proc::scheduler::current_pid()) as isize,
        158 => crate::arch::x86_64::syscall::sys_arch_prctl(a as i32, b),
        186 => crate::proc::thread::sys_gettid(),
        218 => crate::arch::x86_64::syscall::sys_set_tid_address(a),
        228 => crate::proc::nanosleep::sys_clock_gettime(a as u32, b),
        231 => crate::proc::exit::sys_exit_group(a as i32),
        // ── pidfd ─────────────────────────────────────────────────────────
        424 => crate::fs::pidfd::sys_pidfd_send_signal(a, b as u32, c, d as u32),
        434 => crate::fs::pidfd::sys_pidfd_open(a, b as u32),
        435 => crate::proc::clone::sys_clone3(a, b),
        438 => crate::fs::pidfd::sys_pidfd_getfd(a, b, c as u32),
        // ── permission / attribute stubs ──────────────────────────────────
        90  => sys_chmod_impl(a, b as u32),
        91  => sys_fchmod_impl(a, b as u32),
        92  => sys_chown_impl(a, b as u32, c as u32),
        94  => sys_fchown_impl(a, b as u32, c as u32),
        280 => sys_utimensat_impl(a as i32, b, c, d as i32),
        101 => sys_ptrace_impl(a as i32, b as i32, c, d),
        165 => sys_mount_impl(a, b, c, d as u64, e),
        103 => sys_syslog_impl(a as i32, b, c as i32),
        _   => -38,  // ENOSYS
    }
}
