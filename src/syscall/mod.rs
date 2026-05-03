//! x86-64 Linux syscall dispatch table for rustos.
//!
//! ## Wired syscalls
//!    NR   0  read               NR  57  fork
//!    NR   1  write              NR  59  execve (frame ptr)
//!    NR   2  open               NR  60  exit
//!    NR   3  close              NR  61  wait4
//!    NR   4  stat               NR  72  fcntl
//!    NR   5  fstat              NR  78  getdents
//!    NR   6  lstat              NR  79  getcwd
//!    NR   7  poll               NR  80  chdir
//!    NR   8  lseek              NR  82  rename
//!    NR   9  mmap               NR  83  mkdir
//!    NR  10  mprotect           NR  87  unlink
//!    NR  11  munmap             NR 102  getuid
//!    NR  12  brk                NR 104  getgid
//!    NR  13  rt_sigaction       NR 105  setuid
//!    NR  14  rt_sigprocmask     NR 106  setgid
//!    NR  15  rt_sigreturn       NR 107  geteuid
//!    NR  16  ioctl              NR 108  getegid
//!    NR  17  pread64            NR 110  getppid
//!    NR  20  writev             NR 111  getpgrp
//!    NR  21  access             NR 113  setpgid
//!    NR  22  pipe               NR 121  getpgid
//!    NR  23  select             NR 158  arch_prctl
//!    NR  32  dup                NR 186  gettid
//!    NR  33  dup2               NR 213  epoll_create
//!    NR  35  nanosleep          NR 217  getdents64
//!    NR  39  getpid             NR 218  set_tid_address
//!    NR 228  clock_gettime      NR 231  exit_group
//!    NR 232  epoll_wait         NR 233  epoll_ctl
//!    NR 269  faccessat          NR 270  pselect6
//!    NR 271  ppoll              NR 281  epoll_pwait
//!    NR 291  epoll_create1      NR 293  pipe2
//!    NR 424  pidfd_send_signal  NR 434  pidfd_open
//!    NR 435  clone3             NR 438  pidfd_getfd

#![allow(unused_variables, unused_imports)]
extern crate alloc;
use crate::fs::vfs;
use crate::fs::fcntl;

include!("p0_gaps.rs");
include!("socket_gaps.rs");

pub fn dispatch(nr: usize, a: usize, b: usize, c: usize,
                d: usize, e: usize, f: usize) -> isize {
    match nr {
        // ── filesystem I/O ───────────────────────────────────────────────────
        0   => crate::fs::io_syscalls::sys_read(a, b, c),
        1   => crate::fs::io_syscalls::sys_write(a, b, c),
        2   => crate::fs::io_syscalls::sys_open(a, b as u32, c as u32),
        3   => crate::fs::io_syscalls::sys_close(a),
        17  => crate::fs::io_syscalls::sys_pread64(a, b, c, d as i64),
        20  => crate::fs::io_syscalls::sys_writev(a, b, c),
        22  => crate::fs::pipe::sys_pipe(a),
        32  => crate::fs::vfs::dup(a),
        33  => crate::fs::io_syscalls::sys_dup2(a, b),
        72  => crate::fs::fcntl::sys_fcntl(a, b as i32, c),
        78  => crate::fs::getdents::sys_getdents(a, b, c),
        16  => crate::fs::ioctl::sys_ioctl(a, b, c),
        217 => crate::fs::getdents::sys_getdents64(a, b, c),
        293 => crate::fs::pipe::sys_pipe2(a, b as u32),
        // ── I/O multiplexing ────────────────────────────────────────────────
        7   => crate::fs::poll::sys_poll(a, b, c as i32),
        23  => crate::fs::poll::sys_select(a, b, c, d, e),
        213 => crate::fs::poll::sys_epoll_create(a as i32),
        232 => crate::fs::poll::sys_epoll_wait(a, b, c as i32, d as i32),
        233 => crate::fs::poll::sys_epoll_ctl(a, b as i32, c as i32, d),
        270 => crate::fs::poll::sys_pselect6(a, b, c, d, e, f),
        271 => crate::fs::poll::sys_ppoll(a, b, c, d, e),
        281 => crate::fs::poll::sys_epoll_pwait(a, b, c as i32, d as i32, e, f),
        291 => crate::fs::poll::sys_epoll_create(a as i32), // epoll_create1
        // ── stat / path ops ────────────────────────────────────────────────
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
        // ── memory ────────────────────────────────────────────────────────────
        9   => crate::mm::mmap::sys_mmap(a, b, c as u32, d as u32, e, f),
        10  => crate::mm::mmap::sys_mprotect(a, b, c as u32),
        11  => crate::mm::mmap::sys_munmap(a, b),
        12  => crate::mm::mmap::sys_brk(a),
        149 => sys_mlock_impl(a, b),
        150 => sys_munlock_impl(a, b),
        // ── process / signals ─────────────────────────────────────────────
        13  => crate::proc::signal::sys_rt_sigaction(a as u32, b, c, d),
        14  => crate::proc::signal::sys_rt_sigprocmask(a as u32, b, c, d),
        35  => crate::proc::nanosleep::sys_nanosleep(a, b),
        39  => crate::proc::scheduler::current_pid() as isize,
        57  => crate::proc::fork_syscall::sys_fork(),
        60  => crate::proc::exit::sys_exit(a as i32),
        61  => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        // NR 7 wait / waitpid was here; now NR 7 = poll. Waitpid lives at NR 61.
        // Note: the old NR 7 dispatch entry was wait::sys_waitpid—removed.
        // Callers using NR 61 (wait4) continue to work.
        110 => crate::proc::scheduler::ppid_of(crate::proc::scheduler::current_pid()) as isize,
        111 => crate::proc::scheduler::current_pid() as isize,
        113 => 0, // setpgid — no-op
        114 => crate::proc::scheduler::current_pid() as isize,
        121 => crate::proc::scheduler::current_pid() as isize,
        158 => crate::arch::x86_64::syscall::sys_arch_prctl(a as i32, b),
        186 => crate::proc::thread::sys_gettid(),
        218 => crate::arch::x86_64::syscall::sys_set_tid_address(a),
        228 => crate::proc::nanosleep::sys_clock_gettime(a as u32, b),
        231 => crate::proc::exit::sys_exit_group(a as i32),
        // ── uid / gid ──────────────────────────────────────────────────────────
        102 | 104 | 107 | 108 => 0, // get{u,g,eu,eg}id — always 0 (root)
        105 | 106             => 0, // set{u,g}id — no-op
        // ── pidfd ──────────────────────────────────────────────────────────────
        424 => crate::fs::pidfd::sys_pidfd_send_signal(a, b as u32, c, d as u32),
        434 => crate::fs::pidfd::sys_pidfd_open(a, b as u32),
        435 => crate::proc::clone::sys_clone3(a, b),
        438 => crate::fs::pidfd::sys_pidfd_getfd(a, b, c as u32),
        // ── permission / attribute stubs ─────────────────────────────────────
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
