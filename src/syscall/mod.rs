//! x86-64 Linux syscall dispatch table for rustos.
//!
//! ## Wired NRs (75 + 30 new = 105 total)
//!
//! See stubs.rs and p0_gaps.rs for implementations of the gap-fill entries.

#![allow(unused_variables, unused_imports)]
extern crate alloc;
use crate::fs::vfs;
use crate::fs::fcntl;

include!("p0_gaps.rs");
include!("socket_gaps.rs");
include!("stubs.rs");

// EPOLL_CLOEXEC flag value (matches Linux).
const EPOLL_CLOEXEC: u32 = 0x0008_0000;

/// sys_epoll_create1 wrapper: creates an epoll instance and sets FD_CLOEXEC
/// on the returned fd when EPOLL_CLOEXEC is present in flags.
/// Programs using glibc >= 2.9 always pass EPOLL_CLOEXEC; without this the
/// epoll fd leaks across execve.
fn sys_epoll_create1(flags: u32) -> isize {
    let fd = crate::fs::poll::sys_epoll_create(0);
    if fd >= 0 && flags & EPOLL_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fd as usize, true);
    }
    fd
}

pub fn dispatch(nr: usize, a: usize, b: usize, c: usize,
                d: usize, e: usize, f: usize) -> isize {
    match nr {
        // ── filesystem I/O ───────────────────────────────────────────────────────────────
        0   => crate::fs::io_syscalls::sys_read(a, b, c),
        1   => crate::fs::io_syscalls::sys_write(a, b, c),
        2   => crate::fs::io_syscalls::sys_open(a, b as u32, c as u32),
        3   => crate::fs::io_syscalls::sys_close(a),
        17  => crate::fs::io_syscalls::sys_pread64(a, b, c, d as i64),
        18  => sys_pwrite64_impl(a, b, c, d as i64),
        19  => sys_readv_impl(a, b, c),
        20  => crate::fs::io_syscalls::sys_writev(a, b, c),
        22  => crate::fs::pipe::sys_pipe(a),
        32  => crate::fs::vfs::dup(a),
        33  => crate::fs::fcntl::sys_dup2(a, b),
        40  => sys_sendfile_impl(a, b, c, d),
        72  => crate::fs::fcntl::sys_fcntl(a, b as i32, c),
        74  => sys_fsync_impl(a),
        75  => sys_fsync_impl(a),  // fdatasync ≈ fsync
        76  => sys_truncate_impl(a, b as i64),
        77  => sys_ftruncate_impl(a, b as i64),
        78  => crate::fs::getdents::sys_getdents(a, b, c),
        16  => crate::fs::ioctl::sys_ioctl(a, b, c),
        81  => sys_fchdir_impl(a),
        84  => sys_rmdir_impl(a),
        85  => sys_creat_impl(a, b as u32),
        86  => sys_link_impl(a, b),
        88  => sys_symlink_impl(a, b),
        89  => sys_readlink_impl(a, b, c),
        162 => sys_sync_impl(),
        217 => crate::fs::getdents::sys_getdents64(a, b, c),
        257 => sys_openat_impl(a as i32, b, c as i32, d as u32),
        258 => sys_mkdirat_impl(a as i32, b, c as u32),
        262 => sys_newfstatat_impl(a as i32, b, c, d as u32),
        263 => sys_unlinkat_impl(a as i32, b, c as u32),
        264 => sys_renameat_impl(a as i32, b, c as i32, d),
        267 => sys_readlinkat_impl(a as i32, b, c, d),
        290 => crate::fs::eventfd::sys_eventfd2(a as u32, b as u32),
        292 => sys_inotify_init1_impl(a as i32),
        293 => crate::fs::pipe::sys_pipe2(a, b as u32),
        294 => crate::fs::fcntl::sys_dup3(a, b, c as i32),
        319 => sys_memfd_create_impl(a, b as u32),
        // ── I/O multiplexing ───────────────────────────────────────────────────────────────
        7   => crate::fs::poll::sys_poll(a, b, c as i32),
        23  => crate::fs::poll::sys_select(a, b, c, d, e),
        213 => crate::fs::poll::sys_epoll_create(a as i32),   // epoll_create(size)
        232 => crate::fs::poll::sys_epoll_wait(a, b, c as i32, d as i32),
        233 => crate::fs::poll::sys_epoll_ctl(a, b as i32, c as i32, d),
        270 => crate::fs::poll::sys_pselect6(a, b, c, d, e, f),
        271 => crate::fs::poll::sys_ppoll(a, b, c, d, e),
        281 => crate::fs::poll::sys_epoll_pwait(a, b, c as i32, d as i32, e, f),
        291 => sys_epoll_create1(a as u32),                    // epoll_create1(flags) — CLOEXEC aware
        // ── stat / path ops ───────────────────────────────────────────────────────────────
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
        95  => sys_umask_impl(a as u32),
        137 => sys_statfs_impl(a, b),
        138 => sys_fstatfs_impl(a, b),
        269 => crate::fs::stat_syscalls::sys_faccessat(a as i32, b, c as u32),
        // ── memory ──────────────────────────────────────────────────────────────────────────
        9   => crate::mm::mmap::sys_mmap(a, b, c as u32, d as u32, e, f),
        10  => crate::mm::mmap::sys_mprotect(a, b, c as u32),
        11  => crate::mm::mmap::sys_munmap(a, b),
        12  => crate::mm::mmap::sys_brk(a),
        25  => sys_mremap_impl(a, b, c, d, e),
        28  => sys_madvise_impl(a, b, c as i32),
        149 => sys_mlock_impl(a, b),
        150 => sys_munlock_impl(a, b),
        // ── process / signals ───────────────────────────────────────────────────────────────
        13  => crate::proc::signal::sys_rt_sigaction(a as u32, b, c, d),
        14  => crate::proc::signal::sys_rt_sigprocmask(a as u32, b, c, d),
        24  => sys_sched_yield_impl(),
        35  => crate::proc::nanosleep::sys_nanosleep(a, b),
        39  => crate::proc::scheduler::current_pid() as isize,       // getpid
        56  => sys_clone_impl(a, b, c, d, e),
        57  => crate::proc::fork_syscall::sys_fork(),
        58  => sys_vfork_impl(),
        60  => crate::proc::exit::sys_exit(a as i32),
        61  => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        62  => sys_kill_impl(a as isize, b as u32),
        63  => sys_uname_impl(a),
        98  => sys_getrusage_impl(a as i32, b),
        99  => sys_sysinfo_impl(a),
        // NR 110 = getppid — single lock window via current_ppid()
        110 => crate::proc::scheduler::current_ppid() as isize,
        // NR 111 = getpmsg (STREAMS, not implemented — ENOSYS)
        113 => if (b as isize) < 0 { -22 } else { 0 }, // setpgid(pid, pgid): stub; EINVAL if pgid < 0
        114 => crate::proc::scheduler::current_pid() as isize,   // getpgrp
        121 => crate::proc::scheduler::current_pid() as isize,   // getpgid(pid) stub — returns own pgid
        131 => sys_sigaltstack_impl(a, b),
        158 => crate::arch::x86_64::syscall::sys_arch_prctl(a as i32, b),
        185 => sys_prctl_impl(a as i32, b, c, d, e),
        186 => crate::proc::thread::sys_gettid(),
        201 => sys_time_impl(a),
        202 => sys_futex_impl(a, b as u32, c as u32, d, e, f as u32),
        203 => sys_sched_setaffinity_impl(a, b, c),
        204 => sys_sched_getaffinity_impl(a, b, c),
        218 => crate::arch::x86_64::syscall::sys_set_tid_address(a),
        228 => crate::proc::nanosleep::sys_clock_gettime(a as u32, b),
        230 => sys_clock_getres_impl(a as u32, b),
        231 => crate::proc::exit::sys_exit_group(a as i32),
        234 => sys_tgkill_impl(a, b, c as u32),
        247 => sys_waitid_impl(a as i32, b as i32, c, d as u32),
        // ── uid / gid ─────────────────────────────────────────────────────────────────────────
        96  => sys_gettimeofday_impl(a, b),
        97  => sys_getrlimit_impl(a as u32, b),
        160 => sys_setrlimit_impl(a as u32, b),
        302 => sys_prlimit64_impl(a, b as u32, c, d),
        102 | 104 | 107 | 108 => 0, // get{u,g,eu,eg}id = 0 (root)
        105 | 106             => 0, // set{u,g}id no-op
        109 | 117 | 118 | 119 | 120 => 0, // res{u,g}id variants
        // ── pidfd ────────────────────────────────────────────────────────────────────────────
        424 => crate::fs::pidfd::sys_pidfd_send_signal(a, b as u32, c, d as u32),
        434 => crate::fs::pidfd::sys_pidfd_open(a, b as u32),
        435 => crate::proc::clone::sys_clone3(a, b),
        438 => crate::fs::pidfd::sys_pidfd_getfd(a, b, c as u32),
        // ── permission / attribute stubs ─────────────────────────────────────────────────────────────
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
