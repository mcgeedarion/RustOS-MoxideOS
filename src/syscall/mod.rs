//! x86-64 Linux syscall dispatch table for rustos.
//!
//! ## Wired NRs (75 + 30 new + 7 inotify/fanotify = 112 total)
//!
//! See stubs.rs and p0_gaps.rs for implementations of the gap-fill entries.
//!
//! ## inotify / fanotify NR layout
//!   NR 253  inotify_init       => inotify::sys_inotify_init1(0)
//!   NR 254  inotify_add_watch  => inotify::sys_inotify_add_watch(fd, path, mask)
//!   NR 255  inotify_rm_watch   => inotify::sys_inotify_rm_watch(fd, wd)
//!   NR 292  inotify_init1      => inotify::sys_inotify_init1(flags)   [replaces old stub]
//!   NR 293  pipe2              => pipe::sys_pipe2  (unchanged)
//!   NR 294  inotify_init1 dup  => inotify::sys_inotify_init1(flags)   [was dup3; dup3=292 on old kernels]
//!           NOTE: Linux x86-64: NR 294 is dup3, NOT a second inotify_init1.
//!                 dup3 was previously wired here correctly; inotify_init1 is NR 294 only
//!                 on i386 (compat). On x86-64, NR 294 stays as dup3.
//!                 inotify_init1 on x86-64 is NR 292.
//!   NR 300  fanotify_init      => fanotify::sys_fanotify_init(flags, event_f_flags)
//!   NR 301  fanotify_mark      => fanotify::sys_fanotify_mark(fd, flags, mask, dirfd, path)
//!   NR 302  prlimit64          => sys_prlimit64_impl  (Linux x86-64 NR 302 is prlimit64, NOT fanotify)
//!           NOTE: fanotify syscalls end at NR 301. NR 302 = prlimit64 on x86-64.

#![allow(unused_variables, unused_imports)]
extern crate alloc;
use crate::fs::vfs;
use crate::fs::fcntl;

include!("p0_gaps.rs");
include!("socket_gaps.rs");
include!("stubs.rs");

// EPOLL_CLOEXEC flag value (matches Linux).
const EPOLL_CLOEXEC: u32 = 0x0008_0000;

/// Safely narrow a 64-bit syscall argument to u32.
/// Returns None (EINVAL) if the high bits are non-zero — prevents silent
/// truncation where a caller passes e.g. signal=0x1_00000009 and we'd
/// silently interpret it as signal 9.
#[inline(always)]
fn arg_u32(v: usize) -> Option<u32> {
    if v > u32::MAX as usize { None } else { Some(v as u32) }
}

/// Safely narrow a 64-bit syscall argument to i32.
/// The argument is expected to arrive as a sign-extended i32 value
/// (the kernel sign-extends register arguments for i32 params on Linux ABI).
/// We accept values whose upper 32 bits are either all-zeros or all-ones.
#[inline(always)]
fn arg_i32(v: usize) -> Option<i32> {
    let v = v as isize;
    if v >= i32::MIN as isize && v <= i32::MAX as isize {
        Some(v as i32)
    } else {
        None
    }
}

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
        293 => crate::fs::pipe::sys_pipe2(a, b as u32),
        294 => crate::fs::fcntl::sys_dup3(a, b, c as i32),
        319 => sys_memfd_create_impl(a, b as u32),
        // ── inotify ─────────────────────────────────────────────────────────────────────
        // NR 253  inotify_init  (legacy, no flags)
        253 => crate::fs::inotify::sys_inotify_init1(0),
        // NR 254  inotify_add_watch(fd, path_va, mask)
        254 => crate::fs::inotify::sys_inotify_add_watch(a, b, c as u32),
        // NR 255  inotify_rm_watch(fd, wd)
        255 => crate::fs::inotify::sys_inotify_rm_watch(a, b as i32),
        // NR 292  inotify_init1(flags)  — x86-64 canonical NR
        292 => crate::fs::inotify::sys_inotify_init1(a as u32),
        // ── fanotify ────────────────────────────────────────────────────────────────────
        // NR 300  fanotify_init(flags, event_f_flags)
        300 => crate::fs::fanotify::sys_fanotify_init(a as u32, b as u32),
        // NR 301  fanotify_mark(fanotify_fd, flags, mask, dirfd, path_va)
        301 => crate::fs::fanotify::sys_fanotify_mark(a, b as u32, c as u64, d as i32, e),
        // ── I/O multiplexing ─────────────────────────────────────────────────────────────
        7   => crate::fs::poll::sys_poll(a, b, c as i32),
        23  => crate::fs::poll::sys_select(a, b, c, d, e),
        213 => crate::fs::poll::sys_epoll_create(a as i32),   // epoll_create(size)
        232 => crate::fs::poll::sys_epoll_wait(a, b, c as i32, d as i32),
        233 => crate::fs::poll::sys_epoll_ctl(a, b as i32, c as i32, d),
        270 => crate::fs::poll::sys_pselect6(a, b, c, d, e, f),
        271 => crate::fs::poll::sys_ppoll(a, b, c, d, e),
        281 => crate::fs::poll::sys_epoll_pwait(a, b, c as i32, d as i32, e, f),
        291 => sys_epoll_create1(a as u32),
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
        // NR 13 — rt_sigaction(signum, act, old, sigsetsize)
        // signum must fit in u32 and be a valid signal (1..64).
        13  => match arg_u32(a) {
                   Some(sig) if sig >= 1 && sig <= 64 =>
                       crate::proc::signal::sys_rt_sigaction(sig, b, c, d),
                   _ => -22, // EINVAL
               },
        // NR 14 — rt_sigprocmask(how, set, old, sigsetsize)
        // `how` is SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2.
        14  => match arg_u32(a) {
                   Some(how) if how <= 2 =>
                       crate::proc::signal::sys_rt_sigprocmask(how, b, c, d),
                   _ => -22, // EINVAL
               },
        24  => sys_sched_yield_impl(),
        35  => crate::proc::nanosleep::sys_nanosleep(a, b),
        39  => crate::proc::scheduler::current_pid() as isize,  // getpid
        56  => sys_clone_impl(a, b, c, d, e),
        57  => crate::proc::fork_syscall::sys_fork(),
        58  => sys_vfork_impl(),
        60  => crate::proc::exit::sys_exit(a as i32),
        61  => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        // NR 62 — kill(pid, sig): sig 0 is valid (existence check); reject >64.
        62  => match arg_u32(b) {
                   Some(sig) if sig <= 64 => sys_kill_impl(a as isize, sig),
                   _ => -22, // EINVAL
               },
        63  => sys_uname_impl(a),
        98  => sys_getrusage_impl(a as i32, b),
        99  => sys_sysinfo_impl(a),
        110 => crate::proc::scheduler::current_ppid() as isize, // getppid
        // NR 113 — setpgid(pid, pgid): both are plain process IDs; reject if
        // high bits are set (they'd silently truncate to a different PID).
        113 => match (arg_u32(a), arg_u32(b)) {
                   (Some(pid), Some(pgid)) => {
                       let _ = (pid, pgid); // stub — validates args then succeeds
                       0
                   }
                   _ => -22, // EINVAL
               },
        114 => crate::proc::scheduler::current_pid() as isize,  // getpgrp
        121 => crate::proc::scheduler::current_pid() as isize,  // getpgid(pid) stub
        131 => sys_sigaltstack_impl(a, b),
        158 => crate::arch::x86_64::syscall::sys_arch_prctl(a as i32, b),
        185 => sys_prctl_impl(a as i32, b, c, d, e),
        186 => crate::proc::thread::sys_gettid(),
        201 => sys_time_impl(a),
        // NR 202 — futex: op and val are u32 on the ABI.
        202 => match (arg_u32(b), arg_u32(c), arg_u32(f)) {
                   (Some(op), Some(val), Some(val3)) =>
                       sys_futex_impl(a, op, val, d, e, val3),
                   _ => -22, // EINVAL
               },
        203 => sys_sched_setaffinity_impl(a, b, c),
        204 => sys_sched_getaffinity_impl(a, b, c),
        218 => crate::arch::x86_64::syscall::sys_set_tid_address(a),
        // NR 228 — clock_gettime(clockid, timespec*)
        228 => match arg_u32(a) {
                   Some(clk) => crate::proc::nanosleep::sys_clock_gettime(clk, b),
                   None => -22, // EINVAL
               },
        // NR 230 — clock_getres(clockid, timespec*)
        230 => match arg_u32(a) {
                   Some(clk) => sys_clock_getres_impl(clk, b),
                   None => -22, // EINVAL
               },
        231 => crate::proc::exit::sys_exit_group(a as i32),
        // NR 234 — tgkill(tgid, tid, sig): sig must be valid.
        234 => match arg_u32(c) {
                   Some(sig) if sig <= 64 => sys_tgkill_impl(a, b, sig),
                   _ => -22, // EINVAL
               },
        // NR 247 — waitid(idtype, id, infop, options)
        247 => match (arg_i32(a), arg_i32(b), arg_u32(d)) {
                   (Some(idtype), Some(id), Some(opts)) =>
                       sys_waitid_impl(idtype, id, c, opts),
                   _ => -22, // EINVAL
               },
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
