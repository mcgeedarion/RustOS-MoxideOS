//! x86-64 Linux syscall dispatch table for rustos.
//!
//! ## Signal NRs (this commit)
//!   NR 127  rt_sigpending(set, size)              => signal::sys_rt_sigpending
//!   NR 128  rt_sigtimedwait(set, info, ts, size)  => signal::sys_rt_sigtimedwait
//!   NR 130  rt_sigsuspend(mask, size)             => signal::sys_rt_sigsuspend
//!
//! ## NPTL threading NRs (prev commit)
//!   NR 200  tkill   NR 202  futex   NR 234  tgkill
//!   NR 273  set_robust_list   NR 274  get_robust_list
//!
//! ## seccomp / namespace NRs
//!   NR 272  unshare  NR 308  setns  NR 317  seccomp
//!
//! ## inotify / fanotify NRs
//!   NR 253/254/255/292  NR 300/301

#![allow(unused_variables, unused_imports)]
extern crate alloc;
use crate::fs::vfs;
use crate::fs::fcntl;

include!("p0_gaps.rs");
include!("socket_gaps.rs");
include!("stubs.rs");

const EPOLL_CLOEXEC: u32 = 0x0008_0000;

#[inline(always)]
fn arg_u32(v: usize) -> Option<u32> {
    if v > u32::MAX as usize { None } else { Some(v as u32) }
}

#[inline(always)]
fn arg_i32(v: usize) -> Option<i32> {
    let v = v as isize;
    if v >= i32::MIN as isize && v <= i32::MAX as isize {
        Some(v as i32)
    } else {
        None
    }
}

fn sys_epoll_create1(flags: u32) -> isize {
    let fd = crate::fs::poll::sys_epoll_create(0);
    if fd >= 0 && flags & EPOLL_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fd as usize, true);
    }
    fd
}

pub fn dispatch(nr: usize, a: usize, b: usize, c: usize,
                d: usize, e: usize, f: usize) -> isize {

    // ── seccomp pre-check ─────────────────────────────────────────────────────
    if nr != 317 && nr != 60 && nr != 231 {
        match crate::security::seccomp::seccomp_check(nr, &[a, b, c, d, e, f]) {
            crate::security::seccomp::SeccompVerdict::Allow  => {}
            crate::security::seccomp::SeccompVerdict::Errno(e) => return -(e as isize),
            crate::security::seccomp::SeccompVerdict::Trap  => {
                let pid = crate::proc::scheduler::current_pid();
                crate::proc::signal::send_signal(pid, 31 /* SIGSYS */);
                return -1;
            }
            crate::security::seccomp::SeccompVerdict::Kill  => {
                crate::proc::exit::sys_exit(-1);
                return -1;
            }
        }
    }

    match nr {
        // ── filesystem I/O ────────────────────────────────────────────────────
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
        75  => sys_fsync_impl(a),
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
        // ── inotify ───────────────────────────────────────────────────────────
        253 => crate::fs::inotify::sys_inotify_init1(0),
        254 => crate::fs::inotify::sys_inotify_add_watch(a, b, c as u32),
        255 => crate::fs::inotify::sys_inotify_rm_watch(a, b as i32),
        292 => crate::fs::inotify::sys_inotify_init1(a as u32),
        // ── fanotify ──────────────────────────────────────────────────────────
        300 => crate::fs::fanotify::sys_fanotify_init(a as u32, b as u32),
        301 => crate::fs::fanotify::sys_fanotify_mark(a, b as u32, c as u64, d as i32, e),
        // ── seccomp + namespaces ──────────────────────────────────────────────
        272 => crate::proc::namespace::sys_unshare(a),
        308 => crate::proc::namespace::sys_setns(a, b as u32),
        317 => crate::security::seccomp::sys_seccomp(a as u32, b as u32, c),
        // ── I/O multiplexing ──────────────────────────────────────────────────
        7   => crate::fs::poll::sys_poll(a, b, c as i32),
        23  => crate::fs::poll::sys_select(a, b, c, d, e),
        213 => crate::fs::poll::sys_epoll_create(a as i32),
        232 => crate::fs::poll::sys_epoll_wait(a, b, c as i32, d as i32),
        233 => crate::fs::poll::sys_epoll_ctl(a, b as i32, c as i32, d),
        270 => crate::fs::poll::sys_pselect6(a, b, c, d, e, f),
        271 => crate::fs::poll::sys_ppoll(a, b, c, d, e),
        281 => crate::fs::poll::sys_epoll_pwait(a, b, c as i32, d as i32, e, f),
        291 => sys_epoll_create1(a as u32),
        // ── stat / path ops ───────────────────────────────────────────────────
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
        // ── memory ────────────────────────────────────────────────────────────
        9   => crate::mm::mmap::sys_mmap(a, b, c as u32, d as u32, e, f),
        10  => crate::mm::mmap::sys_mprotect(a, b, c as u32),
        11  => crate::mm::mmap::sys_munmap(a, b),
        12  => crate::mm::mmap::sys_brk(a),
        25  => sys_mremap_impl(a, b, c, d, e),
        28  => sys_madvise_impl(a, b, c as i32),
        149 => sys_mlock_impl(a, b),
        150 => sys_munlock_impl(a, b),
        // ── process / signals ─────────────────────────────────────────────────
        13  => match arg_u32(a) {
                   Some(sig) if sig >= 1 && sig <= 64 =>
                       crate::proc::signal::sys_rt_sigaction(sig, b, c, d),
                   _ => -22,
               },
        14  => match arg_u32(a) {
                   Some(how) if how <= 2 =>
                       crate::proc::signal::sys_rt_sigprocmask(how, b, c, d),
                   _ => -22,
               },
        24  => sys_sched_yield_impl(),
        35  => crate::proc::nanosleep::sys_nanosleep(a, b),
        39  => crate::proc::scheduler::current_pid() as isize,
        56  => sys_clone_impl(a, b, c, d, e),
        57  => crate::proc::fork_syscall::sys_fork(),
        58  => sys_vfork_impl(),
        60  => crate::proc::exit::sys_exit(a as i32),
        61  => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        62  => match arg_u32(b) {
                   Some(sig) if sig <= 64 => sys_kill_impl(a as isize, sig),
                   _ => -22,
               },
        63  => sys_uname_impl(a),
        98  => sys_getrusage_impl(a as i32, b),
        99  => sys_sysinfo_impl(a),
        110 => crate::proc::scheduler::current_ppid() as isize,
        113 => match (arg_u32(a), arg_u32(b)) {
                   (Some(pid), Some(pgid)) => { let _ = (pid, pgid); 0 }
                   _ => -22,
               },
        114 => crate::proc::scheduler::current_pid() as isize,
        121 => crate::proc::scheduler::current_pid() as isize,
        127 => crate::proc::signal::sys_rt_sigpending(a, b),
        128 => crate::proc::signal::sys_rt_sigtimedwait(a, b, c, d),
        130 => crate::proc::signal::sys_rt_sigsuspend(a, b),
        131 => sys_sigaltstack_impl(a, b),
        158 => crate::arch::x86_64::syscall::sys_arch_prctl(a as i32, b),
        185 => sys_prctl_impl(a as i32, b, c, d, e),
        186 => crate::proc::thread::sys_gettid(),
        // ── NPTL threading ────────────────────────────────────────────────────
        200 => match arg_u32(b) {
                   Some(sig) if sig <= 64 => crate::proc::thread::sys_tkill(a, sig),
                   _ => -22,
               },
        202 => crate::proc::futex::sys_futex(a, b as u32, c as u32, d, e, f as u32),
        218 => crate::arch::x86_64::syscall::sys_set_tid_address(a),
        234 => match arg_u32(c) {
                   Some(sig) if sig <= 64 => crate::proc::thread::sys_tgkill(a, b, sig),
                   _ => -22,
               },
        273 => crate::proc::futex::sys_set_robust_list(a, b),
        274 => crate::proc::futex::sys_get_robust_list(a, b, c),
        // ── time ──────────────────────────────────────────────────────────────
        201 => sys_time_impl(a),
        203 => sys_sched_setaffinity_impl(a, b, c),
        204 => sys_sched_getaffinity_impl(a, b, c),
        228 => match arg_u32(a) {
                   Some(clk) => crate::proc::nanosleep::sys_clock_gettime(clk, b),
                   None => -22,
               },
        230 => match arg_u32(a) {
                   Some(clk) => sys_clock_getres_impl(clk, b),
                   None => -22,
               },
        231 => crate::proc::exit::sys_exit_group(a as i32),
        247 => match (arg_i32(a), arg_i32(b), arg_u32(d)) {
                   (Some(idtype), Some(id), Some(opts)) =>
                       sys_waitid_impl(idtype, id, c, opts),
                   _ => -22,
               },
        // ── uid / gid ─────────────────────────────────────────────────────────
        96  => sys_gettimeofday_impl(a, b),
        97  => sys_getrlimit_impl(a as u32, b),
        160 => sys_setrlimit_impl(a as u32, b),
        302 => sys_prlimit64_impl(a, b as u32, c, d),
        102 | 104 | 107 | 108 => 0,
        105 | 106             => 0,
        109 | 117 | 118 | 119 | 120 => 0,
        // ── pidfd ─────────────────────────────────────────────────────────────
        424 => crate::fs::pidfd::sys_pidfd_send_signal(a, b as u32, c, d as u32),
        434 => crate::fs::pidfd::sys_pidfd_open(a, b as u32),
        435 => crate::proc::clone::sys_clone3(a, b),
        438 => crate::fs::pidfd::sys_pidfd_getfd(a, b, c as u32),
        // ── permission / attribute stubs ──────────────────────────────────────
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

// ── Syscall-side side-table cleanup (called from do_exit) ─────────────────────────────
// These are thin forwards so do_exit doesn't need to import signal internals.

pub fn altstack_clear_pid(pid: usize) {
    crate::proc::signal::altstack_clear_pid(pid);
}

pub fn proc_name_clear(_pid: usize) {
    // proc name table lives in stubs.rs for now; no-op until /proc is wired.
}
