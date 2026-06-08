//! Subsystem dispatch routers.

#![allow(unused_variables)]

use crate::syscall::dispatcher_context::SyscallContext;
use crate::syscall::errno::{efault, einval, emsgsize, enosys};
use crate::syscall::nr::*;

// Covers: basic I/O, stat/path ops, directory ops, *at variants, timerfd,
// inotify, fanotify, epoll/poll/select, io_uring, pipes, sendfile,
// eventfd, getdents, fcntl, ioctl, fallocate, copy_file_range, statx,
// sockets (NR 41-55, 288), pidfd.
pub fn dispatch_filesystem(ctx: &SyscallContext) -> Option<isize> {
    let (a, b, c, d, e, f) = (ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(), ctx.a5());
    match ctx.nr {
        SYS_READ => Some(crate::fs::io_syscalls::sys_read(a, b, c)),
        SYS_WRITE => Some(crate::fs::io_syscalls::sys_write(a, b, c)),
        SYS_OPEN => Some(crate::fs::io_syscalls::sys_open(a, b as u32, c as u32)),
        SYS_CLOSE => Some(crate::fs::io_syscalls::sys_close(a)),
        SYS_PREAD64 => Some(crate::fs::io_syscalls::sys_pread64(a, b, c, d as i64)),
        SYS_PWRITE64 => Some(crate::syscall::sys_pwrite64_impl(a, b, c, d as i64)),
        SYS_READV => Some(crate::syscall::sys_readv_impl(a, b, c)),
        SYS_WRITEV => Some(crate::fs::io_syscalls::sys_writev(a, b, c)),
        SYS_SENDFILE => Some(crate::syscall::sys_sendfile_impl(a, b, c, d)),
        SYS_STAT => Some(crate::fs::stat_syscalls::sys_stat(a, b)),
        SYS_FSTAT => Some(crate::fs::stat_syscalls::sys_fstat(a, b)),
        SYS_LSTAT => Some(crate::fs::stat_syscalls::sys_lstat(a, b)),
        SYS_LSEEK => Some(crate::fs::stat_syscalls::sys_lseek(a, b as i64, c as i32)),
        SYS_ACCESS => Some(crate::fs::stat_syscalls::sys_access(a, b as u32)),
        SYS_GETCWD => Some(crate::fs::stat_syscalls::sys_getcwd(a, b)),
        SYS_CHDIR => Some(crate::fs::stat_syscalls::sys_chdir(a)),
        SYS_FCHDIR => Some(crate::syscall::sys_fchdir_impl(a)),
        SYS_MKDIR => Some(crate::fs::stat_syscalls::sys_mkdir(a, b as u32)),
        SYS_RMDIR => Some(crate::syscall::sys_rmdir_impl(a)),
        SYS_UNLINK => Some(crate::fs::stat_syscalls::sys_unlink(a)),
        SYS_RENAME => Some(crate::fs::stat_syscalls::sys_rename(a, b)),
        SYS_LINK => Some(crate::syscall::sys_link_impl(a, b)),
        SYS_SYMLINK => Some(crate::syscall::sys_symlink_impl(a, b)),
        SYS_READLINK => Some(crate::syscall::sys_readlink_impl(a, b, c)),
        SYS_CREAT => Some(crate::syscall::sys_creat_impl(a, b as u32)),
        SYS_UMASK => Some(crate::syscall::sys_umask_impl(a as u32)),
        SYS_SYNC => Some(crate::syscall::sys_sync_impl()),
        SYS_UTIME => Some(crate::syscall::sys_utime_impl(a, b)),
        SYS_UTIMES => Some(crate::syscall::sys_utimes_impl(a, b)),
        SYS_MKNOD => Some(crate::syscall::sys_mknod_impl(a, b as u32, c as u64)),
        SYS_CHMOD => Some(crate::syscall::sys_chmod_impl(a, b as u32)),
        SYS_FCHMOD => Some(crate::syscall::sys_fchmod_impl(a, b as u32)),
        SYS_CHOWN => Some(crate::syscall::sys_chown_impl(a, b as u32, c as u32)),
        SYS_LCHOWN => Some(crate::syscall::sys_lchown_impl(a, b as u32, c as u32)),
        SYS_FCHOWN => Some(crate::syscall::sys_fchown_impl(a, b as u32, c as u32)),
        SYS_STATFS => Some(crate::syscall::sys_statfs_impl(a, b)),
        SYS_FSTATFS => Some(crate::syscall::sys_fstatfs_impl(a, b)),
        SYS_USTAT => Some(crate::syscall::sys_ustat_impl(a as u64, b)),
        SYS_ACCT => Some(crate::syscall::sys_acct_impl(a)),
        SYS_MOUNT => Some(crate::syscall::sys_mount_impl(a, b, c, d as u64, e)),
        SYS_UMOUNT2 => Some(crate::syscall::sys_umount2_impl(a, b as i32)),
        SYS_SWAPON => Some(crate::syscall::sys_swapon_impl(a, b as i32)),
        SYS_SYNCFS => Some(crate::syscall::sys_syncfs_impl(a)),
        SYS_FSYNC => Some(crate::syscall::sys_fsync_impl(a)),
        SYS_FDATASYNC => Some(crate::syscall::sys_fdatasync_impl(a)),
        SYS_TRUNCATE => Some(crate::syscall::sys_truncate_impl(a, b as i64)),
        SYS_FTRUNCATE => Some(crate::syscall::sys_ftruncate_impl(a, b as i64)),
        SYS_FALLOCATE => Some(crate::syscall::sys_fallocate_impl(
            a, b as i32, c as i64, d as i64,
        )),
        SYS_DUP => Some(crate::fs::vfs::dup(a)),
        SYS_DUP2 => Some(crate::fs::fcntl::sys_dup2(a, b)),
        SYS_DUP3 => Some(crate::fs::fcntl::sys_dup3(a, b, c as i32)),
        SYS_FCNTL => Some(crate::fs::fcntl::sys_fcntl(a, b as i32, c)),
        SYS_IOCTL => Some(crate::fs::ioctl::sys_ioctl(a, b, c)),
        SYS_FLOCK => Some(crate::fs::vfs_extras::sys_flock(a, b as i32)),
        SYS_PIPE => Some(crate::fs::pipe::sys_pipe(a)),
        SYS_PIPE2 => Some(crate::fs::pipe::sys_pipe2(a, b as u32)),
        SYS_GETDENTS => Some(crate::fs::getdents::sys_getdents(a, b, c)),
        SYS_GETDENTS64 => Some(crate::fs::getdents::sys_getdents64(a, b, c)),
        SYS_OPENAT => Some(crate::syscall::sys_openat_impl(
            a as i32, b, c as i32, d as u32,
        )),
        SYS_MKDIRAT => Some(crate::syscall::sys_mkdirat_impl(a as i32, b, c as u32)),
        SYS_MKNODAT => Some(crate::syscall::sys_mknodat_impl(
            a as i32, b, c as u32, d as u64,
        )),
        SYS_FCHOWNAT | SYS_FCHMODAT => Some(0), // ownership/permissions not enforced
        SYS_FUTIMESAT => Some(crate::syscall::sys_futimesat_impl(a as i32, b, c)),
        SYS_NEWFSTATAT => Some(crate::syscall::sys_newfstatat_impl(
            a as i32, b, c, d as u32,
        )),
        SYS_UNLINKAT => Some(crate::syscall::sys_unlinkat_impl(a as i32, b, c as u32)),
        SYS_RENAMEAT => Some(crate::syscall::sys_renameat_impl(a as i32, b, c as i32, d)),
        SYS_LINKAT => Some(crate::syscall::sys_linkat_impl(
            a as i32, b, c as i32, d, e as i32,
        )),
        SYS_SYMLINKAT => Some(crate::syscall::sys_symlinkat_impl(a, b as i32, c)),
        SYS_READLINKAT => Some(crate::syscall::sys_readlinkat_impl(a as i32, b, c, d)),
        SYS_FACCESSAT => Some(crate::fs::stat_syscalls::sys_faccessat(
            a as i32, b, c as u32,
        )),
        SYS_UTIMENSAT => Some(crate::syscall::sys_utimensat_impl(a as i32, b, c, d as i32)),
        SYS_EXECVEAT => Some(crate::syscall::sys_execveat_impl(
            a as i32, b, c, d, e as i32,
        )),
        SYS_OPENAT2 => Some(crate::syscall::sys_openat2_impl(a as i32, b, c, d)),
        SYS_COPY_FILE_RANGE => Some(crate::syscall::sys_copy_file_range_impl(
            a, b, c, d, e, f as u32,
        )),
        SYS_PREADV2 => Some(crate::syscall::sys_preadv2_impl(a, b, c, d, e, f as i32)),
        SYS_PWRITEV2 => Some(crate::syscall::sys_pwritev2_impl(a, b, c, d, e, f as i32)),
        SYS_STATX => Some(crate::syscall::sys_statx_impl(
            a as i32, b, c as u32, d as u32, e,
        )),
        SYS_CLOSE_RANGE => match (super::arg_u32(a), super::arg_u32(b), super::arg_u32(c)) {
            (Some(first), Some(last), Some(flags)) => {
                Some(crate::fs::close_range::sys_close_range(first, last, flags))
            },
            _ => Some(einval()),
        },
        SYS_MEMFD_CREATE => Some(crate::syscall::sys_memfd_create_impl(a, b as u32)),
        SYS_REMAP_FILE_PAGES => Some(crate::syscall::sys_remap_file_pages_impl()),
        SYS_POSIX_FADVISE => Some(crate::fs::vfs_extras::sys_posix_fadvise(
            a, b as i64, c as i64, d as i32,
        )),
        SYS_POLL => Some(crate::fs::poll::sys_poll(a, b, c as i32)),
        SYS_SELECT => Some(crate::fs::poll::sys_select(a, b, c, d, e)),
        SYS_PPOLL => Some(crate::fs::poll::sys_ppoll(a, b, c, d, e)),
        SYS_PSELECT6 => Some(crate::fs::poll::sys_pselect6(a, b, c, d, e, f)),
        SYS_EPOLL_CREATE => Some(crate::fs::poll::sys_epoll_create(a as i32)),
        SYS_EPOLL_CREATE1 => Some(crate::syscall::sys_epoll_create1(a as u32)),
        SYS_EPOLL_CTL => Some(crate::fs::poll::sys_epoll_ctl(a, b as i32, c as i32, d)),
        SYS_EPOLL_WAIT => Some(crate::fs::poll::sys_epoll_wait(a, b, c as i32, d as i32)),
        SYS_EPOLL_PWAIT => Some(crate::fs::poll::sys_epoll_pwait(
            a, b, c as i32, d as i32, e, f,
        )),
        SYS_EVENTFD => Some(crate::fs::eventfd::sys_eventfd(a as u32)),
        SYS_EVENTFD2 => Some(crate::fs::eventfd::sys_eventfd2(a as u32, b as u32)),
        SYS_TIMERFD_CREATE => Some(crate::fs::timerfd::sys_timerfd_create(a as u32, b as u32)),
        SYS_TIMERFD_SETTIME => Some(crate::fs::timerfd::sys_timerfd_settime(a, b as i32, c, d)),
        SYS_TIMERFD_GETTIME => Some(crate::fs::timerfd::sys_timerfd_gettime(a, b)),
        SYS_INOTIFY_INIT => Some(crate::fs::inotify::sys_inotify_init1(0)),
        SYS_INOTIFY_ADD_WATCH => Some(crate::fs::inotify::sys_inotify_add_watch(a, b, c as u32)),
        SYS_INOTIFY_RM_WATCH => Some(crate::fs::inotify::sys_inotify_rm_watch(a, b as i32)),
        SYS_INOTIFY_INIT1 => Some(crate::fs::inotify::sys_inotify_init1(a as u32)),
        SYS_FANOTIFY_INIT => Some(crate::fs::fanotify::sys_fanotify_init(a as u32, b as u32)),
        SYS_FANOTIFY_MARK => Some(crate::fs::fanotify::sys_fanotify_mark(
            a, b as u32, c as u64, d as i32, e,
        )),
        SYS_IO_URING_SETUP => Some(crate::io_uring::syscall::sys_io_uring_setup(a as u32, b)),
        SYS_IO_URING_ENTER => Some(crate::io_uring::syscall::sys_io_uring_enter(
            a, b as u32, c as u32, d as u32, e, f,
        )),
        SYS_IO_URING_REGISTER => Some(crate::io_uring::syscall::sys_io_uring_register(
            a, b as u32, c, d as u32,
        )),
        SYS_SOCKET => Some(crate::net::socket::sys_socket(a as i32, b as i32, c as i32)),
        SYS_CONNECT => Some(crate::net::socket::sys_connect(a, b, c as u32)),
        SYS_ACCEPT => Some(crate::net::socket::sys_accept(a, b, c)),
        SYS_SENDTO => Some(crate::net::socket::sys_sendto(
            a, b, c, d as i32, e, f as u32,
        )),
        SYS_RECVFROM => Some(crate::net::socket::sys_recvfrom(a, b, c, d as i32, e, f)),
        SYS_SENDMSG => Some(crate::net::socket::sys_sendmsg(a, b, c as i32)),
        SYS_RECVMSG => Some(crate::net::socket::sys_recvmsg(a, b, c as i32)),
        SYS_SHUTDOWN => Some(crate::net::socket::sys_shutdown(a, b as i32)),
        SYS_BIND => Some(crate::net::socket::sys_bind(a, b, c as u32)),
        SYS_LISTEN => Some(crate::net::socket::sys_listen(a, b as i32)),
        SYS_GETSOCKNAME => Some(crate::net::socket::sys_getsockname(a, b, c)),
        SYS_GETPEERNAME => Some(crate::net::socket::sys_getpeername(a, b, c)),
        SYS_SOCKETPAIR => Some(crate::net::socket::sys_socketpair(
            a as i32, b as i32, c as i32, d,
        )),
        SYS_SETSOCKOPT => Some(crate::net::socket::sys_setsockopt(
            a, b as i32, c as i32, d, e as u32,
        )),
        SYS_GETSOCKOPT => Some(crate::net::socket::sys_getsockopt(
            a, b as i32, c as i32, d, e,
        )),
        SYS_ACCEPT4 => {
            let fd = crate::net::socket::sys_accept(a, b, c);
            if fd >= 0 {
                const SOCK_NONBLOCK: usize = 0x800;
                const SOCK_CLOEXEC: usize = 0x80000;
                if d & SOCK_NONBLOCK != 0 {
                    let mut t = crate::net::socket::TCP_SOCKETS.lock();
                    if let Some(Some(s)) = t.get_mut(fd as usize) {
                        s.nonblocking = true;
                    }
                }
                if d & SOCK_CLOEXEC != 0 {
                    crate::fs::fcntl::set_cloexec(fd as usize, true);
                }
            }
            Some(fd)
        },
        SYS_SENDMMSG => Some(crate::syscall::sys_sendmmsg_impl(a, b, c as u32, d as u32)),
        SYS_RECVMMSG => Some(crate::syscall::sys_recvmmsg_impl(
            a, b, c as u32, d as u32, e,
        )),
        SYS_PIDFD_SEND_SIGNAL => Some(crate::fs::pidfd::sys_pidfd_send_signal(
            a, b as u32, c, d as u32,
        )),
        SYS_PIDFD_OPEN => Some(crate::fs::pidfd::sys_pidfd_open(a, b as u32)),
        SYS_PIDFD_GETFD => Some(crate::fs::pidfd::sys_pidfd_getfd(a, b, c as u32)),
        _ => None,
    }
}

pub fn dispatch_process(ctx: &SyscallContext) -> Option<isize> {
    let (a, b, c, d, e, f) = (ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(), ctx.a5());
    match ctx.nr {
        SYS_GETPID => Some(crate::proc::scheduler::current_pid() as isize),
        SYS_GETPPID => Some(crate::proc::scheduler::current_ppid() as isize),
        SYS_GETTID => Some(crate::proc::thread::sys_gettid()),
        SYS_EXIT => {
            crate::proc::exit::sys_exit(a as i32);
            Some(0)
        },
        SYS_EXIT_GROUP => {
            crate::proc::exit::sys_exit_group(a as i32);
            Some(0)
        },
        SYS_FORK => Some(crate::proc::fork_syscall::sys_fork()),
        SYS_VFORK => Some(crate::syscall::sys_vfork_impl()),
        SYS_CLONE => Some(crate::syscall::sys_clone_impl(a, b, c, d, e)),
        SYS_CLONE3 => Some(crate::proc::clone::sys_clone3(a, b)),
        SYS_EXECVE => Some(crate::proc::exec::sys_execve(a, b, c)),
        SYS_WAIT4 => Some(crate::proc::wait::sys_waitpid(a as isize, b, c as u32)),
        SYS_WAITID => match (super::arg_i32(a), super::arg_i32(b), super::arg_u32(d)) {
            (Some(idtype), Some(id), Some(opts)) => {
                Some(crate::syscall::sys_waitid_impl(idtype, id, c, opts))
            },
            _ => Some(einval()),
        },
        SYS_KILL => match super::arg_u32(b) {
            Some(sig) if sig <= 64 => Some(crate::syscall::sys_kill_impl(a as isize, sig)),
            _ => Some(einval()),
        },
        SYS_TKILL => match super::arg_u32(b) {
            Some(sig) if sig <= 64 => Some(crate::proc::thread::sys_tkill(a, sig)),
            _ => Some(einval()),
        },
        SYS_TGKILL => match super::arg_u32(c) {
            Some(sig) if sig <= 64 => Some(crate::proc::thread::sys_tgkill(a, b, sig)),
            _ => Some(einval()),
        },
        SYS_RT_SIGACTION => match super::arg_u32(a) {
            Some(sig) if sig >= 1 && sig <= 64 => {
                Some(crate::proc::signal::sys_rt_sigaction(sig, b, c, d))
            },
            _ => Some(einval()),
        },
        SYS_RT_SIGPROCMASK => match super::arg_u32(a) {
            Some(how) if how <= 2 => Some(crate::proc::signal::sys_rt_sigprocmask(how, b, c, d)),
            _ => Some(einval()),
        },
        SYS_RT_SIGRETURN => Some(enosys()),
        SYS_RT_SIGPENDING => Some(crate::proc::signal::sys_rt_sigpending(a, b)),
        SYS_RT_SIGTIMEDWAIT => Some(crate::proc::signal::sys_rt_sigtimedwait(a, b, c, d)),
        SYS_RT_SIGSUSPEND => Some(crate::proc::signal::sys_rt_sigsuspend(a, b)),
        SYS_RT_SIGQUEUEINFO => Some(crate::syscall::sys_rt_sigqueueinfo_impl(a as i32, b, c)),
        SYS_SIGALTSTACK => Some(crate::syscall::sys_sigaltstack_impl(a, b)),
        SYS_SCHED_YIELD => {
            crate::proc::scheduler::yield_cpu();
            Some(0)
        },
        SYS_NANOSLEEP => Some(crate::proc::nanosleep::sys_nanosleep(a, b)),
        SYS_PAUSE => Some(crate::syscall::sys_pause_impl()),
        SYS_ALARM => Some(crate::syscall::sys_alarm_impl(a as u32)),
        SYS_UNAME => Some(crate::syscall::sys_uname_impl(a)),
        SYS_ARCH_PRCTL => Some(crate::arch::x86_64::syscall::sys_arch_prctl(a as i32, b)),
        SYS_SET_TID_ADDRESS => Some(crate::arch::x86_64::syscall::sys_set_tid_address(a)),
        SYS_PRCTL => Some(crate::syscall::sys_prctl_impl(a as i32, b, c, d, e)),
        SYS_PTRACE => Some(crate::syscall::sys_ptrace_impl(a as i32, b as i32, c, d)),
        SYS_SYSLOG => Some(crate::syscall::sys_syslog_impl(a as i32, b, c as i32)),
        SYS_UNSHARE => Some(crate::proc::namespace::sys_unshare(a)),
        SYS_SETNS => Some(crate::proc::namespace::sys_setns(a, b as u32)),
        SYS_SECCOMP => Some(crate::security::seccomp::sys_seccomp(a as u32, b as u32, c)),
        SYS_FUTEX => Some(crate::proc::futex::sys_futex(
            a, b as u32, c as u32, d, e, f as u32,
        )),
        SYS_SET_ROBUST_LIST => Some(crate::proc::futex::sys_set_robust_list(a, b)),
        SYS_GET_ROBUST_LIST => Some(crate::proc::futex::sys_get_robust_list(a, b, c)),
        SYS_GETUID | SYS_GETEUID => {
            let pid = crate::proc::scheduler::current_pid();
            Some(crate::proc::scheduler::with_proc(pid, |p| p.uid).unwrap_or(0) as isize)
        },
        SYS_GETGID | SYS_GETEGID => {
            let pid = crate::proc::scheduler::current_pid();
            Some(crate::proc::scheduler::with_proc(pid, |p| p.cred.gid).unwrap_or(0) as isize)
        },
        SYS_SETUID | SYS_SETGID | SYS_SETRESGID => Some(0),
        SYS_GETRESGID => Some(crate::syscall::copy_gid_to_user(a, b, c)),
        SYS_GETRESUID => Some(crate::syscall::copy_uid_to_user(a, b, c)),
        SYS_SETREUID => Some(crate::syscall::sys_setreuid_impl(a as u32, b as u32)),
        SYS_SETREGID => Some(crate::syscall::sys_setregid_impl(a as u32, b as u32)),
        SYS_GETGROUPS => Some(crate::syscall::sys_getgroups_impl(a as i32, b)),
        SYS_SETGROUPS => Some(crate::syscall::sys_setgroups_impl(a as i32, b)),
        SYS_SETRESUID => Some(crate::syscall::sys_setresuid_impl(
            a as u32, b as u32, c as u32,
        )),
        SYS_GETPGRP => Some(crate::syscall::sys_getpgrp_impl()),
        SYS_SETPGID => match (super::arg_u32(a), super::arg_u32(b)) {
            (Some(_), Some(_)) => Some(0),
            _ => Some(einval()),
        },
        #[allow(clippy::match_same_arms)] // stub: returns pid until pgid tracking is wired
        SYS_GETPGID => Some(crate::proc::scheduler::current_pid() as isize),
        SYS_SETSID => Some(crate::syscall::sys_setsid_impl()),
        SYS_GETSID => Some(crate::syscall::sys_getsid_impl(a as u32)),
        SYS_PRLIMIT64 => Some(crate::syscall::sys_prlimit64_impl(a, b as u32, c, d)),
        SYS_GETRLIMIT => Some(crate::syscall::sys_getrlimit_impl(a as u32, b)),
        SYS_SETRLIMIT => Some(crate::syscall::sys_setrlimit_impl(a as u32, b)),
        SYS_GETRUSAGE => Some(crate::syscall::sys_getrusage_impl(a as i32, b)),
        SYS_SYSINFO => Some(crate::syscall::sys_sysinfo_impl(a)),
        SYS_GETCPU => Some(crate::syscall::sys_getcpu_impl(a, b, c)),
        SYS_PROCESS_VM_READV => Some(crate::syscall::sys_process_vm_readv_impl(a, b, c, d, e, f)),
        SYS_PROCESS_VM_WRITEV => Some(crate::syscall::sys_process_vm_writev_impl(a, b, c, d, e, f)),
        SYS_SCHED_SETAFFINITY => Some(crate::syscall::sys_sched_setaffinity_impl(a, b, c)),
        SYS_SCHED_GETAFFINITY => Some(crate::syscall::sys_sched_getaffinity_impl(a, b, c)),
        SYS_SCHED_GETATTR => Some(crate::syscall::sys_sched_getattr_impl(
            a, b as u32, c as u32, d as u32,
        )),
        SYS_SCHED_SETATTR => Some(crate::syscall::sys_sched_setattr_impl(a, b, c as u32)),
        SYS_IOPL => Some(crate::syscall::sys_iopl_impl(a as i32)),
        SYS_IOPERM => Some(crate::syscall::sys_ioperm_impl(a, b, c as i32)),
        SYS_INIT_MODULE => Some(crate::syscall::sys_init_module_impl(a, b, c)),
        SYS_DELETE_MODULE => Some(crate::syscall::sys_delete_module_impl(a, b as u32)),
        SYS_REBOOT => Some(crate::syscall::sys_reboot_impl(
            a as u32, b as u32, c as u32, d,
        )),
        SYS_SETHOSTNAME => Some(crate::syscall::sys_sethostname_impl(a, b)),
        SYS_SETDOMAINNAME => Some(crate::syscall::sys_setdomainname_impl(a, b)),
        SYS_PERSONALITY => Some(crate::syscall::sys_personality_impl(a as u32)),
        SYS_KEXEC_FILE_LOAD => Some(crate::syscall::sys_kexec_file_load_impl()),
        SYS_BPF => Some(crate::syscall::sys_bpf_impl()),
        SYS_USERFAULTFD => Some(crate::syscall::sys_userfaultfd_impl()),
        _ => None,
    }
}

pub fn dispatch_memory(ctx: &SyscallContext) -> Option<isize> {
    let (a, b, c, d, e, f) = (ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(), ctx.a5());
    match ctx.nr {
        SYS_MMAP => Some(crate::mm::mmap::sys_mmap(a, b, c as u32, d as u32, e, f)),
        SYS_MPROTECT => Some(crate::mm::mmap::sys_mprotect(a, b, c as u32)),
        SYS_MUNMAP => Some(crate::mm::mmap::sys_munmap(a, b)),
        SYS_BRK => Some(crate::mm::mmap::sys_brk(a)),
        SYS_MREMAP => Some(crate::syscall::sys_mremap_impl(a, b, c, d, e)),
        SYS_MADVISE => Some(crate::syscall::sys_madvise_impl(a, b, c as i32)),
        SYS_MINCORE => Some(crate::syscall::sys_mincore(a, b, c)),
        SYS_MLOCK => Some(crate::syscall::sys_mlock_impl(a, b)),
        SYS_MUNLOCK => Some(crate::syscall::sys_munlock_impl(a, b)),
        SYS_MLOCK2 => Some(crate::syscall::sys_mlock2_impl(a, b, c as u32)),
        SYS_PKEY_MPROTECT => Some(crate::syscall::sys_pkey_mprotect_impl(
            a, b, c as u32, d as i32,
        )),
        SYS_PKEY_ALLOC => Some(crate::syscall::sys_pkey_alloc_impl(a as u32, b as u64)),
        SYS_PKEY_FREE => Some(crate::syscall::sys_pkey_free_impl(a as i32)),
        _ => None,
    }
}

// futex, poll, and select live in dispatch_process / dispatch_filesystem
// because they cross the IPC / blocking-wait boundary.
pub fn dispatch_ipc(ctx: &SyscallContext) -> Option<isize> {
    let (a, b, c, d, e, _f) = (ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(), ctx.a5());
    match ctx.nr {
        SYS_SHMGET => Some(match crate::ipc::shm::shmget(a as i32, b, c as i32) {
            Ok(id) => id as isize,
            Err(e) => e,
        }),
        SYS_SHMAT => Some(match crate::ipc::shm::shmat(a as i32, b, c as i32) {
            Ok(va) => va as isize,
            Err(e) => e,
        }),
        SYS_SHMDT => Some(match crate::ipc::shm::shmdt(a) {
            Ok(()) => 0,
            Err(e) => e,
        }),
        SYS_SHMCTL => Some(crate::syscall::shmctl_dispatch(a as i32, b as i32, c)),
        SYS_SEMGET => Some(
            match crate::ipc::sem::semget(a as i32, b as i32, c as i32) {
                Ok(id) => id as isize,
                Err(e) => e,
            },
        ),
        SYS_SEMOP => Some(crate::syscall::semop_dispatch(a as i32, b, c)),
        SYS_SEMCTL => Some(crate::syscall::semctl_dispatch(
            a as i32, b as i32, c as i32, d,
        )),
        SYS_MSGGET => Some(match crate::ipc::msg::msgget(a as i32, b as i32) {
            Ok(id) => id as isize,
            Err(e) => e,
        }),
        SYS_MSGSND => Some(crate::syscall::msgsnd_dispatch(a as i32, b, c, d as i32)),
        SYS_MSGRCV => Some(crate::syscall::msgrcv_dispatch(
            a as i32, b, c, d as i64, e as i32,
        )),
        SYS_MSGCTL => Some(crate::syscall::msgctl_dispatch(a as i32, b as i32, c)),
        SYS_MQ_OPEN => Some(crate::syscall::mq_open_dispatch(a, b as i32, c as u32, d)),
        SYS_MQ_UNLINK => Some(crate::syscall::mq_unlink_dispatch(a)),
        SYS_MQ_TIMEDSEND => Some(crate::syscall::mq_timedsend_dispatch(
            a as u64, b, c, d as u32,
        )),
        SYS_MQ_TIMEDRECEIVE => Some(crate::syscall::mq_timedreceive_dispatch(a as u64, b, c, d)),
        SYS_MQ_NOTIFY => Some(crate::syscall::mq_notify_dispatch(a as u64, b)),
        SYS_MQ_GETSETATTR => Some(crate::syscall::mq_getsetattr_dispatch(a as u64, b, c)),
        _ => None,
    }
}

pub fn dispatch_time(ctx: &SyscallContext) -> Option<isize> {
    let (a, b, c, d, _e, _f) = (ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(), ctx.a5());
    match ctx.nr {
        SYS_TIME => Some(crate::syscall::sys_time_impl(a)),
        SYS_GETTIMEOFDAY => Some(crate::syscall::sys_gettimeofday_impl(a, b)),
        SYS_SETTIMEOFDAY => Some(crate::syscall::sys_settimeofday_impl(a, b)),
        SYS_CLOCK_GETTIME => match super::arg_u32(a) {
            Some(clk) => Some(crate::proc::nanosleep::sys_clock_gettime(clk, b)),
            None => Some(einval()),
        },
        SYS_CLOCK_SETTIME => Some(crate::syscall::sys_clock_settime_impl(a as u32, b)),
        SYS_CLOCK_GETRES => match super::arg_u32(a) {
            Some(clk) => Some(crate::syscall::sys_clock_getres_impl(clk, b)),
            None => Some(einval()),
        },
        SYS_CLOCK_NANOSLEEP => match super::arg_u32(a) {
            Some(clk) => Some(crate::syscall::sys_clock_nanosleep_impl(
                clk, b as i32, c, d,
            )),
            None => Some(einval()),
        },
        SYS_GETITIMER => Some(crate::syscall::sys_getitimer_impl(a as i32, b)),
        SYS_SETITIMER => Some(crate::syscall::sys_setitimer_impl(a as i32, b, c)),
        SYS_TIMER_CREATE => Some(crate::syscall::sys_timer_create_impl(a as u32, b, c)),
        SYS_TIMER_SETTIME => Some(crate::syscall::sys_timer_settime_impl(
            a as u32, b as i32, c, d,
        )),
        SYS_TIMER_GETTIME => Some(crate::syscall::sys_timer_gettime_impl(a as u32, b)),
        SYS_TIMER_GETOVERRUN => Some(crate::syscall::sys_timer_getoverrun_impl(a as u32)),
        SYS_TIMER_DELETE => Some(crate::syscall::sys_timer_delete_impl(a as u32)),
        SYS_TIMES => Some(crate::syscall::sys_times_impl(a)),
        _ => None,
    }
}

/// RustOS-private hybrid-kernel service-plane syscalls.
pub fn dispatch_hybrid_services(ctx: &SyscallContext) -> Option<isize> {
    let (a, b, c, _d, _e, _f) = (ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(), ctx.a5());
    match ctx.nr {
        SYS_DRIVER_BIND => Some(crate::syscall::driver::dispatch_driver_bind(
            a as u32, b as u32,
        )),
        SYS_DMA_ALLOC => Some(crate::syscall::driver::dispatch_dma_alloc(
            a as u64,
            b,
            c,
            ctx.a3(),
        )),
        SYS_IRQ_SUBSCRIBE => Some(crate::syscall::driver::dispatch_irq_subscribe(
            a as u64, b as u32, c as u64,
        )),
        SYS_IRQ_ACK => Some(crate::syscall::driver::dispatch_irq_ack(a as u64, b as u32)),
        SYS_SCHEME_REGISTER => Some(crate::syscall::scheme::dispatch_scheme_register(
            a, b, c as u64,
        )),
        SYS_SCHEME_UNREGISTER => Some(crate::syscall::scheme::dispatch_scheme_unregister(a, b)),
        SYS_IPC_ENDPOINT_CREATE => Some(crate::ipc::sys_ipc_endpoint_create()),
        SYS_IPC_RECV => Some(crate::ipc::sys_ipc_recv(a as u64, b, c)),
        SYS_IPC_SEND => Some(crate::ipc::sys_ipc_send(a as u64, b, c)),
        _ => None,
    }
}

// Only active when the kernel is compiled with --features kmtest.
// Uses a private NR range (0x8000_0000+) that can never collide with Linux.
#[cfg(feature = "kmtest")]
pub fn dispatch_kmtest(ctx: &SyscallContext) -> Option<isize> {
    let (a, b, ..) = (ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(), ctx.a5());
    match ctx.nr {
        SYS_KMTEST_LIST => Some(crate::syscall::kmtest::sys_kmtest_list(a, b)),
        SYS_KMTEST_RUN => Some(crate::syscall::kmtest::sys_kmtest_run(a)),
        _ => None,
    }
}

#[cfg(not(feature = "kmtest"))]
pub fn dispatch_kmtest(_ctx: &SyscallContext) -> Option<isize> {
    None
}
