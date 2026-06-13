//! Subsystem dispatch routers.

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
        SYS_FCHOWNAT => Some(crate::syscall::sys_fchownat_impl(
            a as i32, b, c as u32, d as u32, e as i32,
        )),
        SYS_FCHMODAT => Some(crate::syscall::sys_fchmodat_impl(
            a as i32, b, c as u32,
        )),
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
