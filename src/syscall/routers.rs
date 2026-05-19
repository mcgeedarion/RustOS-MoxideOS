//! Subsystem dispatch routers.
//!
//! Each function handles one logical group of syscalls and returns
//! `Some(retval)` when it owns the nr, `None` otherwise.  The caller
//! (dispatch_with_rip) tries each router in order and falls through to
//! the remaining inline match arms for syscalls that are not yet grouped.
//!
//! ## Adding a new router
//! 1. Add a `fn dispatch_<subsystem>(ctx: &SyscallContext) -> Option<isize>`.
//! 2. Call it inside dispatch_with_rip before the fallthrough match.
//! 3. Register the new NR constants in `nr.rs`.

use crate::syscall::dispatcher_context::SyscallContext;
use crate::syscall::errno::{efault, einval, enosys, enomem, ebadf};
use crate::syscall::nr::*;

// ── Memory management router ──────────────────────────────────────────────
pub fn dispatch_memory(ctx: &SyscallContext) -> Option<isize> {
    match ctx.nr {
        SYS_MMAP => {
            let ret = crate::mm::mmap::sys_mmap(
                ctx.a0(), ctx.a1(), ctx.a2() as i32,
                ctx.a3() as i32, ctx.a4() as i32, ctx.a5() as i64,
            );
            Some(ret)
        }
        SYS_MUNMAP => {
            let ret = crate::mm::mmap::sys_munmap(ctx.a0(), ctx.a1());
            Some(ret)
        }
        SYS_MPROTECT => {
            let ret = crate::mm::mmap::sys_mprotect(ctx.a0(), ctx.a1(), ctx.a2() as i32);
            Some(ret)
        }
        SYS_MREMAP => {
            let ret = crate::mm::mmap::sys_mremap(
                ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(),
            );
            Some(ret)
        }
        SYS_BRK => {
            let ret = crate::mm::brk::sys_brk(ctx.a0());
            Some(ret)
        }
        SYS_MADVISE => Some(0), // no-op: advisory only
        SYS_MINCORE => Some(enosys()), // not yet implemented
        _ => None,
    }
}

// ── Process / thread / signal router ────────────────────────────────────────
pub fn dispatch_process(ctx: &SyscallContext) -> Option<isize> {
    match ctx.nr {
        SYS_GETPID => {
            Some(crate::proc::scheduler::current_pid() as isize)
        }
        SYS_GETPPID => {
            Some(crate::proc::scheduler::current_ppid() as isize)
        }
        SYS_GETTID => {
            Some(crate::proc::scheduler::current_tid() as isize)
        }
        SYS_EXIT => {
            crate::proc::scheduler::exit_current(ctx.a0() as i32);
            Some(0) // unreachable; here to satisfy type
        }
        SYS_EXIT_GROUP => {
            crate::proc::scheduler::exit_group(ctx.a0() as i32);
            Some(0) // unreachable
        }
        SYS_FORK => {
            Some(crate::proc::fork::sys_fork())
        }
        SYS_VFORK => {
            // vfork: identical to fork for now (no CoW optimisation yet).
            Some(crate::proc::fork::sys_fork())
        }
        SYS_CLONE => {
            Some(crate::proc::fork::sys_clone(
                ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(),
            ))
        }
        SYS_CLONE3 => {
            Some(crate::proc::fork::sys_clone3(ctx.a0(), ctx.a1()))
        }
        SYS_EXECVE => {
            Some(crate::proc::exec::sys_execve(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_WAIT4 => {
            Some(crate::proc::wait::sys_wait4(
                ctx.a0() as i32, ctx.a1(), ctx.a2() as i32, ctx.a3(),
            ))
        }
        SYS_KILL => {
            Some(crate::proc::signal::sys_kill(ctx.a0() as i32, ctx.a1() as i32))
        }
        SYS_TKILL => {
            Some(crate::proc::signal::sys_tkill(ctx.a0() as i32, ctx.a1() as i32))
        }
        SYS_TGKILL => {
            Some(crate::proc::signal::sys_tgkill(
                ctx.a0() as i32, ctx.a1() as i32, ctx.a2() as i32,
            ))
        }
        SYS_RT_SIGACTION => {
            Some(crate::proc::signal::sys_rt_sigaction(
                ctx.a0() as i32, ctx.a1(), ctx.a2(), ctx.a3(),
            ))
        }
        SYS_RT_SIGPROCMASK => {
            Some(crate::proc::signal::sys_rt_sigprocmask(
                ctx.a0() as i32, ctx.a1(), ctx.a2(), ctx.a3(),
            ))
        }
        SYS_RT_SIGRETURN => {
            // Intercepted at the arch entry point; reaching dispatch is a bug.
            Some(enosys())
        }
        SYS_UNAME => {
            Some(crate::proc::uname::sys_uname(ctx.a0()))
        }
        SYS_SCHED_YIELD => {
            crate::proc::scheduler::yield_cpu();
            Some(0)
        }
        SYS_NANOSLEEP => {
            Some(crate::time::sleep::sys_nanosleep(ctx.a0(), ctx.a1()))
        }
        SYS_UNSHARE => {
            Some(crate::proc::namespaces::sys_unshare(ctx.a0() as u32))
        }
        SYS_SETNS => {
            Some(crate::proc::namespaces::sys_setns(ctx.a0() as i32, ctx.a1() as i32))
        }
        _ => None,
    }
}

// ── Filesystem router ────────────────────────────────────────────────────────
pub fn dispatch_filesystem(ctx: &SyscallContext) -> Option<isize> {
    match ctx.nr {
        SYS_READ => {
            Some(crate::fs::vfs::sys_read(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_WRITE => {
            Some(crate::fs::vfs::sys_write(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_OPEN => {
            Some(crate::fs::vfs::sys_open(ctx.a0(), ctx.a1() as i32, ctx.a2() as u32))
        }
        SYS_CLOSE => {
            Some(crate::fs::vfs::sys_close(ctx.a0()))
        }
        SYS_STAT => {
            Some(crate::fs::vfs::sys_stat(ctx.a0(), ctx.a1()))
        }
        SYS_FSTAT => {
            Some(crate::fs::vfs::sys_fstat(ctx.a0(), ctx.a1()))
        }
        SYS_LSTAT => {
            Some(crate::fs::vfs::sys_lstat(ctx.a0(), ctx.a1()))
        }
        SYS_LSEEK => {
            Some(crate::fs::vfs::sys_lseek(ctx.a0(), ctx.a1() as i64, ctx.a2() as i32))
        }
        SYS_ACCESS => {
            Some(crate::fs::vfs::sys_access(ctx.a0(), ctx.a1() as i32))
        }
        SYS_GETCWD => {
            Some(crate::fs::vfs::sys_getcwd(ctx.a0(), ctx.a1()))
        }
        SYS_CHDIR => {
            Some(crate::fs::vfs::sys_chdir(ctx.a0()))
        }
        SYS_FCHDIR => {
            Some(crate::fs::vfs::sys_fchdir(ctx.a0()))
        }
        SYS_MKDIR => {
            Some(crate::fs::vfs::sys_mkdir(ctx.a0(), ctx.a1() as u32))
        }
        SYS_RMDIR => {
            Some(crate::fs::vfs::sys_rmdir(ctx.a0()))
        }
        SYS_UNLINK => {
            Some(crate::fs::vfs::sys_unlink(ctx.a0()))
        }
        SYS_RENAME => {
            Some(crate::fs::vfs::sys_rename(ctx.a0(), ctx.a1()))
        }
        SYS_SYMLINK => {
            Some(crate::fs::vfs::sys_symlink(ctx.a0(), ctx.a1()))
        }
        SYS_READLINK => {
            Some(crate::fs::vfs::sys_readlink(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_LINK => {
            Some(crate::fs::vfs::sys_link(ctx.a0(), ctx.a1()))
        }
        SYS_GETDENTS => {
            Some(crate::fs::vfs::sys_getdents64(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_FCNTL => {
            Some(crate::fs::vfs::sys_fcntl(ctx.a0(), ctx.a1() as i32, ctx.a2()))
        }
        SYS_FLOCK => {
            Some(crate::fs::vfs::sys_flock(ctx.a0(), ctx.a1() as i32))
        }
        SYS_FSYNC => {
            Some(crate::fs::vfs::sys_fsync(ctx.a0()))
        }
        SYS_FDATASYNC => {
            Some(crate::fs::vfs::sys_fdatasync(ctx.a0()))
        }
        SYS_TRUNCATE => {
            Some(crate::fs::vfs::sys_truncate(ctx.a0(), ctx.a1() as i64))
        }
        SYS_FTRUNCATE => {
            Some(crate::fs::vfs::sys_ftruncate(ctx.a0(), ctx.a1() as i64))
        }
        SYS_CHMOD => {
            Some(crate::fs::vfs::sys_chmod(ctx.a0(), ctx.a1() as u32))
        }
        SYS_FCHMOD => {
            Some(crate::fs::vfs::sys_fchmod(ctx.a0(), ctx.a1() as u32))
        }
        SYS_CHOWN => {
            Some(crate::fs::vfs::sys_chown(ctx.a0(), ctx.a1() as u32, ctx.a2() as u32))
        }
        SYS_LCHOWN => {
            Some(crate::fs::vfs::sys_lchown(ctx.a0(), ctx.a1() as u32, ctx.a2() as u32))
        }
        SYS_FCHOWN => {
            Some(crate::fs::vfs::sys_fchown(ctx.a0(), ctx.a1() as u32, ctx.a2() as u32))
        }
        SYS_UMASK => {
            Some(crate::fs::vfs::sys_umask(ctx.a0() as u32) as isize)
        }
        SYS_DUP => {
            Some(crate::fs::vfs::sys_dup(ctx.a0()))
        }
        SYS_DUP2 => {
            Some(crate::fs::vfs::sys_dup2(ctx.a0(), ctx.a1()))
        }
        SYS_PIPE => {
            Some(crate::ipc::pipe::sys_pipe(ctx.a0()))
        }
        SYS_SENDFILE => {
            Some(crate::fs::vfs::sys_sendfile(
                ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3(),
            ))
        }
        SYS_PREAD64 => {
            Some(crate::fs::vfs::sys_pread64(ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3() as i64))
        }
        SYS_PWRITE64 => {
            Some(crate::fs::vfs::sys_pwrite64(ctx.a0(), ctx.a1(), ctx.a2(), ctx.a3() as i64))
        }
        SYS_READV => {
            Some(crate::fs::vfs::sys_readv(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_WRITEV => {
            Some(crate::fs::vfs::sys_writev(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_IOCTL => {
            Some(crate::fs::vfs::sys_ioctl(ctx.a0(), ctx.a1(), ctx.a2()))
        }
        SYS_CREAT => {
            Some(crate::fs::vfs::sys_creat(ctx.a0(), ctx.a1() as u32))
        }
        _ => None,
    }
}

// ── IPC router ───────────────────────────────────────────────────────────────
pub fn dispatch_ipc(ctx: &SyscallContext) -> Option<isize> {
    match ctx.nr {
        SYS_FUTEX => {
            Some(crate::proc::futex::sys_futex(
                ctx.a0(), ctx.a1() as i32, ctx.a2() as u32,
                ctx.a3(), ctx.a4(), ctx.a5() as u32,
            ))
        }
        SYS_SET_ROBUST_LIST => {
            // Stub: record the robust-list head address on the PCB.
            let ret = crate::proc::futex::sys_set_robust_list(ctx.a0(), ctx.a1());
            Some(ret)
        }
        SYS_GET_ROBUST_LIST => {
            let ret = crate::proc::futex::sys_get_robust_list(
                ctx.a0() as i32, ctx.a1(), ctx.a2(),
            );
            Some(ret)
        }
        SYS_POLL => {
            Some(crate::fs::poll::sys_poll(ctx.a0(), ctx.a1() as u32, ctx.a2() as i32))
        }
        SYS_SELECT => {
            Some(crate::fs::poll::sys_select(
                ctx.a0() as i32, ctx.a1(), ctx.a2(), ctx.a3(), ctx.a4(),
            ))
        }
        _ => None,
    }
}

// ── Time router ─────────────────────────────────────────────────────────────
pub fn dispatch_time(ctx: &SyscallContext) -> Option<isize> {
    match ctx.nr {
        SYS_ALARM => {
            Some(crate::time::alarm::sys_alarm(ctx.a0() as u32) as isize)
        }
        SYS_PAUSE => {
            Some(crate::time::sleep::sys_pause())
        }
        _ => None,
    }
}
