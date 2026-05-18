//! ioctl syscall dispatch.

pub mod consts;
pub mod tty;
pub mod net;
pub mod block;
pub mod file;

pub use self::consts::*;

use crate::fs::process_fd::{proc_fd_backing, proc_fd_get, proc_fd_set_cloexec,
    proc_fd_set_nonblock};
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

#[inline(always)]
fn cpid() -> usize { crate::proc::scheduler::current_pid() }

#[inline]
fn resolve(fd: usize) -> isize {
    if fd <= 2 { return fd as isize; }
    proc_fd_backing(cpid(), fd)
}

pub fn sys_ioctl(fd: usize, cmd: u64, arg: usize) -> isize {
    let bfd = resolve(fd) as usize;
    let backing_kind = crate::fs::process_fd::bfd_kind(bfd);
    match backing_kind {
        crate::fs::process_fd::BfdKind::Tty   => self::tty::tty_ioctl(fd, bfd, cmd, arg),
        crate::fs::process_fd::BfdKind::Block => self::block::blk_ioctl(bfd, cmd, arg),
        crate::fs::process_fd::BfdKind::Pipe  => {
            if cmd == FIONREAD { self::file::pipe_fionread(bfd, arg) }
            else if cmd == FIONBIO { self::tty::fionbio(fd, bfd, arg) }
            else { -25 }
        }
        crate::fs::process_fd::BfdKind::Vfs => {
            if cmd == FIONREAD { self::file::vfs_fionread(bfd, arg) }
            else if cmd == FIONBIO { self::tty::fionbio(fd, bfd, arg) }
            else if cmd == FIOCLEX { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            else if cmd == FIONCLEX { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            else { -25 }
        }
        crate::fs::process_fd::BfdKind::Net => {
            if cmd >= 0x8910 && cmd <= 0x8960 { self::net::sioc_ioctl(cmd, arg) }
            else if cmd == FIONBIO { self::tty::fionbio(fd, bfd, arg) }
            else if cmd == FIONREAD { let n: i32 = 0; copy_to_user(arg, &n.to_ne_bytes()); 0 }
            else { -25 }
        }
        _ => -25,
    }
}
