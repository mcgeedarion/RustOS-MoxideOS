extern crate alloc;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};
use crate::fs::process_fd::{proc_fd_set_cloexec, proc_fd_set_nonblock};
use super::consts::*;

fn pty_pair_from_bfd(bfd: usize)
    -> Option<alloc::sync::Arc<crate::tty::pty::Pty>>
{
    crate::tty::pty::get_pty(bfd)
}

pub fn tty_ioctl(fd: usize, bfd: usize, cmd: u64, arg: usize) -> isize {
    match cmd {
        TCGETS => {
            let termios = [0u8; TERMIOS_SIZE];
            copy_to_user(arg, &termios); 0
        }
        TCSETS | TCSETSW | TCSETSF => 0,
        TCSBRK | TCXONC | TCFLSH  => 0,
        TIOCSCTTY => {
            let pid = crate::proc::scheduler::current_pid();
            crate::tty::set_ctty(pid, bfd); 0
        }
        TIOCNOTTY => {
            let pid = crate::proc::scheduler::current_pid();
            crate::tty::clear_ctty(pid); 0
        }
        TIOCGPGRP => {
            let pg = crate::proc::scheduler::current_pgrp() as i32;
            copy_to_user(arg, &pg.to_ne_bytes()); 0
        }
        TIOCSPGRP => {
            let mut buf = [0u8; 4];
            copy_from_user(arg, &mut buf);
            let _pg = i32::from_ne_bytes(buf); 0
        }
        TIOCGSID => {
            let sid = crate::proc::scheduler::current_sid() as i32;
            copy_to_user(arg, &sid.to_ne_bytes()); 0
        }
        TIOCOUTQ => { let n: i32 = 0; copy_to_user(arg, &n.to_ne_bytes()); 0 }
        TIOCGWINSZ => {
            let ws = [0u8; WINSIZE_SIZE];
            copy_to_user(arg, &ws); 0
        }
        TIOCSWINSZ => 0,
        TIOCMGET => { let flags: u32 = 0; copy_to_user(arg, &flags.to_ne_bytes()); 0 }
        TIOCGPTN => {
            let pty = pty_pair_from_bfd(bfd);
            let n: u32 = pty.map(|p| p.index()).unwrap_or(0);
            copy_to_user(arg, &n.to_ne_bytes()); 0
        }
        TIOCSPTLCK => 0,
        FIONREAD   => fionread_tty(arg),
        FIONBIO    => fionbio(fd, bfd, arg),
        FIOCLEX    => { proc_fd_set_cloexec(crate::proc::scheduler::current_pid(), fd, true);  0 }
        FIONCLEX   => { proc_fd_set_cloexec(crate::proc::scheduler::current_pid(), fd, false); 0 }
        _          => -25,
    }
}

pub fn fionbio(fd: usize, bfd: usize, arg: usize) -> isize {
    let mut buf = [0u8; 4];
    copy_from_user(arg, &mut buf);
    let v = i32::from_ne_bytes(buf);
    proc_fd_set_nonblock(crate::proc::scheduler::current_pid(), fd, v != 0);
    0
}

pub fn fionread_tty(arg: usize) -> isize {
    let n: i32 = 0;
    copy_to_user(arg, &n.to_ne_bytes()); 0
}
