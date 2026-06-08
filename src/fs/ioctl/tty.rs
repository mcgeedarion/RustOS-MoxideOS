//! TTY / termios ioctl handlers.
use super::consts::*;
use crate::uaccess::{copy_from_user, copy_to_user};

pub fn tty_ioctl(fd: usize, req: usize, arg: usize) -> isize {
    match req {
        TCGETS => {
            let mut t = [0u8; 60];
            t[0..4].copy_from_slice(&0x0100u32.to_ne_bytes());
            t[4..8].copy_from_slice(&0x0001u32.to_ne_bytes());
            t[8..12].copy_from_slice(&0x0B00u32.to_ne_bytes());
            t[12..16].copy_from_slice(&0x8A3Bu32.to_ne_bytes());
            t[22] = 1;
            copy_to_user(arg, &t);
            0
        },
        TCSETS | TCSETSW | TCSETSF => 0,
        TIOCGPGRP => {
            let pgid: u32 = crate::proc::scheduler::current_pid() as u32;
            copy_to_user(arg, &pgid.to_ne_bytes());
            0
        },
        TIOCSPGRP => 0,
        TIOCGWINSZ => {
            let ws = [
                25u16.to_ne_bytes(),
                80u16.to_ne_bytes(),
                0u16.to_ne_bytes(),
                0u16.to_ne_bytes(),
            ]
            .concat();
            copy_to_user(arg, &ws);
            0
        },
        TIOCSWINSZ => 0,
        TIOCGPTPEER => -1,
        TIOCSPTLCK => 0,
        TIOCGPTN => {
            copy_to_user(arg, &0u32.to_ne_bytes());
            0
        },
        TIOCNOTTY => 0,
        TIOCSCTTY => 0,
        TIOCEXCL => 0,
        TIOCNXCL => 0,
        TIOCOUTQ => {
            copy_to_user(arg, &0u32.to_ne_bytes());
            0
        },
        TIOCSTI => 0,
        FIONBIO => 0,
        FIOCLEX => 0,
        FIONCLEX => 0,
        FIOASYNC => 0,
        FIONREAD => vfs_fionread(fd, arg),
        _ => -25, // ENOTTY
    }
}

fn vfs_fionread(fd: usize, arg: usize) -> isize {
    let n: u32 = crate::fs::vfs::vfs_fionread(fd).unwrap_or(0) as u32;
    copy_to_user(arg, &n.to_ne_bytes());
    0
}
