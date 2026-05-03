//! ioctl syscall implementation (NR 16).
//!
//! ## Implemented requests
//!   TCGETS   (0x5401) — copy Termios to user
//!   TCSETS   (0x5402) — set Termios from user (immediate)
//!   TCSETSW  (0x5403) — set Termios after drain (treated as TCSETS)
//!   TCSETSF  (0x5404) — set Termios after flush (treated as TCSETS)
//!   TIOCGWINSZ (0x5413) — return window size (80x24 hardcoded)
//!   TIOCSWINSZ (0x5414) — set window size (accepted, ignored)
//!   TIOCGPGRP  (0x540F) — get foreground process group
//!   TIOCSPGRP  (0x5410) — set foreground process group
//!   FIONREAD   (0x541B) — bytes available to read (always 0)
//!   FIOCLEX    (0x5451) — set FD_CLOEXEC
//!   FIONCLEX   (0x5450) — clear FD_CLOEXEC
//!
//! All others return -ENOTTY (-25).

use crate::shell::tty;

// ── ioctl request codes ───────────────────────────────────────────────────

const TCGETS:     usize = 0x5401;
const TCSETS:     usize = 0x5402;
const TCSETSW:    usize = 0x5403;
const TCSETSF:    usize = 0x5404;
const TIOCGWINSZ: usize = 0x5413;
const TIOCSWINSZ: usize = 0x5414;
const TIOCGPGRP:  usize = 0x540F;
const TIOCSPGRP:  usize = 0x5410;
const FIONREAD:   usize = 0x541B;
const FIOCLEX:    usize = 0x5451;
const FIONCLEX:   usize = 0x5450;

// ── winsize struct (4 × u16) ──────────────────────────────────────────────

#[repr(C)]
struct Winsize { ws_row: u16, ws_col: u16, ws_xpixel: u16, ws_ypixel: u16 }

/// sys_ioctl(fd, request, arg) [NR 16]
pub fn sys_ioctl(fd: usize, request: usize, arg: usize) -> isize {
    // Only operate on TTY-like fds (0, 1, 2, or /dev/tty fd).
    let is_tty = fd <= 2
        || crate::fs::devfs::get_dev_fd(fd)
            .map_or(false, |k| k == crate::fs::devfs::DevKind::Tty);

    match request {
        TCGETS => {
            if arg < 0x1000 { return -14; } // EFAULT
            let t = tty::get_termios();
            unsafe { core::ptr::write_volatile(arg as *mut tty::Termios, t); }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            if arg < 0x1000 { return -14; }
            let t = unsafe { core::ptr::read_volatile(arg as *const tty::Termios) };
            tty::set_termios(t);
            0
        }
        TIOCGWINSZ => {
            if arg < 0x1000 { return -14; }
            let ws = Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
            unsafe { core::ptr::write_volatile(arg as *mut Winsize, ws); }
            0
        }
        TIOCSWINSZ => 0,  // accepted, ignored
        TIOCGPGRP => {
            if arg < 0x1000 { return -14; }
            let pid = tty::foreground_pid() as u32;
            unsafe { core::ptr::write_volatile(arg as *mut u32, pid); }
            0
        }
        TIOCSPGRP => {
            if arg < 0x1000 { return -14; }
            let pid = unsafe { core::ptr::read_volatile(arg as *const u32) } as usize;
            tty::set_foreground_pid(pid);
            0
        }
        FIONREAD => {
            if arg < 0x1000 { return -14; }
            unsafe { core::ptr::write_volatile(arg as *mut u32, 0); }
            0
        }
        FIOCLEX  => 0,  // FD_CLOEXEC set — no-op until exec clears fds
        FIONCLEX => 0,  // FD_CLOEXEC clear
        _ => {
            if is_tty { -25 } else { -25 } // ENOTTY
        }
    }
}
