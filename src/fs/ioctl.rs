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
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── ioctl request codes ─────────────────────────────────────────────────────────
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

// ── winsize struct (4 × u16 = 8 bytes) ──────────────────────────────────────────────
#[repr(C)]
struct Winsize { ws_row: u16, ws_col: u16, ws_xpixel: u16, ws_ypixel: u16 }

/// sys_ioctl(fd, request, arg) [NR 16]
pub fn sys_ioctl(fd: usize, request: usize, arg: usize) -> isize {
    let is_tty = fd <= 2
        || crate::fs::devfs::get_dev_fd(fd)
            .map_or(false, |k| k == crate::fs::devfs::DevKind::Tty);

    match request {
        TCGETS => {
            let sz = core::mem::size_of::<tty::Termios>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let t = tty::get_termios();
            let bytes = unsafe {
                core::slice::from_raw_parts(&t as *const tty::Termios as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            let sz = core::mem::size_of::<tty::Termios>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut buf = alloc::vec![0u8; sz];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            // SAFETY: buf has exactly sizeof(Termios) bytes, all bit
            // patterns are valid for the Termios POD struct.
            let t = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const tty::Termios) };
            tty::set_termios(t);
            0
        }
        TIOCGWINSZ => {
            if !validate_user_ptr(arg, 8) { return -14; }
            let ws = Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
            let bytes = unsafe {
                core::slice::from_raw_parts(&ws as *const Winsize as *const u8, 8)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }
        TIOCSWINSZ => 0,
        TIOCGPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let pid = tty::foreground_pid() as u32;
            if copy_to_user(arg, &pid.to_le_bytes()).is_err() { return -14; }
            0
        }
        TIOCSPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut buf = [0u8; 4];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let pid = u32::from_le_bytes(buf) as usize;
            tty::set_foreground_pid(pid);
            0
        }
        FIONREAD => {
            if !validate_user_ptr(arg, 4) { return -14; }
            if copy_to_user(arg, &0u32.to_le_bytes()).is_err() { return -14; }
            0
        }
        FIOCLEX  => { crate::fs::fcntl::set_cloexec(fd, true);  0 }
        FIONCLEX => { crate::fs::fcntl::set_cloexec(fd, false); 0 }
        _ => {
            if is_tty { -25 } else { -25 } // ENOTTY
        }
    }
}

extern crate alloc;
