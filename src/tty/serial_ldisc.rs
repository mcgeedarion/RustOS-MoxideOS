//! Serial-backed TTY line discipline — canonical mode with echo.
//!
//! This is the *early* TTY used by the kernel debug REPL before the full
//! PTY/ldisc stack (`src/tty/`) is initialised.  It drives COM1 directly
//! (no IRQ — polled) and therefore makes no scheduler assumptions.
//!
//! Provides the POSIX canonical (cooked) read path:
//!   - Characters accumulate in a line buffer until '\n' or '\r'.
//!   - Backspace (0x7F / 0x08) erases the previous character and echoes the
//!     erase sequence "\x08 \x08" (backspace, space, backspace).
//!   - ^C (0x03) sends SIGINT to the foreground process group.
//!   - ^D (0x04) at the start of a line signals EOF (returns 0).
//!   - ^Z (0x1A) sends SIGTSTP (ignored for now, mapped to SIGSTOP).
//!   - All other printable characters are echoed immediately.
//!
//! Raw mode is also supported (used by programs that do their own input
//! processing, e.g. vim).  Switch via set_raw(true/false).
//!
//! ## Integration
//!   vfs::read(0, buf) → devfs::read(0, buf) → tty::read_line(buf)
//!   vfs::write(1/2, buf) → devfs::write → tty::write(buf)
//!   ioctl TCGETS / TCSETS → tty::get_termios / set_termios

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

const COM1: u16 = 0x3F8;

#[inline]
fn serial_write(b: u8) {
    unsafe {
        loop {
            let lsr: u8;
            core::arch::asm!("in al, dx", out("al") lsr, in("dx") COM1+5, options(nostack));
            if lsr & 0x20 != 0 {
                break;
            }
        }
        core::arch::asm!("out dx, al", in("dx") COM1, in("al") b, options(nostack));
    }
}

#[inline]
fn serial_read() -> Option<u8> {
    unsafe {
        let lsr: u8;
        core::arch::asm!("in al, dx", out("al") lsr, in("dx") COM1+5, options(nostack));
        if lsr & 0x01 == 0 {
            return None;
        }
        let d: u8;
        core::arch::asm!("in al, dx", out("al") d, in("dx") COM1, options(nostack));
        Some(d)
    }
}

#[derive(Clone, Copy)]
pub struct Termios {
    pub c_iflag: u32, // input flags
    pub c_oflag: u32, // output flags
    pub c_cflag: u32, // control flags
    pub c_lflag: u32, // local flags
    pub c_cc: [u8; 32],
}

impl Termios {
    pub const fn default() -> Self {
        let mut cc = [0u8; 32];
        cc[3] = 0x7F; // VERASE = DEL
        cc[4] = 28; // VKILL  = \\
        cc[5] = 4; // VEOF   = ^D
        cc[6] = 0; // VTIME
        cc[7] = 1; // VMIN
        cc[8] = 17; // VSTART = ^Q
        cc[9] = 19; // VSTOP  = ^S
        cc[10] = 26; // VSUSP  = ^Z
        cc[11] = 0; // VEOL
        cc[1] = 3; // VINTR  = ^C
        cc[2] = 28; // VQUIT  = ^|
        Self {
            c_iflag: 0x0500, // ICRNL | IXON
            c_oflag: 0x0005, // OPOST | ONLCR
            c_cflag: 0x00BF, // CS8 | CREAD | CLOCAL
            c_lflag: 0x8A3B, // ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN
            c_cc: cc,
        }
    }

    pub fn is_canonical(&self) -> bool {
        self.c_lflag & 0x0002 != 0
    } // ICANON
    pub fn echo_on(&self) -> bool {
        self.c_lflag & 0x0008 != 0
    } // ECHO
}

/// POSIX window size (struct winsize, <sys/ioctl.h>).
/// Stored in TtyState so TIOCSWINSZ persists across calls and TIOCGWINSZ
/// returns the last value set rather than a hardcoded constant.
#[derive(Clone, Copy)]
pub struct Winsize {
    pub ws_row: u16,    // terminal rows
    pub ws_col: u16,    // terminal columns
    pub ws_xpixel: u16, // pixel width  (0 = unknown)
    pub ws_ypixel: u16, // pixel height (0 = unknown)
}

impl Winsize {
    pub const fn default() -> Self {
        Self {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

struct TtyState {
    line_buf: Vec<u8>,
    termios: Termios,
    foreground_pid: usize,
    winsize: Winsize,
}

static TTY: Mutex<TtyState> = Mutex::new(TtyState {
    line_buf: Vec::new(),
    termios: Termios::default(),
    foreground_pid: 1,
    winsize: Winsize::default(),
});

fn echo(b: u8, tty: &Termios) {
    if !tty.echo_on() {
        return;
    }
    if b == b'\r' || b == b'\n' {
        serial_write(b'\r');
        serial_write(b'\n');
    } else if b < 0x20 {
        // Control character — print as ^X
        serial_write(b'^');
        serial_write(b + b'@');
    } else {
        serial_write(b);
    }
}

fn echo_erase(tty: &Termios) {
    if tty.echo_on() {
        serial_write(0x08); // backspace
        serial_write(b' ');
        serial_write(0x08);
    }
}

/// Block until a full line is available, then copy up to buf.len() bytes.
/// Returns bytes read, or 0 for EOF (^D), or negative errno.
pub fn read_line(buf: &mut [u8]) -> isize {
    loop {
        // Drain any pending line from the buffer first.
        {
            let mut tty = TTY.lock();
            if tty.line_buf.contains(&b'\n') || tty.line_buf.contains(&b'\x04') {
                return drain_line(&mut tty, buf);
            }
        }

        // Read bytes from serial until we have a complete line.
        loop {
            let byte = loop {
                if let Some(b) = serial_read() {
                    break b;
                }
                core::hint::spin_loop();
            };

            let mut tty = TTY.lock();
            let is_canon = tty.termios.is_canonical();

            if !is_canon {
                // Raw mode: return immediately.
                if buf.is_empty() {
                    return 0;
                }
                buf[0] = byte;
                return 1;
            }

            match byte {
                // ^C → SIGINT
                0x03 => {
                    let pid = tty.foreground_pid;
                    drop(tty);
                    crate::proc::signal::send_signal(pid, 2);
                    serial_write(b'^');
                    serial_write(b'C');
                    serial_write(b'\r');
                    serial_write(b'\n');
                    return -4; // EINTR
                },
                // ^D → EOF
                0x04 => {
                    if tty.line_buf.is_empty() {
                        return 0; // EOF
                    }
                    // Flush current line without newline.
                    tty.line_buf.push(0x04);
                    return drain_line(&mut tty, buf);
                },
                // ^Z → SIGTSTP
                0x1A => {
                    let pid = tty.foreground_pid;
                    drop(tty);
                    crate::proc::signal::send_signal(pid, 20);
                    return -4; // EINTR
                },
                // Backspace / DEL
                0x08 | 0x7F => {
                    if !tty.line_buf.is_empty() {
                        tty.line_buf.pop();
                        echo_erase(&tty.termios.clone());
                    }
                },
                // CR → LF
                b'\r' => {
                    echo(b'\n', &tty.termios.clone());
                    tty.line_buf.push(b'\n');
                    return drain_line(&mut tty, buf);
                },
                // Normal character
                _ => {
                    echo(byte, &tty.termios.clone());
                    tty.line_buf.push(byte);
                    if byte == b'\n' {
                        return drain_line(&mut tty, buf);
                    }
                },
            }
        }
    }
}

fn drain_line(tty: &mut TtyState, buf: &mut [u8]) -> isize {
    let n = buf.len().min(tty.line_buf.len());
    buf[..n].copy_from_slice(&tty.line_buf[..n]);
    tty.line_buf.drain(..n);
    n as isize
}

/// Write bytes to the terminal with ONLCR translation (\n → \r\n).
pub fn write(buf: &[u8]) -> isize {
    let tty = TTY.lock();
    let onlcr = tty.termios.c_oflag & 0x0004 != 0; // ONLCR
    drop(tty);
    for &b in buf {
        if onlcr && b == b'\n' {
            serial_write(b'\r');
        }
        serial_write(b);
    }
    buf.len() as isize
}

/// Get a copy of the current termios struct.
pub fn get_termios() -> Termios {
    TTY.lock().termios
}

/// Replace the termios struct (used by TCSETS ioctl).
pub fn set_termios(t: Termios) {
    TTY.lock().termios = t;
}

/// Set/clear raw mode.
pub fn set_raw(raw: bool) {
    let mut tty = TTY.lock();
    if raw {
        tty.termios.c_lflag &= !(0x0002 | 0x0008); // clear ICANON | ECHO
    } else {
        tty.termios.c_lflag |= 0x0002 | 0x0008; // set   ICANON | ECHO
    }
}

/// Get the current window size (used by TIOCGWINSZ ioctl).
/// Returns the last value set via TIOCSWINSZ, defaulting to 80x24.
pub fn get_winsize() -> Winsize {
    TTY.lock().winsize
}

/// Store a new window size (used by TIOCSWINSZ ioctl).
/// Programmes that call tcgetwinsize/tcsetwinsize see a consistent value.
pub fn set_winsize(ws: Winsize) {
    TTY.lock().winsize = ws;
}

/// Set the foreground process group (for SIGINT/SIGTSTP delivery).
pub fn set_foreground_pid(pid: usize) {
    TTY.lock().foreground_pid = pid;
}
pub fn foreground_pid() -> usize {
    TTY.lock().foreground_pid
}
