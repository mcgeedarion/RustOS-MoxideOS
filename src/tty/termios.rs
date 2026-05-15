//! `struct termios` and all associated constants.
//!
//! Matches the Linux x86_64 / riscv64 UAPI layout in <asm/termbits.h>.
//! The struct is `repr(C)` so it can be passed directly through ioctl
//! TCGETS / TCSETS without any translation.

// ─────────────────────────────────────────────────────────────────────────────
// c_iflag — input mode flags
// ─────────────────────────────────────────────────────────────────────────────

pub mod iflag {
    pub const IGNBRK: u32 = 0o000001;
    pub const BRKINT: u32 = 0o000002;
    pub const IGNPAR: u32 = 0o000004;
    pub const PARMRK: u32 = 0o000010;
    pub const INPCK: u32 = 0o000020;
    pub const ISTRIP: u32 = 0o000040;
    pub const INLCR: u32 = 0o000100;
    pub const IGNCR: u32 = 0o000200;
    pub const ICRNL: u32 = 0o000400; // Map CR → NL on input
    pub const IUCLC: u32 = 0o001000;
    pub const IXON: u32 = 0o002000; // XON/XOFF flow control
    pub const IXANY: u32 = 0o004000;
    pub const IXOFF: u32 = 0o010000;
    pub const IMAXBEL: u32 = 0o020000;
    pub const IUTF8: u32 = 0o040000;
}

// ─────────────────────────────────────────────────────────────────────────────
// c_oflag — output mode flags
// ─────────────────────────────────────────────────────────────────────────────

pub mod oflag {
    pub const OPOST: u32 = 0o000001; // Enable output processing
    pub const OLCUC: u32 = 0o000002;
    pub const ONLCR: u32 = 0o000004; // Map NL → CR+NL
    pub const OCRNL: u32 = 0o000010;
    pub const ONOCR: u32 = 0o000020;
    pub const ONLRET: u32 = 0o000040;
    pub const OFILL: u32 = 0o000100;
    pub const OFDEL: u32 = 0o000200;
}

// ─────────────────────────────────────────────────────────────────────────────
// c_cflag — control mode flags
// ─────────────────────────────────────────────────────────────────────────────

pub mod cflag {
    pub const CS5: u32 = 0o000000;
    pub const CS6: u32 = 0o000020;
    pub const CS7: u32 = 0o000040;
    pub const CS8: u32 = 0o000060;
    pub const CSTOPB: u32 = 0o000100;
    pub const CREAD: u32 = 0o000200;
    pub const PARENB: u32 = 0o000400;
    pub const PARODD: u32 = 0o001000;
    pub const HUPCL: u32 = 0o002000;
    pub const CLOCAL: u32 = 0o004000;
    // Baud rate values encoded in c_cflag (CBAUD mask = 0o010017)
    pub const B0: u32 = 0o000000;
    pub const B9600: u32 = 0o000015;
    pub const B38400: u32 = 0o000017;
    pub const B115200: u32 = 0o010017;
}

// ─────────────────────────────────────────────────────────────────────────────
// c_lflag — local mode flags
// ─────────────────────────────────────────────────────────────────────────────

pub mod lflag {
    pub const ISIG: u32 = 0o000001; // Generate signals (INTR/QUIT/SUSP)
    pub const ICANON: u32 = 0o000002; // Canonical (line) mode
    pub const XCASE: u32 = 0o000004;
    pub const ECHO: u32 = 0o000010; // Echo input
    pub const ECHOE: u32 = 0o000020; // Echo ERASE as BS-SP-BS
    pub const ECHOK: u32 = 0o000040; // Echo KILL
    pub const ECHONL: u32 = 0o000100;
    pub const NOFLSH: u32 = 0o000200;
    pub const TOSTOP: u32 = 0o000400;
    pub const ECHOCTL: u32 = 0o001000;
    pub const ECHOPRT: u32 = 0o002000;
    pub const ECHOKE: u32 = 0o004000;
    pub const FLUSHO: u32 = 0o010000;
    pub const PENDIN: u32 = 0o040000;
    pub const IEXTEN: u32 = 0o100000;
}

// ─────────────────────────────────────────────────────────────────────────────
// c_cc indices
// ─────────────────────────────────────────────────────────────────────────────

pub mod cc {
    pub const VINTR: usize = 0; // ^C  → SIGINT
    pub const VQUIT: usize = 1; // ^\ → SIGQUIT
    pub const VERASE: usize = 2; // DEL / BS
    pub const VKILL: usize = 3; // ^U  — erase line
    pub const VEOF: usize = 4; // ^D
    pub const VTIME: usize = 5; // Read timeout (0.1s units, raw mode)
    pub const VMIN: usize = 6; // Minimum chars for raw read
    pub const VSWTC: usize = 7;
    pub const VSTART: usize = 8; // ^Q  XON
    pub const VSTOP: usize = 9; // ^S  XOFF
    pub const VSUSP: usize = 10; // ^Z  → SIGTSTP
    pub const VEOL: usize = 11;
    pub const VREPRINT: usize = 12;
    pub const VDISCARD: usize = 13;
    pub const VWERASE: usize = 14; // ^W  — erase word
    pub const VLNEXT: usize = 15;
    pub const VEOL2: usize = 16;
    pub const NCCS: usize = 19;
}

// ─────────────────────────────────────────────────────────────────────────────
// struct termios
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; cc::NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Termios {
    /// Standard "cooked" defaults matching a typical Linux xterm.
    pub fn cooked_default() -> Self {
        let mut cc = [0u8; cc::NCCS];
        cc[cc::VINTR] = 0x03; // ^C
        cc[cc::VQUIT] = 0x1C; // ^\
        cc[cc::VERASE] = 0x7F; // DEL
        cc[cc::VKILL] = 0x15; // ^U
        cc[cc::VEOF] = 0x04; // ^D
        cc[cc::VTIME] = 0;
        cc[cc::VMIN] = 1;
        cc[cc::VSTART] = 0x11; // ^Q
        cc[cc::VSTOP] = 0x13; // ^S
        cc[cc::VSUSP] = 0x1A; // ^Z
        Termios {
            c_iflag: iflag::ICRNL | iflag::IXON | iflag::IUTF8,
            c_oflag: oflag::OPOST | oflag::ONLCR,
            c_cflag: cflag::B38400 | cflag::CS8 | cflag::CREAD | cflag::HUPCL,
            c_lflag: lflag::ISIG
                | lflag::ICANON
                | lflag::ECHO
                | lflag::ECHOE
                | lflag::ECHOK
                | lflag::ECHOCTL
                | lflag::ECHOKE
                | lflag::IEXTEN,
            c_line: 0,
            c_cc: cc,
            c_ispeed: 38400,
            c_ospeed: 38400,
        }
    }

    /// "Raw" mode — no processing, suitable for screen editors (vim, less).
    pub fn raw_default() -> Self {
        let mut t = Self::cooked_default();
        t.c_iflag &= !(iflag::IGNBRK
            | iflag::BRKINT
            | iflag::PARMRK
            | iflag::ISTRIP
            | iflag::INLCR
            | iflag::IGNCR
            | iflag::ICRNL
            | iflag::IXON);
        t.c_oflag &= !oflag::OPOST;
        t.c_cflag = cflag::CS8;
        t.c_lflag = 0;
        t.c_cc[cc::VMIN] = 1;
        t.c_cc[cc::VTIME] = 0;
        t
    }

    pub fn is_canonical(&self) -> bool {
        self.c_lflag & lflag::ICANON != 0
    }
    pub fn is_echo(&self) -> bool {
        self.c_lflag & lflag::ECHO != 0
    }
    pub fn is_isig(&self) -> bool {
        self.c_lflag & lflag::ISIG != 0
    }
    pub fn is_opost(&self) -> bool {
        self.c_oflag & oflag::OPOST != 0
    }
    pub fn is_onlcr(&self) -> bool {
        self.c_oflag & oflag::ONLCR != 0
    }
    pub fn is_icrnl(&self) -> bool {
        self.c_iflag & iflag::ICRNL != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// struct winsize  (TIOCGWINSZ / TIOCSWINSZ)
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

// ─────────────────────────────────────────────────────────────────────────────
// ioctl request codes  (match Linux x86_64 UAPI <asm/ioctls.h>)
// ─────────────────────────────────────────────────────────────────────────────

pub mod ioctl {
    pub const TCGETS: usize = 0x5401;
    pub const TCSETS: usize = 0x5402;
    pub const TCSETSW: usize = 0x5403;
    pub const TCSETSF: usize = 0x5404;
    pub const TIOCGWINSZ: usize = 0x5413;
    pub const TIOCSWINSZ: usize = 0x5414;
    pub const TIOCGPTN: usize = 0x8004_5430; // get PTY slave index
    pub const TIOCSPTLCK: usize = 0x4004_5431; // unlock PTY slave
    pub const TIOCGPTLCK: usize = 0x8004_5439;
    pub const TIOCSCTTY: usize = 0x540E; // set controlling terminal
    pub const TIOCNOTTY: usize = 0x5422; // detach controlling terminal
    pub const TIOCGPGRP: usize = 0x540F;
    pub const TIOCSPGRP: usize = 0x5410;
    pub const TIOCGSID: usize = 0x5429;
    pub const FIONREAD: usize = 0x541B;
}
