//! ioctl command constants (Linux x86_64 UAPI).
#![allow(dead_code)]

pub const TCGETS:      u64 = 0x5401;
pub const TCSETS:      u64 = 0x5402;
pub const TCSETSW:     u64 = 0x5403;
pub const TCSETSF:     u64 = 0x5404;
pub const TCSBRK:      u64 = 0x5409;
pub const TCXONC:      u64 = 0x540A;
pub const TCFLSH:      u64 = 0x540B;
pub const TIOCSCTTY:   u64 = 0x540E;
pub const TIOCGPGRP:   u64 = 0x540F;
pub const TIOCSPGRP:   u64 = 0x5410;
pub const TIOCOUTQ:    u64 = 0x5411;
pub const TIOCGWINSZ:  u64 = 0x5413;
pub const TIOCSWINSZ:  u64 = 0x5414;
pub const TIOCMGET:    u64 = 0x5415;
pub const TIOCNOTTY:   u64 = 0x5422;
pub const TIOCGSID:    u64 = 0x5429;
pub const FIONBIO:     u64 = 0x5421;
pub const FIONREAD:    u64 = 0x541B;
pub const FIONCLEX:    u64 = 0x5450;
pub const FIOCLEX:     u64 = 0x5451;
pub const TIOCGPTN:    u64 = 0x8004_5430;
pub const TIOCSPTLCK:  u64 = 0x4004_5431;

pub const BLKGETSIZE:   u64 = 0x1260;
pub const BLKGETSIZE64: u64 = 0x8008_1272;
pub const BLKSSZGET:    u64 = 0x1268;
pub const BLKBSZGET:    u64 = 0x8008_1270;

pub const SIOCGIFNAME:    u64 = 0x8910;
pub const SIOCGIFFLAGS:   u64 = 0x8913;
pub const SIOCSIFFLAGS:   u64 = 0x8914;
pub const SIOCGIFADDR:    u64 = 0x8915;
pub const SIOCSIFADDR:    u64 = 0x8916;
pub const SIOCGIFDSTADDR: u64 = 0x8917;
pub const SIOCGIFBRDADDR: u64 = 0x8919;
pub const SIOCGIFNETMASK: u64 = 0x891B;
pub const SIOCGIFMTU:     u64 = 0x8921;
pub const SIOCSIFMTU:     u64 = 0x8922;
pub const SIOCGIFHWADDR:  u64 = 0x8927;
pub const SIOCGIFINDEX:   u64 = 0x8933;
pub const SIOCGIFCONF:    u64 = 0x8912;

pub const IFNAMSIZ:   usize = 16;
pub const IFREQ_SIZE: usize = 40;
pub const TERMIOS_SIZE: usize = 36;
pub const WINSIZE_SIZE: usize = 8;
pub const SCHEME_FD_BASE: usize = 0x8000_0000;
