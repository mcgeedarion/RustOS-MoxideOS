//! ioctl request number constants.

// tty
pub const TCGETS:     usize = 0x5401;
pub const TCSETS:     usize = 0x5402;
pub const TCSETSW:    usize = 0x5403;
pub const TCSETSF:    usize = 0x5404;
pub const TIOCGPGRP:  usize = 0x540F;
pub const TIOCSPGRP:  usize = 0x5410;
pub const TIOCGWINSZ: usize = 0x5413;
pub const TIOCSWINSZ: usize = 0x5414;
pub const TIOCGPTPEER:usize = 0x5441;
pub const TIOCSPTLCK: usize = 0x40045431;
pub const TIOCGPTN:   usize = 0x80045430;
pub const TIOCNOTTY:  usize = 0x5422;
pub const TIOCSCTTY:  usize = 0x540E;
pub const TIOCEXCL:   usize = 0x540C;
pub const TIOCNXCL:   usize = 0x540D;
pub const TIOCOUTQ:   usize = 0x5411;
pub const TIOCSTI:    usize = 0x5412;
pub const FIONREAD:   usize = 0x541B;
pub const FIONBIO:    usize = 0x5421;
pub const FIOCLEX:    usize = 0x5451;
pub const FIONCLEX:   usize = 0x5450;
pub const FIOASYNC:   usize = 0x5452;

// network
pub const SIOCGIFNAME:  usize = 0x8910;
pub const SIOCGIFFLAGS: usize = 0x8913;
pub const SIOCSIFFLAGS: usize = 0x8914;
pub const SIOCGIFADDR:  usize = 0x8915;
pub const SIOCSIFADDR:  usize = 0x8916;
pub const SIOCGIFNETMASK: usize = 0x891B;
pub const SIOCSIFNETMASK: usize = 0x891C;
pub const SIOCGIFHWADDR:  usize = 0x8927;
pub const SIOCGIFMTU:     usize = 0x8921;
pub const SIOCSIFMTU:     usize = 0x8922;
pub const SIOCGIFINDEX:   usize = 0x8933;
pub const SIOCGIFCONF:    usize = 0x8912;
pub const SIOCADDRT:      usize = 0x890B;
pub const SIOCDELRT:      usize = 0x890C;
pub const SIOCGARP:       usize = 0x8954;
pub const SIOCSARP:       usize = 0x8955;
pub const SIOCDARP:       usize = 0x8956;
pub const SIOCETHTOOL:    usize = 0x8946;

// block / generic
pub const BLKGETSIZE:   usize = 0x1260;
pub const BLKGETSIZE64: usize = 0x80081272;
pub const BLKBSZGET:    usize = 0x80081270;
pub const BLKFLSBUF:    usize = 0x1261;
pub const BLKROGET:     usize = 0x125E;
pub const BLKROSET:     usize = 0x125D;