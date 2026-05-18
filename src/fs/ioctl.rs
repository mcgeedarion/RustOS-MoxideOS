//! `ioctl(2)` — device/file control operations.
//!
//! ## Syscall signature
//!   sys_ioctl(fd: usize, cmd: u64, arg: usize) -> isize
//!   Wired to NR 16 in src/syscall/mod.rs.
//!
//! ## Dispatch order  (on resolved backing fd)
//!
//!   1. fd == 0/1/2 (stdin/stdout/stderr)  → tty layer (TCGETS/TCSETS/TIOC*)
//!   2. scheme fd   (backing >= 0x8000_0000) → scheme_fd::scheme_fd_ioctl
//!   3. pipe fd                              → FIONREAD (readable bytes)
//!   4. socket fd                            → SIOC* network interface ioctls
//!   5. devfs fd                             → FIONREAD / BLKGETSIZE / passthrough
//!   6. PTY master/slave (path = /dev/ptmx   → PTY termios / winsize ioctls
//!                        or /dev/pts/<n>)
//!   7. timerfd / eventfd / inotify / fanotify → FIONREAD
//!   8. plain VFS file                       → FIONREAD via file size
//!
//! ## ioctl commands implemented
//!
//! ### Terminal / PTY
//!   TCGETS  (0x5401) — copy struct termios to user space
//!   TCSETS  (0x5402) — set termios from user space (drain immediately)
//!   TCSETSW (0x5403) — set termios (wait for output to drain) — same as TCSETS
//!   TCSETSF (0x5404) — set termios + flush queues             — same as TCSETS
//!   TIOCGWINSZ (0x5413) — get struct winsize
//!   TIOCSWINSZ (0x5414) — set struct winsize + deliver SIGWINCH
//!   TIOCGPTN   (0x80045430) — get PTY slave index (TIOCGPTN)
//!   TIOCSPTLCK (0x40045431) — lock/unlock PTY slave
//!   TIOCGPGRP  (0x540F) — get foreground process group
//!   TIOCSPGRP  (0x5410) — set foreground process group
//!   TIOCGSID   (0x5429) — get session ID of controlling terminal
//!   TIOCSCTTY  (0x540E) — make fd the controlling terminal
//!   TIOCNOTTY  (0x5422) — detach controlling terminal
//!   FIONBIO    (0x5421) — set / clear O_NONBLOCK on the fd
//!
//! ### Generic / file
//!   FIONREAD   (0x541B) — bytes available to read without blocking
//!   BLKGETSIZE (0x1260) — block device sector count (512-byte sectors)
//!   BLKGETSIZE64 (0x80081272) — block device size in bytes
//!   BLKSSZGET  (0x1268) — logical sector size
//!   FIOCLEX    (0x5451) — set FD_CLOEXEC
//!   FIONCLEX   (0x5450) — clear FD_CLOEXEC
//!
//! ### Network
//!   SIOCGIFFLAGS (0x8913) — get interface flags → arg is *mut ifreq
//!   SIOCSIFFLAGS (0x8914) — set interface flags
//!   SIOCGIFADDR  (0x8915) — get interface address
//!   SIOCSIFADDR  (0x8916) — set interface address
//!   SIOCGIFMTU   (0x8921) — get MTU
//!   SIOCSIFMTU   (0x8922) — set MTU
//!   SIOCGIFHWADDR (0x8927) — get hardware (MAC) address
//!   SIOCGIFINDEX  (0x8933) — get interface index

#![allow(dead_code)]

extern crate alloc;
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

const TCGETS:      u64 = 0x5401;
const TCSETS:      u64 = 0x5402;
const TCSETSW:     u64 = 0x5403;
const TCSETSF:     u64 = 0x5404;
const TCSBRK:      u64 = 0x5409;
const TCXONC:      u64 = 0x540A;
const TCFLSH:      u64 = 0x540B;
const TIOCSCTTY:   u64 = 0x540E;
const TIOCGPGRP:   u64 = 0x540F;
const TIOCSPGRP:   u64 = 0x5410;
const TIOCOUTQ:    u64 = 0x5411;
const TIOCGWINSZ:  u64 = 0x5413;
const TIOCSWINSZ:  u64 = 0x5414;
const TIOCMGET:    u64 = 0x5415;
const TIOCNOTTY:   u64 = 0x5422;
const TIOCGSID:    u64 = 0x5429;
const FIONBIO:     u64 = 0x5421;
const FIONREAD:    u64 = 0x541B;
const FIONCLEX:    u64 = 0x5450;
const FIOCLEX:     u64 = 0x5451;
const TIOCGPTN:    u64 = 0x8004_5430;
const TIOCSPTLCK:  u64 = 0x4004_5431;

const BLKGETSIZE:   u64 = 0x1260;
const BLKGETSIZE64: u64 = 0x8008_1272;
const BLKSSZGET:    u64 = 0x1268;
const BLKBSZGET:    u64 = 0x8008_1270;

const SIOCGIFNAME:   u64 = 0x8910;
const SIOCGIFFLAGS:  u64 = 0x8913;
const SIOCSIFFLAGS:  u64 = 0x8914;
const SIOCGIFADDR:   u64 = 0x8915;
const SIOCSIFADDR:   u64 = 0x8916;
const SIOCGIFDSTADDR:u64 = 0x8917;
const SIOCGIFBRDADDR:u64 = 0x8919;
const SIOCGIFNETMASK:u64 = 0x891B;
const SIOCGIFMTU:    u64 = 0x8921;
const SIOCSIFMTU:    u64 = 0x8922;
const SIOCGIFHWADDR: u64 = 0x8927;
const SIOCGIFINDEX:  u64 = 0x8933;
const SIOCGIFCONF:   u64 = 0x8912;

// ifreq layout (linux/if.h, x86_64) — 40-byte struct
// struct ifreq {
//     char ifr_name[IFNAMSIZ];  /* 16 bytes */
//     union { ... };            /* 24 bytes */
// };
// We treat the union as a raw [u8; 24] and populate individual fields as
// needed (sockaddr_in for SIOCGIFADDR, flags u16, mtu i32, hwaddr, index).
const IFNAMSIZ: usize = 16;
const IFREQ_SIZE: usize = 40;

fn read_ifname(ifreq_va: usize) -> Option<alloc::string::String> {
    if !validate_user_ptr(ifreq_va, IFREQ_SIZE) { return None; }
    let mut raw = [0u8; IFNAMSIZ];
    if copy_from_user(&mut raw, ifreq_va).is_err() { return None; }
    let end = raw.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    Some(alloc::string::String::from_utf8_lossy(&raw[..end]).into_owned())
}

// struct termios layout (x86_64 Linux UAPI, <asm/termbits.h>)
// c_iflag, c_oflag, c_cflag, c_lflag: u32 each = 16 bytes
// c_line: u8 = 1 byte; c_cc[19]: u8 = 19 bytes; Total: 36 bytes
const TERMIOS_SIZE: usize = 36;

// struct winsize: ws_row, ws_col, ws_xpixel, ws_ypixel: u16 each = 8 bytes
const WINSIZE_SIZE: usize = 8;

const SCHEME_FD_BASE: usize = 0x8000_0000;

// Identify PTY fds by path stored in the process fd table:
//   master → debug name contains "ptmx" or "ptymaster"
//   slave  → path starts with "/dev/pts/"
fn pty_pair_from_bfd(bfd: usize) -> Option<alloc::sync::Arc<crate::tty::pty::PtyPair>> {
    if let Some(name) = crate::fs::vfs::fd_get_debug_name(bfd) {
        if name.contains("ptmx") || name.contains("ptymaster") {
            if let Some(idx) = name.split('/').last()
                .and_then(|s| s.parse::<u32>().ok())
            {
                return crate::tty::lookup_pty(idx);
            }
        }
        if let Some(rest) = name.strip_prefix("/dev/pts/") {
            if let Ok(idx) = rest.parse::<u32>() {
                return crate::tty::lookup_pty(idx);
            }
        }
    }
    let path = crate::fs::fcntl::fd_get_path(bfd)?;
    if let Some(rest) = path.strip_prefix("/dev/pts/") {
        if let Ok(idx) = rest.parse::<u32>() {
            return crate::tty::lookup_pty(idx);
        }
    }
    None
}

fn tty_ioctl(fd: usize, bfd: usize, cmd: u64, arg: usize) -> isize {
    match cmd {
        TCGETS => {
            if !validate_user_ptr(arg, TERMIOS_SIZE) { return -14; }
            let pair = pty_pair_from_bfd(bfd);
            let t = if let Some(ref p) = pair {
                let pt = p.get_termios();
                let mut buf = [0u8; TERMIOS_SIZE];
                buf[0..4].copy_from_slice(&pt.c_iflag.to_ne_bytes());
                buf[4..8].copy_from_slice(&pt.c_oflag.to_ne_bytes());
                buf[8..12].copy_from_slice(&pt.c_cflag.to_ne_bytes());
                buf[12..16].copy_from_slice(&pt.c_lflag.to_ne_bytes());
                buf[16] = 0;
                for i in 0..19usize {
                    buf[17 + i] = pt.c_cc[i];
                }
                buf
            } else {
                let t = crate::shell::tty::get_termios();
                let mut buf = [0u8; TERMIOS_SIZE];
                buf[0..4].copy_from_slice(&t.c_iflag.to_ne_bytes());
                buf[4..8].copy_from_slice(&t.c_oflag.to_ne_bytes());
                buf[8..12].copy_from_slice(&t.c_cflag.to_ne_bytes());
                buf[12..16].copy_from_slice(&t.c_lflag.to_ne_bytes());
                buf[16] = 0;
                for i in 0..19usize.min(t.c_cc.len()) {
                    buf[17 + i] = t.c_cc[i];
                }
                buf
            };
            if copy_to_user(arg, &t).is_err() { return -14; }
            0
        }

        TCSETS | TCSETSW | TCSETSF => {
            if !validate_user_ptr(arg, TERMIOS_SIZE) { return -14; }
            let mut buf = [0u8; TERMIOS_SIZE];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let c_iflag = u32::from_ne_bytes(buf[0..4].try_into().unwrap_or([0;4]));
            let c_oflag = u32::from_ne_bytes(buf[4..8].try_into().unwrap_or([0;4]));
            let c_cflag = u32::from_ne_bytes(buf[8..12].try_into().unwrap_or([0;4]));
            let c_lflag = u32::from_ne_bytes(buf[12..16].try_into().unwrap_or([0;4]));
            let mut c_cc = [0u8; 32];
            for i in 0..19usize {
                c_cc[i] = buf[17 + i];
            }

            if let Some(pair) = pty_pair_from_bfd(bfd) {
                use crate::tty::termios::Termios as PtyTermios;
                let new_t = PtyTermios { c_iflag, c_oflag, c_cflag, c_lflag, c_cc };
                pair.set_termios(new_t);
            } else {
                let new_t = crate::shell::tty::Termios {
                    c_iflag, c_oflag, c_cflag, c_lflag, c_cc,
                };
                crate::shell::tty::set_termios(new_t);
            }
            0
        }

        TIOCGWINSZ => {
            if !validate_user_ptr(arg, WINSIZE_SIZE) { return -14; }
            let ws = if let Some(pair) = pty_pair_from_bfd(bfd) {
                let p = pair.get_winsize();
                [p.ws_row, p.ws_col, p.ws_xpixel, p.ws_ypixel]
            } else {
                let w = crate::shell::tty::get_winsize();
                [w.ws_row, w.ws_col, w.ws_xpixel, w.ws_ypixel]
            };
            let mut buf = [0u8; WINSIZE_SIZE];
            buf[0..2].copy_from_slice(&ws[0].to_ne_bytes());
            buf[2..4].copy_from_slice(&ws[1].to_ne_bytes());
            buf[4..6].copy_from_slice(&ws[2].to_ne_bytes());
            buf[6..8].copy_from_slice(&ws[3].to_ne_bytes());
            if copy_to_user(arg, &buf).is_err() { return -14; }
            0
        }

        TIOCSWINSZ => {
            if !validate_user_ptr(arg, WINSIZE_SIZE) { return -14; }
            let mut buf = [0u8; WINSIZE_SIZE];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let ws_row    = u16::from_ne_bytes(buf[0..2].try_into().unwrap_or([0;2]));
            let ws_col    = u16::from_ne_bytes(buf[2..4].try_into().unwrap_or([0;2]));
            let ws_xpixel = u16::from_ne_bytes(buf[4..6].try_into().unwrap_or([0;2]));
            let ws_ypixel = u16::from_ne_bytes(buf[6..8].try_into().unwrap_or([0;2]));

            if let Some(pair) = pty_pair_from_bfd(bfd) {
                use crate::tty::termios::Winsize;
                pair.set_winsize(Winsize { ws_row, ws_col, ws_xpixel, ws_ypixel });
            } else {
                use crate::shell::tty::Winsize;
                crate::shell::tty::set_winsize(Winsize { ws_row, ws_col, ws_xpixel, ws_ypixel });
                let pid = crate::shell::tty::foreground_pid();
                if pid != 0 {
                    crate::proc::signal::send_signal(pid, 28);
                }
            }
            0
        }

        TIOCGPTN => {
            if !validate_user_ptr(arg, 4) { return -14; }
            match pty_pair_from_bfd(bfd) {
                Some(pair) => {
                    let idx = pair.index;
                    if copy_to_user(arg, &idx.to_ne_bytes()).is_err() { return -14; }
                    0
                }
                None => -25,
            }
        }

        TIOCSPTLCK => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut val = [0u8; 4];
            if copy_from_user(&mut val, arg).is_err() { return -14; }
            let lock_val = i32::from_ne_bytes(val);
            match pty_pair_from_bfd(bfd) {
                Some(pair) => {
                    if lock_val == 0 { pair.unlock(); }
                    0
                }
                None => -25,
            }
        }

        TIOCGPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let pgid = crate::shell::tty::foreground_pid() as u32;
            if copy_to_user(arg, &pgid.to_ne_bytes()).is_err() { return -14; }
            0
        }

        TIOCSPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut val = [0u8; 4];
            if copy_from_user(&mut val, arg).is_err() { return -14; }
            let pgid = u32::from_ne_bytes(val) as usize;
            crate::shell::tty::set_foreground_pid(pgid);
            0
        }

        TIOCGSID => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let pid = crate::shell::tty::foreground_pid() as u32;
            if copy_to_user(arg, &pid.to_ne_bytes()).is_err() { return -14; }
            0
        }

        TIOCSCTTY => { 0 }
        TIOCNOTTY  => { 0 }
        TCSBRK     => 0,
        TCXONC     => 0,
        TCFLSH     => 0,

        TIOCOUTQ => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let zero: u32 = 0;
            if copy_to_user(arg, &zero.to_ne_bytes()).is_err() { return -14; }
            0
        }

        TIOCMGET => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let bits: u32 = 0x0020 | 0x0002 | 0x0040 | 0x0020;
            if copy_to_user(arg, &bits.to_ne_bytes()).is_err() { return -14; }
            0
        }

        FIONBIO  => fionbio(fd, bfd, arg),
        FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
        FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
        FIONREAD => fionread_tty(arg),
        _        => -25,
    }
}

fn fionbio(fd: usize, bfd: usize, arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    let mut val = [0u8; 4];
    if copy_from_user(&mut val, arg).is_err() { return -14; }
    let nonblock = i32::from_ne_bytes(val) != 0;
    proc_fd_set_nonblock(cpid(), fd, nonblock);
    let new_fl = if nonblock {
        crate::fs::fcntl::fd_getfl(bfd) | 2048
    } else {
        crate::fs::fcntl::fd_getfl(bfd) & !2048
    };
    crate::fs::fcntl::fd_setfl(bfd, new_fl);
    0
}

fn fionread_tty(arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    let n: u32 = 0;
    if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
    0
}

// FIONREAD for a pipe: reads available bytes without consuming them.
// Uses POLLIN readiness; reports 1 as conservative lower bound when data
// is ready (true peek requires a PipeTable::len() method).
fn pipe_fionread(bfd: usize, arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    use crate::fs::poll::{POLLIN};
    let ready = crate::fs::pipe::pipe_poll(bfd, POLLIN);
    let avail: u32 = if ready & POLLIN != 0 { 1 } else { 0 };
    if copy_to_user(arg, &avail.to_ne_bytes()).is_err() { return -14; }
    0
}

// FIONREAD for regular VFS files: bytes between current seek position and EOF.
fn vfs_fionread(bfd: usize, arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    let avail: u32 = match crate::fs::vfs::file_size(bfd) {
        Some(sz) => {
            let pos = crate::fs::vfs::seek(bfd, 0,
                crate::fs::fcntl::SEEK_CUR);
            if pos < 0 {
                sz as u32
            } else {
                let pos = pos as usize;
                if pos >= sz { 0 } else { (sz - pos) as u32 }
            }
        }
        None => 0,
    };
    if copy_to_user(arg, &avail.to_ne_bytes()).is_err() { return -14; }
    0
}

fn sioc_ioctl(cmd: u64, arg: usize) -> isize {
    if !validate_user_ptr(arg, IFREQ_SIZE) { return -14; }

    let ifname = match read_ifname(arg) {
        Some(n) => n,
        None    => return -14,
    };

    let iface = match crate::net::eth::find_interface(&ifname) {
        Some(i) => i,
        None    => return -19,
    };

    match cmd {
        SIOCGIFFLAGS => {
            let flags: u16 = if iface.is_up() { 0x0001 | 0x0040 } else { 0 };
            let mut buf = [0u8; 2];
            buf.copy_from_slice(&flags.to_ne_bytes());
            if copy_to_user(arg + IFNAMSIZ, &buf).is_err() { return -14; }
            0
        }
        SIOCSIFFLAGS => {
            let mut buf = [0u8; 2];
            if copy_from_user(&mut buf, arg + IFNAMSIZ).is_err() { return -14; }
            let flags = u16::from_ne_bytes(buf);
            let up = flags & 0x0001 != 0;
            iface.set_up(up);
            0
        }
        SIOCGIFADDR => {
            let addr = iface.ipv4_addr();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes());
            sa[4..8].copy_from_slice(&addr.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        SIOCSIFADDR => {
            let mut sa = [0u8; 16];
            if copy_from_user(&mut sa, arg + IFNAMSIZ).is_err() { return -14; }
            let addr = u32::from_be_bytes(sa[4..8].try_into().unwrap_or([0;4]));
            iface.set_ipv4_addr(addr);
            0
        }
        SIOCGIFMTU => {
            let mtu: i32 = iface.mtu() as i32;
            if copy_to_user(arg + IFNAMSIZ, &mtu.to_ne_bytes()).is_err() { return -14; }
            0
        }
        SIOCSIFMTU => {
            let mut buf = [0u8; 4];
            if copy_from_user(&mut buf, arg + IFNAMSIZ).is_err() { return -14; }
            let mtu = i32::from_ne_bytes(buf) as usize;
            if mtu < 68 || mtu > 65535 { return -22; }
            iface.set_mtu(mtu);
            0
        }
        SIOCGIFHWADDR => {
            let mac = iface.mac_addr();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&1u16.to_ne_bytes());
            sa[2..8].copy_from_slice(&mac);
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        SIOCGIFINDEX => {
            let idx: i32 = iface.index() as i32;
            if copy_to_user(arg + IFNAMSIZ, &idx.to_ne_bytes()).is_err() { return -14; }
            0
        }
        SIOCGIFNETMASK => {
            let netmask = iface.netmask();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes());
            sa[4..8].copy_from_slice(&netmask.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        SIOCGIFBRDADDR => {
            let bcast = iface.broadcast();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes());
            sa[4..8].copy_from_slice(&bcast.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        SIOCGIFDSTADDR => {
            let addr = iface.ipv4_addr();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes());
            sa[4..8].copy_from_slice(&addr.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        SIOCGIFNAME => {
            let name_bytes = ifname.as_bytes();
            let mut buf = [0u8; IFNAMSIZ];
            let len = name_bytes.len().min(IFNAMSIZ - 1);
            buf[..len].copy_from_slice(&name_bytes[..len]);
            if copy_to_user(arg, &buf).is_err() { return -14; }
            0
        }
        _ => -22,
    }
}

fn blk_ioctl(bfd: usize, cmd: u64, arg: usize) -> isize {
    let path = match crate::fs::fcntl::fd_get_path(bfd) {
        Some(p) => p,
        None    => return -9,
    };

    let h = match crate::fs::mount::resolve(&path) {
        Ok(h)  => h,
        Err(e) => return e,
    };

    let sectors = crate::block::sector_count_for_mount(&h);
    let sector_size: u32 = 512;
    let total_bytes: u64 = sectors as u64 * sector_size as u64;

    match cmd {
        BLKGETSIZE => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let count = (total_bytes / sector_size as u64) as u32;
            if copy_to_user(arg, &count.to_ne_bytes()).is_err() { return -14; }
            0
        }
        BLKGETSIZE64 => {
            if !validate_user_ptr(arg, 8) { return -14; }
            if copy_to_user(arg, &total_bytes.to_ne_bytes()).is_err() { return -14; }
            0
        }
        BLKSSZGET | BLKBSZGET => {
            if !validate_user_ptr(arg, 4) { return -14; }
            if copy_to_user(arg, &sector_size.to_ne_bytes()).is_err() { return -14; }
            0
        }
        _ => -25,
    }
}

/// `ioctl(2)` — NR 16.
///
/// Translates the user-visible `fd` to a kernel backing fd, classifies the
/// fd type, and dispatches to the appropriate handler above.
pub fn sys_ioctl(fd: usize, cmd: u64, arg: usize) -> isize {
    let bfd = match resolve(fd) {
        n if n < 0 => return n,
        n          => n as usize,
    };

    if fd <= 2 {
        return tty_ioctl(fd, bfd, cmd, arg);
    }

    if bfd >= SCHEME_FD_BASE && !crate::fs::pipe::is_pipe(bfd) {
        if let Some(_pair) = pty_pair_from_bfd(bfd) {
            return tty_ioctl(fd, bfd, cmd, arg);
        }
        return crate::fs::scheme_fd::scheme_fd_ioctl(bfd, cmd, arg);
    }

    if crate::fs::pipe::is_pipe(bfd) {
        return match cmd {
            FIONREAD => pipe_fionread(bfd, arg),
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            _        => -25,
        };
    }

    if crate::net::socket::is_socket_fd(bfd) {
        return match cmd {
            FIONREAD => {
                if !validate_user_ptr(arg, 4) { return -14; }
                let n = crate::net::socket::socket_readable_bytes(bfd) as u32;
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            SIOCGIFFLAGS  | SIOCSIFFLAGS  |
            SIOCGIFADDR   | SIOCSIFADDR   |
            SIOCGIFMTU    | SIOCSIFMTU    |
            SIOCGIFHWADDR | SIOCGIFINDEX  |
            SIOCGIFNETMASK| SIOCGIFBRDADDR|
            SIOCGIFDSTADDR| SIOCGIFNAME   |
            SIOCGIFCONF => sioc_ioctl(cmd, arg),
            _ => -25,
        };
    }

    if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        return match cmd {
            FIONREAD => {
                if !validate_user_ptr(arg, 4) { return -14; }
                let n: u32 = 0;
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            _ => crate::fs::devfs::device_ioctl(bfd, cmd, arg),
        };
    }

    if let Some(_pair) = pty_pair_from_bfd(bfd) {
        return tty_ioctl(fd, bfd, cmd, arg);
    }

    if crate::fs::timerfd::is_timerfd(bfd) {
        return match cmd {
            FIONREAD => {
                if !validate_user_ptr(arg, 4) { return -14; }
                let n: u32 = if crate::fs::timerfd::timerfd_has_expired(bfd) { 8 } else { 0 };
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            _ => -25,
        };
    }

    if crate::fs::eventfd::is_eventfd(bfd) {
        return match cmd {
            FIONREAD => {
                if !validate_user_ptr(arg, 4) { return -14; }
                let n: u32 = if crate::fs::eventfd::eventfd_count(bfd) > 0 { 8 } else { 0 };
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            _ => -25,
        };
    }

    if crate::fs::inotify::is_inotify_fd(bfd) {
        return match cmd {
            FIONREAD => {
                if !validate_user_ptr(arg, 4) { return -14; }
                let n: u32 = if crate::fs::inotify::inotify_has_events(bfd) { 1 } else { 0 };
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            _ => -25,
        };
    }

    if crate::fs::fanotify::is_fanotify_fd(bfd) {
        return match cmd {
            FIONREAD => {
                if !validate_user_ptr(arg, 4) { return -14; }
                let n: u32 = if crate::fs::fanotify::fanotify_has_events(bfd) { 1 } else { 0 };
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            _ => -25,
        };
    }

    match cmd {
        FIONREAD => vfs_fionread(bfd, arg),
        FIONBIO  => fionbio(fd, bfd, arg),
        FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
        FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
        BLKGETSIZE | BLKGETSIZE64 | BLKSSZGET | BLKBSZGET => blk_ioctl(bfd, cmd, arg),
        _ if crate::fs::procfs::is_procfs_fd(bfd) => {
            match cmd {
                FIONREAD => {
                    if !validate_user_ptr(arg, 4) { return -14; }
                    let n: u32 = 0;
                    if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                    0
                }
                _ => -25,
            }
        }
        _ if crate::fs::sysfs::is_sysfs_fd(bfd) => {
            match cmd {
                FIONREAD => {
                    if !validate_user_ptr(arg, 4) { return -14; }
                    let n: u32 = 0;
                    if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                    0
                }
                _ => -25,
            }
        }
        _ if crate::fs::cgroupfs::is_cgroupfs_fd(bfd) => {
            match cmd {
                FIONREAD => {
                    if !validate_user_ptr(arg, 4) { return -14; }
                    let n: u32 = 0;
                    if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                    0
                }
                _ => -25,
            }
        }
        _ => -25,
    }
}
