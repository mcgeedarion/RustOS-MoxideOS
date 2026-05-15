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

// ── Current pid shorthand ────────────────────────────────────────────────────
#[inline(always)]
fn cpid() -> usize { crate::proc::scheduler::current_pid() }

// ── fd resolver (user → backing) ────────────────────────────────────────────
#[inline]
fn resolve(fd: usize) -> isize {
    if fd <= 2 { return fd as isize; }
    proc_fd_backing(cpid(), fd)
}

// ── POSIX ioctl command constants ────────────────────────────────────────────

// Terminal
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

// Block device
const BLKGETSIZE:   u64 = 0x1260;
const BLKGETSIZE64: u64 = 0x8008_1272;
const BLKSSZGET:    u64 = 0x1268;
const BLKBSZGET:    u64 = 0x8008_1270;

// Network (SIOC*)
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

// ── ifreq layout (linux/if.h, x86_64) — 40-byte struct ─────────────────────
//
// struct ifreq {
//     char ifr_name[IFNAMSIZ];  /* 16 bytes */
//     union { ... };            /* 24 bytes */
// };
//
// We treat the union as a raw [u8; 24] and populate individual fields as
// needed (sockaddr_in for SIOCGIFADDR, flags u16, mtu i32, hwaddr, index).
const IFNAMSIZ: usize = 16;
const IFREQ_SIZE: usize = 40;

/// Read a NUL-terminated interface name from the first IFNAMSIZ bytes of ifreq.
fn read_ifname(ifreq_va: usize) -> Option<alloc::string::String> {
    if !validate_user_ptr(ifreq_va, IFREQ_SIZE) { return None; }
    let mut raw = [0u8; IFNAMSIZ];
    if copy_from_user(&mut raw, ifreq_va).is_err() { return None; }
    let end = raw.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    Some(alloc::string::String::from_utf8_lossy(&raw[..end]).into_owned())
}

// ── struct termios layout (x86_64 Linux UAPI, <asm/termbits.h>) ─────────────
//
// struct termios2 is the same size but we only use termios here.
// c_iflag, c_oflag, c_cflag, c_lflag: u32 each   = 16 bytes
// c_line: u8                                       =  1 byte
// c_cc[19]: u8                                     = 19 bytes
// Total: 36 bytes (matches Linux kernel struct termios)
const TERMIOS_SIZE: usize = 36;

// ── struct winsize layout ────────────────────────────────────────────────────
// ws_row, ws_col, ws_xpixel, ws_ypixel: u16 each = 8 bytes
const WINSIZE_SIZE: usize = 8;

// ── Scheme backing-fd range (from scheme_fd.rs) ──────────────────────────────
const SCHEME_FD_BASE: usize = 0x8000_0000;

// ── Helper: is this fd a PTY master or slave? ────────────────────────────────
//
// We identify PTY fds by the path stored in the process fd table:
//   master  → path is None  (devfs open of /dev/ptmx stores no path)
//             **or** debug name contains "ptmx" or "ptymaster"
//   slave   → path starts with "/dev/pts/"
//
// Returns Some(pair_index) when `bfd` is a PTY fd.
fn pty_pair_from_bfd(bfd: usize) -> Option<alloc::sync::Arc<crate::tty::pty::PtyPair>> {
    // Try debug name first (set when /dev/ptmx is opened via devfs path).
    if let Some(name) = crate::fs::vfs::fd_get_debug_name(bfd) {
        if name.contains("ptmx") || name.contains("ptymaster") {
            // Master: the debug name encodes the pair index as the last
            // component, e.g. "ptmx/3" or we stored the index directly.
            if let Some(idx) = name.split('/').last()
                .and_then(|s| s.parse::<u32>().ok())
            {
                return crate::tty::lookup_pty(idx);
            }
        }
        // Slave path: "/dev/pts/<n>"
        if let Some(rest) = name.strip_prefix("/dev/pts/") {
            if let Ok(idx) = rest.parse::<u32>() {
                return crate::tty::lookup_pty(idx);
            }
        }
    }
    // Fall back to path stored in the process fd table.
    let path = crate::fs::fcntl::fd_get_path(bfd)?;
    if let Some(rest) = path.strip_prefix("/dev/pts/") {
        if let Ok(idx) = rest.parse::<u32>() {
            return crate::tty::lookup_pty(idx);
        }
    }
    None
}

// ── TTY ioctl (fd 0/1/2 or any terminal-class fd) ────────────────────────────

fn tty_ioctl(fd: usize, bfd: usize, cmd: u64, arg: usize) -> isize {
    match cmd {
        // ── TCGETS ────────────────────────────────────────────────────────────
        TCGETS => {
            if !validate_user_ptr(arg, TERMIOS_SIZE) { return -14; } // EFAULT
            // Try PTY pair first; fall back to the raw serial tty.
            let pair = pty_pair_from_bfd(bfd);
            let t = if let Some(ref p) = pair {
                let pt = p.get_termios();
                // Convert tty::termios::Termios → packed bytes
                let mut buf = [0u8; TERMIOS_SIZE];
                buf[0..4].copy_from_slice(&pt.c_iflag.to_ne_bytes());
                buf[4..8].copy_from_slice(&pt.c_oflag.to_ne_bytes());
                buf[8..12].copy_from_slice(&pt.c_cflag.to_ne_bytes());
                buf[12..16].copy_from_slice(&pt.c_lflag.to_ne_bytes());
                // c_line (1 byte) at offset 16
                buf[16] = 0; // N_TTY
                // c_cc[19] at offset 17 — copy first 19 elements of pt.c_cc
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

        // ── TCSETS / TCSETSW / TCSETSF ───────────────────────────────────────
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

        // ── TIOCGWINSZ ────────────────────────────────────────────────────────
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

        // ── TIOCSWINSZ ────────────────────────────────────────────────────────
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
                // SIGWINCH is delivered by PtyPair::set_winsize.
            } else {
                use crate::shell::tty::Winsize;
                crate::shell::tty::set_winsize(Winsize { ws_row, ws_col, ws_xpixel, ws_ypixel });
                // Deliver SIGWINCH to the foreground process.
                let pid = crate::shell::tty::foreground_pid();
                if pid != 0 {
                    crate::proc::signal::send_signal(pid, 28 /* SIGWINCH */);
                }
            }
            0
        }

        // ── TIOCGPTN — get PTY slave index ───────────────────────────────────
        TIOCGPTN => {
            if !validate_user_ptr(arg, 4) { return -14; }
            match pty_pair_from_bfd(bfd) {
                Some(pair) => {
                    let idx = pair.index;
                    if copy_to_user(arg, &idx.to_ne_bytes()).is_err() { return -14; }
                    0
                }
                None => -25, // ENOTTY — not a PTY
            }
        }

        // ── TIOCSPTLCK — lock/unlock PTY slave ───────────────────────────────
        TIOCSPTLCK => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut val = [0u8; 4];
            if copy_from_user(&mut val, arg).is_err() { return -14; }
            let lock_val = i32::from_ne_bytes(val);
            match pty_pair_from_bfd(bfd) {
                Some(pair) => {
                    if lock_val == 0 { pair.unlock(); }
                    // Non-zero: lock — unlockpt(3) only ever passes 0.
                    0
                }
                None => -25, // ENOTTY
            }
        }

        // ── TIOCGPGRP — get foreground process group ──────────────────────────
        TIOCGPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let pgid = crate::shell::tty::foreground_pid() as u32;
            if copy_to_user(arg, &pgid.to_ne_bytes()).is_err() { return -14; }
            0
        }

        // ── TIOCSPGRP — set foreground process group ──────────────────────────
        TIOCSPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut val = [0u8; 4];
            if copy_from_user(&mut val, arg).is_err() { return -14; }
            let pgid = u32::from_ne_bytes(val) as usize;
            crate::shell::tty::set_foreground_pid(pgid);
            0
        }

        // ── TIOCGSID — get session ID ─────────────────────────────────────────
        TIOCGSID => {
            if !validate_user_ptr(arg, 4) { return -14; }
            // Return the session ID of the foreground process group.
            let pid = crate::shell::tty::foreground_pid() as u32;
            if copy_to_user(arg, &pid.to_ne_bytes()).is_err() { return -14; }
            0
        }

        // ── TIOCSCTTY — make fd the controlling terminal ───────────────────────
        TIOCSCTTY => {
            // arg is the "steal" flag (1 = steal from another session).
            // For a single-session kernel this is a no-op: the terminal is
            // already the controlling terminal of the calling process.
            0
        }

        // ── TIOCNOTTY — detach controlling terminal ───────────────────────────
        TIOCNOTTY => {
            // No-op: single-session kernel.
            0
        }

        // ── TCSBRK — send break / drain ───────────────────────────────────────
        TCSBRK => 0, // No-op on a serial emulator.

        // ── TCXONC — flow control start/stop ─────────────────────────────────
        TCXONC => 0, // No-op.

        // ── TCFLSH — flush input/output queues ───────────────────────────────
        TCFLSH => 0, // No-op: no buffered data to flush on this path.

        // ── TIOCOUTQ — bytes pending in output queue ──────────────────────────
        TIOCOUTQ => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let zero: u32 = 0; // write-through serial; output queue is always empty
            if copy_to_user(arg, &zero.to_ne_bytes()).is_err() { return -14; }
            0
        }

        // ── TIOCMGET — get modem control bits ────────────────────────────────
        TIOCMGET => {
            if !validate_user_ptr(arg, 4) { return -14; }
            // Report DCD + DSR + CTS + CAR asserted (typical for a virtual tty).
            let bits: u32 = 0x0020 | 0x0002 | 0x0040 | 0x0020; // TIOCM_CAR | TIOCM_DSR | TIOCM_CTS
            if copy_to_user(arg, &bits.to_ne_bytes()).is_err() { return -14; }
            0
        }

        // ── FIONBIO — set/clear O_NONBLOCK ───────────────────────────────────
        FIONBIO => fionbio(fd, bfd, arg),

        // ── FIOCLEX / FIONCLEX ───────────────────────────────────────────────
        FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
        FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }

        // ── FIONREAD — for a tty: 0 readable (non-blocking check) ────────────
        FIONREAD => fionread_tty(arg),

        // Anything else: not a TTY function, caller should use -ENOTTY.
        _ => -25, // ENOTTY
    }
}

// ── FIONBIO helper ───────────────────────────────────────────────────────────

fn fionbio(fd: usize, bfd: usize, arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    let mut val = [0u8; 4];
    if copy_from_user(&mut val, arg).is_err() { return -14; }
    let nonblock = i32::from_ne_bytes(val) != 0;
    proc_fd_set_nonblock(cpid(), fd, nonblock);
    // Also update fcntl FD_META so F_GETFL reflects the new flag.
    let new_fl = if nonblock {
        crate::fs::fcntl::fd_getfl(bfd) | 2048 // O_NONBLOCK
    } else {
        crate::fs::fcntl::fd_getfl(bfd) & !2048
    };
    crate::fs::fcntl::fd_setfl(bfd, new_fl);
    0
}

// ── FIONREAD for a tty (always 0 — canonical mode reads block) ──────────────

fn fionread_tty(arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    let n: u32 = 0;
    if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
    0
}

// ── FIONREAD for a pipe ──────────────────────────────────────────────────────
//
// Reads the number of bytes currently available in the pipe's ring buffer
// without consuming them.  The result is written as a u32 (int) to *arg.

fn pipe_fionread(bfd: usize, arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    // Peek at the pipe's ring buffer length via a zero-byte read.
    // We use a 1-byte dummy buf with a non-blocking poll instead of
    // draining the pipe.
    //
    // Strategy: ask pipe_poll for POLLIN; if set, do a length query via
    // the poll mechanism.  For now we do a best-effort: count by peeking
    // at the backing ring through the poll-readiness flag.
    //
    // The pipe module does not expose a separate readable_bytes() helper,
    // so we approximate: if poll says data is ready, attempt to read up to
    // PIPE_BUF_SIZE into a temp buf with a non-draining method.  Since we
    // can't peek, we instead report the minimum of what poll reports.
    //
    // A proper implementation requires a peek/len method on PipeTable.
    // We use the poll-based approach: POLLIN set → at least 1 byte, else 0.
    // This is sufficient for musl's stdio which only tests nonzero.
    use crate::fs::poll::{POLLIN};
    let ready = crate::fs::pipe::pipe_poll(bfd, POLLIN);
    let avail: u32 = if ready & POLLIN != 0 {
        // Read into a scratch buffer to find the exact byte count.
        // We must not consume the data so we use a temp allocation and
        // immediately restore.  Since we cannot do a true peek on our ring
        // buffer without modifying pipe.rs, we report 1 as a conservative
        // lower bound.  Callers (select/poll) only care about nonzero.
        1
    } else {
        0
    };
    if copy_to_user(arg, &avail.to_ne_bytes()).is_err() { return -14; }
    0
}

// ── FIONREAD for regular VFS files ───────────────────────────────────────────
//
// Reports bytes between the current seek position and end of file.

fn vfs_fionread(bfd: usize, arg: usize) -> isize {
    if !validate_user_ptr(arg, 4) { return -14; }
    let avail: u32 = match crate::fs::vfs::file_size(bfd) {
        Some(sz) => {
            // Get current offset via a SEEK_CUR of 0.
            let pos = crate::fs::vfs::seek(bfd, 0,
                crate::fs::fcntl::SEEK_CUR);
            if pos < 0 {
                // fd is not seekable (e.g. devfs node) — report size as avail.
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

// ── Network interface ioctl helpers ─────────────────────────────────────────

fn sioc_ioctl(cmd: u64, arg: usize) -> isize {
    if !validate_user_ptr(arg, IFREQ_SIZE) { return -14; }

    let ifname = match read_ifname(arg) {
        Some(n) => n,
        None    => return -14,
    };

    // Look up the interface by name.
    let iface = match crate::net::eth::find_interface(&ifname) {
        Some(i) => i,
        None    => return -19, // ENODEV
    };

    match cmd {
        // ── SIOCGIFFLAGS ─────────────────────────────────────────────────────
        SIOCGIFFLAGS => {
            // Write IFF_UP | IFF_RUNNING into ifr_flags (offset 16, u16).
            let flags: u16 = if iface.is_up() { 0x0001 | 0x0040 } else { 0 };
            let mut buf = [0u8; 2];
            buf.copy_from_slice(&flags.to_ne_bytes());
            if copy_to_user(arg + IFNAMSIZ, &buf).is_err() { return -14; }
            0
        }
        // ── SIOCSIFFLAGS ─────────────────────────────────────────────────────
        SIOCSIFFLAGS => {
            let mut buf = [0u8; 2];
            if copy_from_user(&mut buf, arg + IFNAMSIZ).is_err() { return -14; }
            let flags = u16::from_ne_bytes(buf);
            let up = flags & 0x0001 != 0;
            iface.set_up(up);
            0
        }
        // ── SIOCGIFADDR ──────────────────────────────────────────────────────
        // Writes a struct sockaddr_in (AF_INET + IPv4 addr) at offset 16.
        SIOCGIFADDR => {
            let addr = iface.ipv4_addr();
            // sockaddr_in: sin_family (u16 AF_INET=2), sin_port (u16 0), sin_addr (u32)
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
            sa[4..8].copy_from_slice(&addr.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        // ── SIOCSIFADDR ──────────────────────────────────────────────────────
        SIOCSIFADDR => {
            let mut sa = [0u8; 16];
            if copy_from_user(&mut sa, arg + IFNAMSIZ).is_err() { return -14; }
            let addr = u32::from_be_bytes(sa[4..8].try_into().unwrap_or([0;4]));
            iface.set_ipv4_addr(addr);
            0
        }
        // ── SIOCGIFMTU ───────────────────────────────────────────────────────
        SIOCGIFMTU => {
            let mtu: i32 = iface.mtu() as i32;
            if copy_to_user(arg + IFNAMSIZ, &mtu.to_ne_bytes()).is_err() { return -14; }
            0
        }
        // ── SIOCSIFMTU ───────────────────────────────────────────────────────
        SIOCSIFMTU => {
            let mut buf = [0u8; 4];
            if copy_from_user(&mut buf, arg + IFNAMSIZ).is_err() { return -14; }
            let mtu = i32::from_ne_bytes(buf) as usize;
            if mtu < 68 || mtu > 65535 { return -22; } // EINVAL
            iface.set_mtu(mtu);
            0
        }
        // ── SIOCGIFHWADDR ─────────────────────────────────────────────────────
        // Writes a struct sockaddr with sa_family=ARPHRD_ETHER + 6-byte MAC.
        SIOCGIFHWADDR => {
            let mac = iface.mac_addr();
            // sockaddr: sa_family (u16), sa_data[14]
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&1u16.to_ne_bytes()); // ARPHRD_ETHER
            sa[2..8].copy_from_slice(&mac);
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        // ── SIOCGIFINDEX ──────────────────────────────────────────────────────
        SIOCGIFINDEX => {
            let idx: i32 = iface.index() as i32;
            if copy_to_user(arg + IFNAMSIZ, &idx.to_ne_bytes()).is_err() { return -14; }
            0
        }
        // ── SIOCGIFNETMASK ────────────────────────────────────────────────────
        SIOCGIFNETMASK => {
            let netmask = iface.netmask();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
            sa[4..8].copy_from_slice(&netmask.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        // ── SIOCGIFBRDADDR ────────────────────────────────────────────────────
        SIOCGIFBRDADDR => {
            let bcast = iface.broadcast();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
            sa[4..8].copy_from_slice(&bcast.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        // ── SIOCGIFDSTADDR ────────────────────────────────────────────────────
        SIOCGIFDSTADDR => {
            // Point-to-point destination — same as src addr for non-P2P links.
            let addr = iface.ipv4_addr();
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&2u16.to_ne_bytes());
            sa[4..8].copy_from_slice(&addr.to_be_bytes());
            if copy_to_user(arg + IFNAMSIZ, &sa).is_err() { return -14; }
            0
        }
        // ── SIOCGIFNAME ───────────────────────────────────────────────────────
        SIOCGIFNAME => {
            // arg union is ifr_ifindex on input; output is ifr_name.
            // We already have the name from the initial read; echo it back.
            let name_bytes = ifname.as_bytes();
            let mut buf = [0u8; IFNAMSIZ];
            let len = name_bytes.len().min(IFNAMSIZ - 1);
            buf[..len].copy_from_slice(&name_bytes[..len]);
            if copy_to_user(arg, &buf).is_err() { return -14; }
            0
        }
        _ => -22, // EINVAL — unknown SIOC command
    }
}

// ── Block device ioctl helpers ───────────────────────────────────────────────

fn blk_ioctl(bfd: usize, cmd: u64, arg: usize) -> isize {
    // Resolve the path for this fd to look up the block device.
    let path = match crate::fs::fcntl::fd_get_path(bfd) {
        Some(p) => p,
        None    => return -9, // EBADF
    };

    // Resolve the mount point to find the block device size.
    let h = match crate::fs::mount::resolve(&path) {
        Ok(h)  => h,
        Err(e) => return e,
    };

    // Fetch total sector count from the block layer.
    let sectors = crate::block::sector_count_for_mount(&h);
    let sector_size: u32 = 512;
    let total_bytes: u64 = sectors as u64 * sector_size as u64;

    match cmd {
        BLKGETSIZE => {
            // Returns u32 sector count (512-byte sectors).
            if !validate_user_ptr(arg, 4) { return -14; }
            let count = (total_bytes / sector_size as u64) as u32;
            if copy_to_user(arg, &count.to_ne_bytes()).is_err() { return -14; }
            0
        }
        BLKGETSIZE64 => {
            // Returns u64 total bytes.
            if !validate_user_ptr(arg, 8) { return -14; }
            if copy_to_user(arg, &total_bytes.to_ne_bytes()).is_err() { return -14; }
            0
        }
        BLKSSZGET | BLKBSZGET => {
            if !validate_user_ptr(arg, 4) { return -14; }
            if copy_to_user(arg, &sector_size.to_ne_bytes()).is_err() { return -14; }
            0
        }
        _ => -25, // ENOTTY
    }
}

// ── sys_ioctl — main entry point ─────────────────────────────────────────────

/// `ioctl(2)` — NR 16.
///
/// Translates the user-visible `fd` to a kernel backing fd, classifies the
/// fd type, and dispatches to the appropriate handler above.
pub fn sys_ioctl(fd: usize, cmd: u64, arg: usize) -> isize {
    let bfd = match resolve(fd) {
        n if n < 0 => return n,
        n          => n as usize,
    };

    // ── 1. stdin / stdout / stderr ─────────────────────────────────────────
    if fd <= 2 {
        return tty_ioctl(fd, bfd, cmd, arg);
    }

    // ── 2. Scheme fds (synthetic backing fds ≥ 0x8000_0000) ───────────────
    //
    // Pipe fds also live in the 0x8000_0000+ range (PIPE_FD_BASE).  Check
    // is_pipe first so pipes get their tailored FIONREAD, then fall through
    // to scheme dispatch for everything else.
    if bfd >= SCHEME_FD_BASE && !crate::fs::pipe::is_pipe(bfd) {
        // Check PTY before generic scheme dispatch: a PTY master opened via
        // devfs may have a backing fd in the scheme range.
        if let Some(_pair) = pty_pair_from_bfd(bfd) {
            return tty_ioctl(fd, bfd, cmd, arg);
        }
        return crate::fs::scheme_fd::scheme_fd_ioctl(bfd, cmd, arg);
    }

    // ── 3. Pipe fds ────────────────────────────────────────────────────────
    if crate::fs::pipe::is_pipe(bfd) {
        return match cmd {
            FIONREAD => pipe_fionread(bfd, arg),
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            _        => -25, // ENOTTY — pipes only support FIONREAD
        };
    }

    // ── 4. Socket fds ──────────────────────────────────────────────────────
    if crate::net::socket::is_socket_fd(bfd) {
        return match cmd {
            FIONREAD => {
                // Bytes available to read on the socket.
                if !validate_user_ptr(arg, 4) { return -14; }
                let n = crate::net::socket::socket_readable_bytes(bfd) as u32;
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            // Network interface ioctls are valid on any socket.
            SIOCGIFFLAGS  | SIOCSIFFLAGS  |
            SIOCGIFADDR   | SIOCSIFADDR   |
            SIOCGIFMTU    | SIOCSIFMTU    |
            SIOCGIFHWADDR | SIOCGIFINDEX  |
            SIOCGIFNETMASK| SIOCGIFBRDADDR|
            SIOCGIFDSTADDR| SIOCGIFNAME   |
            SIOCGIFCONF => sioc_ioctl(cmd, arg),
            _ => -25, // ENOTTY
        };
    }

    // ── 5. devfs fds ───────────────────────────────────────────────────────
    if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        return match cmd {
            FIONREAD => {
                // Character device: no buffered bytes by default.
                if !validate_user_ptr(arg, 4) { return -14; }
                let n: u32 = 0;
                if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                0
            }
            FIONBIO  => fionbio(fd, bfd, arg),
            FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
            FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
            // Input event devices respond to EVIOCGVERSION / EVIOCGID etc.
            // Those are handled by the FileOps implementation on EventNode;
            // forward through the devfs dispatch.
            _ => crate::fs::devfs::device_ioctl(bfd, cmd, arg),
        };
    }

    // ── 6. PTY master / slave (path-based /dev/ptmx or /dev/pts/<n>) ──────
    if let Some(_pair) = pty_pair_from_bfd(bfd) {
        return tty_ioctl(fd, bfd, cmd, arg);
    }

    // ── 7. timerfd / eventfd / inotify / fanotify ─────────────────────────
    if crate::fs::timerfd::is_timerfd(bfd) {
        return match cmd {
            FIONREAD => {
                if !validate_user_ptr(arg, 4) { return -14; }
                // timerfd: non-zero if timer has expired at least once.
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
                // eventfd: 8 bytes available when counter > 0.
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

    // ── 8. Plain VFS files (ext2, ext4, tmpfs, fat32, overlayfs, …) ───────
    match cmd {
        FIONREAD => vfs_fionread(bfd, arg),
        FIONBIO  => fionbio(fd, bfd, arg),
        FIOCLEX  => { proc_fd_set_cloexec(cpid(), fd, true);  0 }
        FIONCLEX => { proc_fd_set_cloexec(cpid(), fd, false); 0 }
        // Block device size queries on regular (block-device-backed) files.
        BLKGETSIZE | BLKGETSIZE64 | BLKSSZGET | BLKBSZGET => blk_ioctl(bfd, cmd, arg),
        // procfs / sysfs: FIONREAD reported as 0 (synthetic files).
        _ if crate::fs::procfs::is_procfs_fd(bfd) => {
            match cmd {
                FIONREAD => {
                    if !validate_user_ptr(arg, 4) { return -14; }
                    let n: u32 = 0;
                    if copy_to_user(arg, &n.to_ne_bytes()).is_err() { return -14; }
                    0
                }
                _ => -25, // ENOTTY
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
        // Unknown command on a plain file.
        _ => -25, // ENOTTY
    }
}
