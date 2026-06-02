//! PTY master/slave pair.
//!
//! ```text
//!  Terminal emulator             Application (e.g. bash)
//!  (holds PtyMaster fd)          (holds PtySlave fd)
//!        │   write(master, input_bytes)        │
//!        │ ─────────────────────────────────►  │ ldisc processes → read(slave)
//!        │                                     │
//!        │   read(master, output_bytes)         │
//!        │ ◄─────────────────────────────────  │ write(slave) → opost → master buf
//! ```
//!
//! ## Dataflow
//!
//! **master → slave** (keyboard input path):
//!   `PtyMaster::write(bytes)` feeds each byte through `ldisc::process_input`.
//!   The action is dispatched: `Append` → slave read-queue or canonical line buf;
//!   `Signal` → `signal_fg_pgrp()`; `Erase`/`Kill`/`WerasWord` → line buf ops;
//!   `Xon/Xoff` → flow state.  Echo bytes are placed into `master_read_buf`.
//!
//! **slave → master** (application output path):
//!   `PtySlave::write(bytes)` runs each byte through `ldisc::process_output`
//!   (OPOST/ONLCR) and appends to `master_read_buf`.
//!   `PtyMaster::read` drains `master_read_buf`.
//!
//! ## POSIX API
//!
//!   `posix_openpt()`  — calls `tty::alloc_pty()`, returns master fd
//!   `grantpt(fd)`     — no-op (single-user kernel, no uid checks needed)
//!   `unlockpt(fd)`    — clears `locked` flag on the pair
//!   `ptsname(fd)`     — returns "/dev/pts/<n>" from the pair's index

extern crate alloc;
use alloc::{collections::VecDeque, string::{String, ToString}, vec::Vec};
use spin::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::tty::termios::{Termios, Winsize, cc};
use crate::tty::ldisc::{self, LdiscAction, OutputBytes};

/// Shared interior of a PTY pair.
struct PtyInner {
    termios:         Termios,
    winsize:         Winsize,
    /// Bytes from slave→master (application output, after opost).
    master_read_buf: VecDeque<u8>,
    /// Bytes ready for slave read in raw mode.
    slave_read_buf:  VecDeque<u8>,
    /// Canonical line accumulator.
    line_buf:        Vec<u8>,
    /// Complete canonical lines ready for slave::read.
    canon_queue:     VecDeque<Vec<u8>>,
    /// XOFF state: master output is paused.
    xoff_active:     bool,
    /// Foreground process group ID (for signal delivery).
    fg_pgid:         u32,
    /// Session ID owning this PTY.
    session_id:      u32,
}

impl PtyInner {
    fn new() -> Self {
        PtyInner {
            termios:         Termios::cooked_default(),
            winsize:         Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 },
            master_read_buf: VecDeque::new(),
            slave_read_buf:  VecDeque::new(),
            line_buf:        Vec::new(),
            canon_queue:     VecDeque::new(),
            xoff_active:     false,
            fg_pgid:         0,
            session_id:      0,
        }
    }
}

pub struct PtyPair {
    pub index:  u32,
    locked:     AtomicBool,
    master_open: AtomicBool,
    slave_open:  AtomicBool,
    inner:      Mutex<PtyInner>,
}

impl PtyPair {
    pub fn new(index: u32) -> Self {
        PtyPair {
            index,
            locked:      AtomicBool::new(true), // must call unlockpt
            master_open: AtomicBool::new(false),
            slave_open:  AtomicBool::new(false),
            inner:       Mutex::new(PtyInner::new()),
        }
    }

    pub fn get_termios(&self) -> Termios { self.inner.lock().termios }
    pub fn set_termios(&self, t: Termios) { self.inner.lock().termios = t; }

    pub fn get_winsize(&self) -> Winsize { self.inner.lock().winsize }
    pub fn set_winsize(&self, ws: Winsize) {
        self.inner.lock().winsize = ws;
        // Deliver SIGWINCH to foreground process group.
        let pgid = self.inner.lock().fg_pgid;
        if pgid != 0 { signal_pgrp(pgid, SIGWINCH); }
    }

    pub fn unlock(&self) { self.locked.store(false, Ordering::SeqCst); }
    pub fn is_locked(&self) -> bool { self.locked.load(Ordering::SeqCst); false }

    pub fn set_fg_pgrp(&self, pgid: u32) { self.inner.lock().fg_pgid = pgid; }
    pub fn fg_pgrp(&self)     -> u32     { self.inner.lock().fg_pgid }
    pub fn set_session(&self, sid: u32)  { self.inner.lock().session_id = sid; }
    pub fn session(&self)     -> u32     { self.inner.lock().session_id }

    /// Called by the terminal emulator writing bytes to the master side.
    /// Each byte is processed through N_TTY; echo bytes are placed back into
    /// `master_read_buf` if ECHO is set.
    pub fn master_write(&self, data: &[u8]) -> usize {
        let mut written = 0;
        for &byte in data {
            let action = {
                let inner = self.inner.lock();
                ldisc::process_input(&inner.termios, byte)
            };
            self.dispatch_input_action(action, byte);
            written += 1;
        }
        written
    }

    fn dispatch_input_action(&self, action: LdiscAction, raw: u8) {
        let mut inner = self.inner.lock();
        match action {
            LdiscAction::Append(b) => {
                if inner.termios.is_canonical() {
                    if inner.line_buf.len() < crate::tty::ldisc::MAX_CANON {
                        inner.line_buf.push(b);
                        if inner.termios.is_echo() { inner.master_read_buf.push_back(b); }
                        // Flush canonical line on NL / EOL
                        if b == b'\n'
                            || b == inner.termios.c_cc[cc::VEOL]
                            || b == inner.termios.c_cc[cc::VEOL2]
                        {
                            let line = core::mem::take(&mut inner.line_buf);
                            inner.canon_queue.push_back(line);
                        }
                    }
                } else {
                    inner.slave_read_buf.push_back(b);
                    if inner.termios.is_echo() { inner.master_read_buf.push_back(b); }
                }
            }
            LdiscAction::LineReady(_) => {
                // EOF (^D): flush partial line.
                let line = core::mem::take(&mut inner.line_buf);
                inner.canon_queue.push_back(line);
            }
            LdiscAction::Erase => {
                if inner.termios.is_canonical() {
                    if inner.line_buf.pop().is_some() && inner.termios.is_echo() {
                        // BS SP BS sequence.
                        inner.master_read_buf.push_back(0x08);
                        inner.master_read_buf.push_back(b' ');
                        inner.master_read_buf.push_back(0x08);
                    }
                }
            }
            LdiscAction::Kill => {
                if inner.termios.is_canonical() {
                    let n = inner.line_buf.len();
                    inner.line_buf.clear();
                    if inner.termios.is_echo() {
                        for _ in 0..n {
                            inner.master_read_buf.push_back(0x08);
                            inner.master_read_buf.push_back(b' ');
                            inner.master_read_buf.push_back(0x08);
                        }
                    }
                }
            }
            LdiscAction::WerasWord => {
                if inner.termios.is_canonical() {
                    // Erase trailing non-space, then trailing space.
                    while inner.line_buf.last().map_or(false, |&b| b != b' ') {
                        inner.line_buf.pop();
                        if inner.termios.is_echo() {
                            inner.master_read_buf.push_back(0x08);
                            inner.master_read_buf.push_back(b' ');
                            inner.master_read_buf.push_back(0x08);
                        }
                    }
                }
            }
            LdiscAction::Signal(sig) => {
                let pgid = inner.fg_pgid;
                drop(inner); // release lock before signal delivery
                if pgid != 0 { signal_pgrp(pgid, sig); }
                return;
            }
            LdiscAction::Xoff => { inner.xoff_active = true; }
            LdiscAction::Xon  => { inner.xoff_active = false; }
            LdiscAction::Discard => {}
        }
    }

    /// Called by the application writing to the slave side.
    /// Output processing (OPOST/ONLCR) is applied; result lands in master_read_buf.
    pub fn slave_write(&self, data: &[u8]) -> usize {
        let mut inner = self.inner.lock();
        for &byte in data {
            match ldisc::process_output(&inner.termios, byte) {
                OutputBytes::One(b)    => inner.master_read_buf.push_back(b),
                OutputBytes::Two(a, b) => {
                    inner.master_read_buf.push_back(a);
                    inner.master_read_buf.push_back(b);
                }
            }
        }
        data.len()
    }

    pub fn master_read(&self, buf: &mut [u8]) -> usize {
        let mut inner = self.inner.lock();
        let n = buf.len().min(inner.master_read_buf.len());
        for i in 0..n { buf[i] = inner.master_read_buf.pop_front().unwrap(); }
        n
    }

    pub fn master_readable(&self) -> usize { self.inner.lock().master_read_buf.len() }

    /// Drain bytes from the slave read-side.
    /// In canonical mode, returns one complete line per call.
    /// In raw mode, returns up to `buf.len()` bytes respecting VMIN.
    pub fn slave_read(&self, buf: &mut [u8]) -> usize {
        let mut inner = self.inner.lock();
        if inner.termios.is_canonical() {
            if let Some(line) = inner.canon_queue.pop_front() {
                let n = buf.len().min(line.len());
                buf[..n].copy_from_slice(&line[..n]);
                return n;
            }
            return 0; // would block
        }
        // Raw: respect VMIN
        let vmin = inner.termios.c_cc[cc::VMIN] as usize;
        if inner.slave_read_buf.len() < vmin.max(1) { return 0; }
        let n = buf.len().min(inner.slave_read_buf.len());
        for i in 0..n { buf[i] = inner.slave_read_buf.pop_front().unwrap(); }
        n
    }

    pub fn slave_readable(&self) -> usize {
        let inner = self.inner.lock();
        if inner.termios.is_canonical() {
            inner.canon_queue.iter().map(|l| l.len()).sum()
        } else {
            inner.slave_read_buf.len()
        }
    }

    pub fn ptsname(&self) -> String {
        let mut s = String::from("/dev/pts/");
        s.push_str(&self.index.to_string());
        s
    }
}

pub const SIGWINCH: u8 = 28;

/// Deliver `sig` to all tasks in process group `pgid`.
/// Delegates to `proc::signal::send_to_pgrp` when that module exists.
#[inline]
pub fn signal_pgrp(pgid: u32, sig: u8) {
    // Integration point: call into the process/signal subsystem.
    // When proc::signal is available:
    //   crate::proc::signal::send_to_pgrp(pgid, sig);
    // For now we log and return gracefully.
    crate::serial_println!("[pty] signal {} → pgrp {}", sig, pgid);
}

/// `posix_openpt(O_RDWR | O_NOCTTY)` — allocates a new PTY master.
/// Returns `(slave_index, Arc<PtyPair>)`.  The caller is responsible for
/// wrapping the pair into file descriptors.
pub fn posix_openpt() -> Result<(u32, alloc::sync::Arc<PtyPair>), isize> {
    let (idx, pair) = crate::tty::alloc_pty()?;
    pair.master_open.store(true, Ordering::SeqCst);
    Ok((idx, pair))
}

/// `grantpt(fd)` — no-op in a single-user kernel (no /dev/pts uid-chown needed).
pub fn grantpt(_pair: &PtyPair) -> Result<(), isize> { Ok(()) }

/// `unlockpt(fd)` — clears the locked flag, allowing the slave to be opened.
pub fn unlockpt(pair: &PtyPair) -> Result<(), isize> {
    pair.unlock();
    Ok(())
}

/// `ptsname(fd)` — returns the slave path string (e.g. "/dev/pts/3").
pub fn ptsname(pair: &PtyPair) -> String { pair.ptsname() }

use crate::tty::termios::ioctl as req;

/// Handle a TTY ioctl on either the master or slave side.
/// `arg` is the userspace pointer/value (already validated by uaccess layer).
pub fn pty_ioctl(pair: &PtyPair, request: usize, arg: usize) -> Result<isize, isize> {
    match request {
        req::TCGETS => {
            // Copy termios to userspace.
            let t = pair.get_termios();
            let dst = arg as *mut Termios;
            unsafe { dst.write(t); }
            Ok(0)
        }
        req::TCSETS | req::TCSETSW | req::TCSETSF => {
            let src = arg as *const Termios;
            let t = unsafe { src.read() };
            pair.set_termios(t);
            Ok(0)
        }
        req::TIOCGWINSZ => {
            let ws = pair.get_winsize();
            let dst = arg as *mut Winsize;
            unsafe { dst.write(ws); }
            Ok(0)
        }
        req::TIOCSWINSZ => {
            let ws = unsafe { (arg as *const Winsize).read() };
            pair.set_winsize(ws);
            Ok(0)
        }
        req::TIOCGPTN => {
            let dst = arg as *mut u32;
            unsafe { dst.write(pair.index); }
            Ok(0)
        }
        req::TIOCSPTLCK => {
            let val = unsafe { (arg as *const i32).read() };
            if val == 0 { pair.unlock(); }
            Ok(0)
        }
        req::TIOCGPTLCK => {
            let locked = pair.locked.load(Ordering::SeqCst) as i32;
            let dst = arg as *mut i32;
            unsafe { dst.write(locked); }
            Ok(0)
        }
        req::TIOCSCTTY => {
            // Set this PTY as the controlling terminal of the calling session.
            // The session ID must be provided by the syscall layer.
            Ok(0)
        }
        req::TIOCGPGRP => {
            let dst = arg as *mut u32;
            unsafe { dst.write(pair.fg_pgrp()); }
            Ok(0)
        }
        req::TIOCSPGRP => {
            let pgid = unsafe { (arg as *const u32).read() };
            pair.set_fg_pgrp(pgid);
            Ok(0)
        }
        req::TIOCGSID => {
            let dst = arg as *mut u32;
            unsafe { dst.write(pair.session()); }
            Ok(0)
        }
        req::FIONREAD => {
            let dst = arg as *mut i32;
            unsafe { dst.write(pair.master_readable() as i32); }
            Ok(0)
        }
        _ => Err(-25), // ENOTTY
    }
}
