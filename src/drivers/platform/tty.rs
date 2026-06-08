//! TTY — terminal line discipline.
//!
//! Implements a minimal VT100-compatible line discipline:
//!   - Canonical (cooked) mode: line-buffered with echo, Backspace, Ctrl-C/D
//!   - Raw mode: pass bytes straight through without buffering or echo
//!
//! The TTY sits between the keyboard driver (which calls `tty_input`) and
//! processes that `read(2)` from `/dev/tty0`.  A 4 KiB circular buffer
//! decouples the two sides; `tty_read` blocks (spins) until a full line
//! is available (canonical) or at least one byte is ready (raw).

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

const BUF_CAP: usize = 4096;
const SIGINT: i32 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TtyMode {
    Canonical,
    Raw,
}

struct TtyState {
    buf: Vec<u8>,
    mode: TtyMode,
    /// In canonical mode: number of complete lines (newline-terminated) in buf.
    lines: usize,
    /// Foreground process group for terminal-generated signals.
    ///
    /// A value of 0 means no foreground process group has been explicitly set.
    /// In that case, Ctrl-C falls back to the current process id so early
    /// single-process shells still work before job-control ioctls are used.
    foreground_pgid: usize,
}

impl TtyState {
    const fn new() -> Self {
        TtyState {
            buf: Vec::new(),
            mode: TtyMode::Canonical,
            lines: 0,
            foreground_pgid: 0,
        }
    }
}

static TTY: Mutex<TtyState> = Mutex::new(TtyState::new());

/// Feed a raw byte from the keyboard or serial port into the TTY.
pub fn tty_input(byte: u8) {
    let sigint_pgid = {
        let mut tty = TTY.lock();

        match tty.mode {
            TtyMode::Raw => {
                if tty.buf.len() < BUF_CAP {
                    tty.buf.push(byte);
                }
                None
            },
            TtyMode::Canonical => {
                match byte {
                    b'\r' | b'\n' => {
                        if tty.buf.len() < BUF_CAP {
                            tty.buf.push(b'\n');
                            tty.lines += 1;
                            crate::drivers::gpu::vga::print_char('\n');
                        }
                        None
                    },
                    // Backspace / DEL
                    0x08 | 0x7F => {
                        // Remove last byte up to (not including) a newline.
                        if let Some(&last) = tty.buf.last() {
                            if last != b'\n' {
                                tty.buf.pop();
                                crate::drivers::gpu::vga::print_char('\x08');
                            }
                        }
                        None
                    },
                    // Ctrl-C
                    0x03 => {
                        tty.buf.clear();
                        tty.lines = 0;
                        crate::drivers::gpu::vga::print_char('\n');

                        let pgid = if tty.foreground_pgid != 0 {
                            tty.foreground_pgid
                        } else {
                            crate::proc::scheduler::current_pid()
                        };

                        Some(pgid)
                    },
                    // Ctrl-D (EOF)
                    0x04 => {
                        // Flush any partial line as an immediate EOF token.
                        if tty.buf.len() < BUF_CAP {
                            tty.buf.push(b'\x04');
                            tty.lines += 1;
                        }
                        None
                    },
                    // Printable
                    _ => {
                        if tty.buf.len() < BUF_CAP {
                            tty.buf.push(byte);
                            if byte.is_ascii() {
                                crate::drivers::gpu::vga::print_char(byte as char);
                            }
                        }
                        None
                    },
                }
            },
        }
    };

    if let Some(pgid) = sigint_pgid {
        send_signal_to_pgrp(pgid, SIGINT);
    }
}

fn send_signal_to_pgrp(pgid: usize, sig: i32) {
    let tgids = crate::proc::scheduler::with_procs_ro(|procs| {
        procs
            .iter()
            .filter(|p| p.pgid == pgid && p.pid == p.tgid)
            .map(|p| p.tgid)
            .collect::<Vec<_>>()
    });

    for tgid in tgids {
        crate::proc::signal::send_signal_group(tgid, sig);
    }
}

/// Read up to `buf.len()` bytes from the TTY into `buf`.
///
/// - Canonical mode: blocks until at least one complete line is available, then
///   drains up to the first newline (inclusive).
/// - Raw mode: blocks until at least one byte is available, then drains up to
///   `buf.len()` bytes.
///
/// Returns the number of bytes written into `buf`.
pub fn tty_read(buf: &mut [u8]) -> usize {
    loop {
        {
            let mut tty = TTY.lock();
            match tty.mode {
                TtyMode::Raw => {
                    if !tty.buf.is_empty() {
                        let n = buf.len().min(tty.buf.len());
                        buf[..n].copy_from_slice(&tty.buf[..n]);
                        tty.buf.drain(..n);
                        return n;
                    }
                },
                TtyMode::Canonical => {
                    if tty.lines > 0 {
                        // Find first newline or EOF token.
                        if let Some(nl) = tty.buf.iter().position(|&b| b == b'\n' || b == b'\x04') {
                            let end = nl + 1;
                            let n = buf.len().min(end);
                            buf[..n].copy_from_slice(&tty.buf[..n]);
                            tty.buf.drain(..end);
                            tty.lines -= 1;
                            return n;
                        }
                    }
                },
            }
        }
        core::hint::spin_loop();
    }
}

/// Returns true if data is immediately available (non-blocking poll).
pub fn tty_poll() -> bool {
    let tty = TTY.lock();
    match tty.mode {
        TtyMode::Raw => !tty.buf.is_empty(),
        TtyMode::Canonical => tty.lines > 0,
    }
}

pub fn set_mode(mode: TtyMode) {
    TTY.lock().mode = mode;
}

pub fn get_mode() -> TtyMode {
    TTY.lock().mode
}

pub fn get_foreground_pgid() -> usize {
    let tty = TTY.lock();
    if tty.foreground_pgid != 0 {
        tty.foreground_pgid
    } else {
        crate::proc::scheduler::current_pid()
    }
}

pub fn set_foreground_pgid(pgid: usize) -> isize {
    if pgid == 0 {
        return -22; // EINVAL
    }

    TTY.lock().foreground_pgid = pgid;
    0
}

/// Discard all buffered input and reset the line counter.
pub fn flush() {
    let mut tty = TTY.lock();
    tty.buf.clear();
    tty.lines = 0;
}