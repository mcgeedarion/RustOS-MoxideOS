//! TTY — terminal line discipline.
//!
//! Implements a minimal VT100-compatible line discipline:
//!   - Input: keyboard events → UTF-8 byte stream → line buffer
//!   - Output: byte stream → framebuffer console / serial
//!
//! ## Data flow
//!
//!   [keyboard ISR] → keyboard::read_char()
//!          ↓
//!   tty_keyboard_tick()   (call from main loop or timer tick)
//!          ↓
//!   line buffer  ──→  tty_read() returns completed lines
//!          ↓
//!   [userspace / shell]
//!
//!   [kernel / userspace] → tty_write() → serial + console
//!
//! ## Public API
//!   tty_init()              — called once from kernel_main
//!   tty_keyboard_tick()     — drain keyboard char FIFO into line buffer
//!   tty_read(buf)           — copy a completed line into buf; returns len
//!   tty_write(bytes)        — emit bytes to serial + framebuffer console
//!   tty_line_ready() -> bool — true if a complete line is waiting

use spin::Mutex;

const TTY_BUF_SIZE: usize = 512;

struct LineBuf { data: [u8; TTY_BUF_SIZE], len: usize, ready: bool }
impl LineBuf {
    const fn new() -> Self { Self { data: [0u8; TTY_BUF_SIZE], len: 0, ready: false } }
    fn push_char(&mut self, c: char) {
        match c {
            '\x08' | '\x7F' => { if self.len > 0 { self.len -= 1; tty_echo(b"\x08 \x08"); } }
            '\n' | '\r' => {
                tty_echo(b"\r\n");
                if self.len < TTY_BUF_SIZE { self.data[self.len] = b'\n'; self.len += 1; }
                self.ready = true;
            }
            c if c.is_ascii() => {
                let b = c as u8;
                if self.len < TTY_BUF_SIZE - 1 { self.data[self.len] = b; self.len += 1; tty_echo(&[b]); }
            }
            _ => {}
        }
    }
    fn read_into(&mut self, dst: &mut [u8]) -> usize {
        if !self.ready { return 0; }
        let n = self.len.min(dst.len());
        dst[..n].copy_from_slice(&self.data[..n]);
        let remaining = self.len - n;
        self.data.copy_within(n..n+remaining, 0);
        self.len   = remaining;
        self.ready = self.data[..remaining].contains(&b'\n');
        n
    }
}

struct OutRing { buf: [u8; TTY_BUF_SIZE], head: usize, tail: usize }
impl OutRing {
    const fn new() -> Self { Self { buf: [0u8; TTY_BUF_SIZE], head: 0, tail: 0 } }
    fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let next = (self.head + 1) & (TTY_BUF_SIZE - 1);
            if next != self.tail { self.buf[self.head] = b; self.head = next; }
        }
    }
    fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail { return None; }
        let b = self.buf[self.tail];
        self.tail = (self.tail + 1) & (TTY_BUF_SIZE - 1);
        Some(b)
    }
}

struct TtyState { line: LineBuf, out: OutRing }
static TTY: Mutex<TtyState> = Mutex::new(TtyState { line: LineBuf::new(), out: OutRing::new() });

fn tty_echo(bytes: &[u8]) {
    for &b in bytes { crate::arch::x86_64::serial::serial_write_byte(b); }
}

pub fn tty_init() {}

pub fn tty_keyboard_tick() {
    let mut chars = [0u8; 16]; let mut n = 0usize;
    while n < chars.len() {
        match crate::drivers::input::keyboard::read_char() {
            Some(c) if c.is_ascii() => { chars[n] = c as u8; n += 1; }
            Some(_) => {} None => break,
        }
    }
    if n == 0 { return; }
    let mut tty = TTY.lock();
    for &b in &chars[..n] { tty.line.push_char(b as char); }
}

pub fn tty_line_ready() -> bool { TTY.lock().line.ready }
pub fn tty_read(buf: &mut [u8]) -> usize { TTY.lock().line.read_into(buf) }
pub fn tty_write(bytes: &[u8]) {
    for &b in bytes { crate::arch::x86_64::serial::serial_write_byte(b); }
    TTY.lock().out.push(bytes);
}
pub fn tty_out_pop() -> Option<u8> { TTY.lock().out.pop() }
