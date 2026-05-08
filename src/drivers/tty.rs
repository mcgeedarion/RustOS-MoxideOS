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

// ── Configuration ─────────────────────────────────────────────────────────────

/// Size of the raw input ring and the line buffer.
const TTY_BUF_SIZE: usize = 512;

// ── Line buffer ───────────────────────────────────────────────────────────────

struct LineBuf {
    data:   [u8; TTY_BUF_SIZE],
    len:    usize,
    /// True once a '\n' has been pushed; tty_read() returns up to that point.
    ready:  bool,
}

impl LineBuf {
    const fn new() -> Self {
        Self { data: [0u8; TTY_BUF_SIZE], len: 0, ready: false }
    }

    fn push_char(&mut self, c: char) {
        match c {
            '\x08' | '\x7F' => {
                // Backspace / DEL — erase last character.
                if self.len > 0 {
                    self.len -= 1;
                    // Echo backspace: move back, write space, move back.
                    tty_echo(b"\x08 \x08");
                }
            }
            '\n' | '\r' => {
                tty_echo(b"\r\n");
                if self.len < TTY_BUF_SIZE { self.data[self.len] = b'\n'; self.len += 1; }
                self.ready = true;
            }
            c if c.is_ascii() => {
                let b = c as u8;
                if self.len < TTY_BUF_SIZE - 1 {
                    self.data[self.len] = b;
                    self.len += 1;
                    tty_echo(&[b]);
                }
            }
            _ => {} // Non-ASCII: ignore for now.
        }
    }

    /// Copy pending data into `dst`.  Returns bytes copied.
    /// If `ready`, copies the full line and resets.
    fn read_into(&mut self, dst: &mut [u8]) -> usize {
        if !self.ready { return 0; }
        let n = self.len.min(dst.len());
        dst[..n].copy_from_slice(&self.data[..n]);
        // Shift remaining bytes (partial line after \n).
        let remaining = self.len - n;
        self.data.copy_within(n..n+remaining, 0);
        self.len    = remaining;
        self.ready  = self.data[..remaining].contains(&b'\n');
        n
    }
}

// ── Output ring ───────────────────────────────────────────────────────────────

/// 512-byte output ring for bytes pending to be sent to console/serial.
struct OutRing {
    buf:  [u8; TTY_BUF_SIZE],
    head: usize,
    tail: usize,
}

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

// ── Global state ──────────────────────────────────────────────────────────────

struct TtyState {
    line: LineBuf,
    out:  OutRing,
}

static TTY: Mutex<TtyState> = Mutex::new(TtyState {
    line: LineBuf::new(),
    out:  OutRing::new(),
});

// ── Echo helper (called with TTY lock held from push_char) ────────────────────

/// Write bytes directly to serial (no lock needed — serial is its own lock).
fn tty_echo(bytes: &[u8]) {
    for &b in bytes {
        crate::arch::x86_64::serial::serial_write_byte(b);
    }
    // TODO: echo to framebuffer console once console::putchar() is available.
}

// ── Public API ────────────────────────────────────────────────────────────────

/// One-time init.  Currently a no-op; reserved for future UART setup.
pub fn tty_init() {
    crate::arch::x86_64::serial::serial_println!("tty: init");
}

/// Drain the keyboard char FIFO and push characters into the line buffer.
/// Call from main loop or a periodic 10ms tick.
pub fn tty_keyboard_tick() {
    // Pull chars without holding the TTY lock while calling keyboard (avoids
    // lock-order inversion if keyboard ISR also tries to acquire TTY).
    let mut chars = [0u8; 16];
    let mut n = 0usize;
    while n < chars.len() {
        match crate::drivers::keyboard::read_char() {
            Some(c) if c.is_ascii() => { chars[n] = c as u8; n += 1; }
            Some(_) => {}
            None    => break,
        }
    }
    if n == 0 { return; }
    let mut tty = TTY.lock();
    for &b in &chars[..n] {
        tty.line.push_char(b as char);
    }
}

/// Returns true if a complete line (ending with \n) is ready to be read.
pub fn tty_line_ready() -> bool {
    TTY.lock().line.ready
}

/// Copy the next complete line into `buf`.  Returns number of bytes copied,
/// or 0 if no complete line is available.
pub fn tty_read(buf: &mut [u8]) -> usize {
    TTY.lock().line.read_into(buf)
}

/// Write bytes to the TTY output path (serial + future console).
/// This is the kernel-side equivalent of write(1, ...).
pub fn tty_write(bytes: &[u8]) {
    // Fast path: directly to serial.
    for &b in bytes {
        crate::arch::x86_64::serial::serial_write_byte(b);
    }
    // Also queue in output ring for future framebuffer consumer.
    TTY.lock().out.push(bytes);
}

/// Pop one byte from the output ring (for a framebuffer console flush loop).
pub fn tty_out_pop() -> Option<u8> {
    TTY.lock().out.pop()
}
