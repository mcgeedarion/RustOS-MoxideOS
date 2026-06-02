//! TTY / PTY subsystem.
//!
//! ## Module layout
//!
//! ```
//! tty/
//!   mod.rs      — TtyFile trait, Tty registry, /dev/tty open
//!   termios.rs  — struct termios, c_iflag/c_oflag/c_cflag/c_lflag constants
//!   ldisc.rs    — N_TTY line discipline (canonical + raw mode)
//!   pty.rs      — PtyMaster / PtySlave pair, posix_openpt / grantpt / unlockpt
//!   pts_fs.rs   — /dev/pts virtual filesystem (devpts)
//!   serial.rs   — COM1 serial line discipline (used by stdin/stdout before PTY init)
//! ```
//!
//! ## Syscall surface implemented
//!
//!   open("/dev/ptmx")        → posix_openpt() → returns master fd
//!   ioctl(fd, TIOCGPTN)      → slave index (ptsname)
//!   ioctl(fd, TIOCSPTLCK, 0) → unlockpt
//!   open("/dev/pts/<n>")     → open slave side
//!   ioctl(fd, TCGETS)        → copy termios
//!   ioctl(fd, TCSETS/TCSETSW/TCSETSF) → set termios
//!   ioctl(fd, TIOCGWINSZ)    → winsize
//!   ioctl(fd, TIOCSWINSZ)    → set winsize + SIGWINCH
//!   ioctl(fd, TIOCSWINSZ)    → set window size + deliver SIGWINCH
//!   read(master)  → bytes written by slave (application output)
//!   write(master) → bytes injected into slave's read buffer (terminal input)
//!   read(slave)   → canonical/raw cooked bytes for the application
//!   write(slave)  → bytes echoed/processed and available on master

pub mod termios;
pub mod ldisc;
pub mod pty;
pub mod pts_fs;
pub mod serial;

extern crate alloc;
use alloc::{collections::BTreeMap, sync::Arc};
use spin::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

use pty::PtyPair;

/// Maximum simultaneous PTY pairs (matches Linux default pts_max).
pub const PTY_MAX: u32 = 4096;

static NEXT_PTY: AtomicU32 = AtomicU32::new(0);

struct PtyRegistry {
    pairs: BTreeMap<u32, Arc<PtyPair>>,
}

impl PtyRegistry {
    fn new() -> Self { PtyRegistry { pairs: BTreeMap::new() } }
}

static REGISTRY: Mutex<Option<PtyRegistry>> = Mutex::new(None);

pub fn init() {
    *REGISTRY.lock() = Some(PtyRegistry::new());
    pts_fs::init();
}

/// Allocate a new PTY pair.  Returns `(index, Arc<PtyPair>)`.
/// Called from the `/dev/ptmx` open handler (posix_openpt).
pub fn alloc_pty() -> Result<(u32, Arc<PtyPair>), isize> {
    let idx = NEXT_PTY.fetch_add(1, Ordering::SeqCst);
    if idx >= PTY_MAX { return Err(-28); } // ENOSPC
    let pair = Arc::new(PtyPair::new(idx));
    let mut reg = REGISTRY.lock();
    reg.as_mut().ok_or(-1isize)?.pairs.insert(idx, pair.clone());
    pts_fs::register_slave(idx);
    Ok((idx, pair))
}

/// Look up an existing PTY pair by slave index (for /dev/pts/<n> open).
pub fn lookup_pty(idx: u32) -> Option<Arc<PtyPair>> {
    REGISTRY.lock().as_ref()?.pairs.get(&idx).cloned()
}

/// Deallocate a PTY pair when both sides are closed.
pub fn free_pty(idx: u32) {
    let mut reg = REGISTRY.lock();
    if let Some(r) = reg.as_mut() {
        r.pairs.remove(&idx);
        pts_fs::unregister_slave(idx);
    }
}

// Drivers that want to emit bytes to a physical console implement this trait
// instead of calling arch serial functions directly.  This keeps src/tty/
// free of arch ifdefs everywhere output is needed.

pub trait ConsoleOutput: Send + Sync {
    fn write_bytes(&self, bytes: &[u8]);
}

pub struct SerialConsole;

impl ConsoleOutput for SerialConsole {
    fn write_bytes(&self, bytes: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        for &b in bytes {
            crate::arch::x86_64::serial::serial_write_byte(b);
        }
        #[cfg(target_arch = "riscv64")]
        for &b in bytes {
            crate::arch::riscv64::uart::uart_write_byte(b);
        }
    }
}

// Call this from the keyboard ISR or a periodic timer tick.
// Drains `keyboard::read_char()` and injects ASCII bytes into the
// PTY-0 master (the system console).  If PTY-0 hasn't been allocated
// yet (early boot), chars are silently dropped — same behaviour as the
// old drivers/tty.rs tty_keyboard_tick().

pub fn keyboard_tick() {
    let pair = match lookup_pty(0) {
        Some(p) => p,
        None    => return,
    };
    while let Some(c) = crate::drivers::keyboard::read_char() {
        if c.is_ascii() {
            pair.master_write(&[c as u8]);
        }
    }
}
