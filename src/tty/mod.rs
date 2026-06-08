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

pub mod ldisc;
pub mod pts_fs;
pub mod pty;
pub mod serial;
pub mod termios;

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use pty::PtyPair;

/// Maximum simultaneous PTY pairs (matches Linux default pts_max).
pub const PTY_MAX: u32 = 4096;

static NEXT_PTY: AtomicU32 = AtomicU32::new(0);

struct PtyRegistry {
    pairs: BTreeMap<u32, Arc<PtyPair>>,
}

impl PtyRegistry {
    fn new() -> Self {
        PtyRegistry {
            pairs: BTreeMap::new(),
        }
    }
}

static REGISTRY: Mutex<Option<PtyRegistry>> = Mutex::new(None);

pub fn init() {
    *REGISTRY.lock() = Some(PtyRegistry::new());
    pts_fs::init();
}

/// Allocate a new PTY pair. Returns `(index, Arc<PtyPair>)`.
pub fn alloc_pty() -> Result<(u32, Arc<PtyPair>), isize> {
    let idx = NEXT_PTY.fetch_add(1, Ordering::SeqCst);

    if idx >= PTY_MAX {
        return Err(-28);
    }

    let pair = Arc::new(PtyPair::new(idx));

    let mut reg = REGISTRY.lock();
    reg.as_mut()
        .ok_or(-1isize)?
        .pairs
        .insert(idx, pair.clone());

    pts_fs::register_slave(idx);
    Ok((idx, pair))
}

/// Look up an existing PTY pair by slave index for `/dev/pts/<n>`.
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

pub fn keyboard_tick() {
    let pair = match lookup_pty(0) {
        Some(p) => p,
        None => return,
    };

    while let Some(c) = crate::drivers::keyboard::read_char() {
        if c.is_ascii() {
            pair.master_write(&[c as u8]);
        }
    }
}

#[derive(Clone, Copy)]
enum TtySide {
    Master,
    Slave,
}

struct TtyHandle {
    pair: Arc<PtyPair>,
    side: TtySide,
}

static TTY_HANDLES: Mutex<Vec<Option<TtyHandle>>> = Mutex::new(Vec::new());

fn alloc_handle(handle: TtyHandle) -> scheme_api::SchemeFileId {
    let mut handles = TTY_HANDLES.lock();

    for (idx, slot) in handles.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(handle);
            return scheme_api::SchemeFileId((idx + 1) as u64);
        }
    }

    handles.push(Some(handle));
    scheme_api::SchemeFileId(handles.len() as u64)
}

fn fid_index(fid: scheme_api::SchemeFileId) -> Result<usize, scheme_api::SchemeError> {
    fid.0
        .checked_sub(1)
        .map(|v| v as usize)
        .ok_or(scheme_api::SchemeError::InvalidArg)
}

fn errno_to_scheme_error(errno: isize) -> scheme_api::SchemeError {
    match errno {
        -2 => scheme_api::SchemeError::NotFound,
        -11 => scheme_api::SchemeError::WouldBlock,
        -13 => scheme_api::SchemeError::PermissionDenied,
        -22 => scheme_api::SchemeError::InvalidArg,
        -28 => scheme_api::SchemeError::Other,
        _ => scheme_api::SchemeError::Io,
    }
}

/// TTY scheme adapter.
///
/// Supported paths:
/// - `tty:ptmx` — allocate/open a PTY master.
/// - `tty:pts/<n>` or `tty:<n>` — open an existing PTY slave.
/// - `tty:console` — open PTY 0 slave if it exists.
pub struct TtyScheme;

impl TtyScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for TtyScheme {
    fn open(
        &self,
        path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        let path = path.trim_matches('/');

        if path == "ptmx" {
            let (_idx, pair) = pty::posix_openpt().map_err(errno_to_scheme_error)?;

            return Ok(alloc_handle(TtyHandle {
                pair,
                side: TtySide::Master,
            }));
        }

        let idx = if path == "console" || path == "tty0" {
            0
        } else if let Some(rest) = path.strip_prefix("pts/") {
            rest.parse::<u32>()
                .map_err(|_| scheme_api::SchemeError::InvalidArg)?
        } else {
            path.parse::<u32>()
                .map_err(|_| scheme_api::SchemeError::InvalidArg)?
        };

        let pair = lookup_pty(idx).ok_or(scheme_api::SchemeError::NotFound)?;

        if pair.is_locked() {
            return Err(scheme_api::SchemeError::PermissionDenied);
        }

        Ok(alloc_handle(TtyHandle {
            pair,
            side: TtySide::Slave,
        }))
    }

    fn read(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &mut [u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;

        let (pair, side) = {
            let handles = TTY_HANDLES.lock();

            let Some(Some(handle)) = handles.get(idx) else {
                return Err(scheme_api::SchemeError::InvalidArg);
            };

            (handle.pair.clone(), handle.side)
        };

        let n = match side {
            TtySide::Master => pair.master_read(buf),
            TtySide::Slave => pair.slave_read(buf),
        };

        if n == 0 {
            Err(scheme_api::SchemeError::WouldBlock)
        } else {
            Ok(n)
        }
    }

    fn write(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &[u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;

        let (pair, side) = {
            let handles = TTY_HANDLES.lock();

            let Some(Some(handle)) = handles.get(idx) else {
                return Err(scheme_api::SchemeError::InvalidArg);
            };

            (handle.pair.clone(), handle.side)
        };

        let n = match side {
            TtySide::Master => pair.master_write(buf),
            TtySide::Slave => pair.slave_write(buf),
        };

        Ok(n)
    }

    fn ioctl(
        &self,
        fid: scheme_api::SchemeFileId,
        cmd: u64,
        arg: usize,
    ) -> Result<usize, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;

        let pair = {
            let handles = TTY_HANDLES.lock();

            let Some(Some(handle)) = handles.get(idx) else {
                return Err(scheme_api::SchemeError::InvalidArg);
            };

            handle.pair.clone()
        };

        pty::pty_ioctl(&pair, cmd as usize, arg)
            .map(|v| v as usize)
            .map_err(errno_to_scheme_error)
    }

    fn close(&self, fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        let idx = fid_index(fid)?;
        let mut handles = TTY_HANDLES.lock();

        if let Some(slot) = handles.get_mut(idx) {
            *slot = None;
            Ok(())
        } else {
            Err(scheme_api::SchemeError::InvalidArg)
        }
    }
}