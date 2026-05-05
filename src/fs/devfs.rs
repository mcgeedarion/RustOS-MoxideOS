//! /dev virtual filesystem.
//!
//! Provides the minimal set of device nodes that musl and a POSIX shell
//! need on startup.  All I/O is handled without a real file descriptor;
//! devfs is consulted before the ramfs/ext2 path in vfs::open.
//!
//! ## Nodes implemented
//!   /dev/null   — reads return 0, writes are discarded
//!   /dev/zero   — reads return 0x00 bytes, writes discarded
//!   /dev/full   — reads return 0x00, writes return ENOSPC
//!   /dev/random — reads return RDRAND bytes (or LFSR fallback)
//!   /dev/urandom— same as /dev/random
//!   /dev/tty    — proxy to the serial console (stdin/stdout/stderr)
//!   /dev/stdin  — fd 0 alias
//!   /dev/stdout — fd 1 alias
//!   /dev/stderr — fd 2 alias
//!
//! ## Integration with vfs.rs
//!   vfs::open() calls devfs::try_open(path) first.
//!   vfs::read() / write() check get_dev_fd(fdno) before the FD table.
//!   The devfs fd numbers are allocated from a range above the normal FD table
//!   (DEV_FD_BASE = 0x4000_0000) to avoid collisions.

extern crate alloc;
use alloc::string::{String, ToString};
use spin::Mutex;

// ── Device kind ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DevKind {
    Null,
    Zero,
    Full,
    Random,
    Tty,
    FdAlias(usize), // /dev/stdin→0, /dev/stdout→1, /dev/stderr→2
}

// ── Open device slot ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct DevFd {
    kind:  DevKind,
    flags: u32,
    pos:   usize,
}

const DEV_TABLE_SIZE: usize = 64;
static DEV_TABLE: Mutex<[Option<DevFd>; DEV_TABLE_SIZE]> =
    Mutex::new([const { None }; DEV_TABLE_SIZE]);

// ── Path → DevKind mapping ───────────────────────────────────────────────────────────────

fn path_to_kind(path: &str) -> Option<DevKind> {
    match path {
        "/dev/null"                    => Some(DevKind::Null),
        "/dev/zero"                    => Some(DevKind::Zero),
        "/dev/full"                    => Some(DevKind::Full),
        "/dev/random" | "/dev/urandom" => Some(DevKind::Random),
        "/dev/tty"                     => Some(DevKind::Tty),
        "/dev/stdin"                   => Some(DevKind::FdAlias(0)),
        "/dev/stdout"                  => Some(DevKind::FdAlias(1)),
        "/dev/stderr"                  => Some(DevKind::FdAlias(2)),
        _                              => None,
    }
}

// ── Internal fd allocation ───────────────────────────────────────────────────────────────

const DEV_FD_BASE: usize = 0x4000_0000;

fn alloc_dev_fd(kind: DevKind, flags: u32) -> Option<usize> {
    let mut tbl = DEV_TABLE.lock();
    for (i, slot) in tbl.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(DevFd { kind, flags, pos: 0 });
            return Some(DEV_FD_BASE + i);
        }
    }
    None
}

// ── Public API (called from vfs.rs) ───────────────────────────────────────────────────

/// Try to open a /dev path. Returns a synthetic fd number or None.
pub fn try_open(path: &str, flags: u32) -> Option<usize> {
    let kind = path_to_kind(path)?;
    if let DevKind::FdAlias(fd) = kind { return Some(fd); }
    alloc_dev_fd(kind, flags)
}

/// Returns Some(DevKind) if `fdno` is a devfs fd.
pub fn get_dev_fd(fdno: usize) -> Option<DevKind> {
    if fdno < DEV_FD_BASE { return None; }
    let idx = fdno - DEV_FD_BASE;
    if idx >= DEV_TABLE_SIZE { return None; }
    DEV_TABLE.lock()[idx].as_ref().map(|d| d.kind)
}

/// Close a devfs fd.
pub fn close(fdno: usize) {
    if fdno < DEV_FD_BASE { return; }
    let idx = fdno - DEV_FD_BASE;
    if idx < DEV_TABLE_SIZE {
        DEV_TABLE.lock()[idx] = None;
    }
}

/// Read from a devfs fd. Returns bytes read, or negative errno.
pub fn read(fdno: usize, buf: &mut [u8]) -> isize {
    let kind = match get_dev_fd(fdno) { Some(k) => k, None => return -9 };
    match kind {
        DevKind::Null             => 0,
        DevKind::Zero | DevKind::Full => {
            buf.fill(0);
            buf.len() as isize
        }
        DevKind::Random           => {
            fill_random(buf);
            buf.len() as isize
        }
        DevKind::Tty              => {
            let mut n = 0usize;
            for b in buf.iter_mut() {
                match serial_read_byte() {
                    Some(c) => { *b = c; n += 1; }
                    None    => break,
                }
            }
            n as isize
        }
        DevKind::FdAlias(real_fd) => crate::fs::vfs::read(real_fd, buf),
    }
}

/// Write to a devfs fd. Returns bytes written, or negative errno.
pub fn write(fdno: usize, buf: &[u8]) -> isize {
    let kind = match get_dev_fd(fdno) { Some(k) => k, None => return -9 };
    match kind {
        DevKind::Null | DevKind::Zero | DevKind::Random | DevKind::Tty => {
            if kind == DevKind::Tty {
                for &b in buf { serial_write_byte(b); }
            }
            buf.len() as isize
        }
        DevKind::Full             => -28, // ENOSPC
        DevKind::FdAlias(real_fd) => crate::fs::vfs::write(real_fd, buf),
    }
}

// ── Random number generation ───────────────────────────────────────────────────────────────

use core::sync::atomic::{AtomicU64, Ordering};
static LFSR: AtomicU64 = AtomicU64::new(0xDEAD_BEEF_CAFE_1337);

/// Fill `buf` with random bytes.
/// Generates one u64 per 8-byte chunk (8× fewer RDRAND calls than per-byte);
/// leftover tail bytes are filled from the last word.
fn fill_random(buf: &mut [u8]) {
    let mut chunks = buf.chunks_exact_mut(8);
    for chunk in chunks.by_ref() {
        let word = next_random_u64();
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    // Fill remainder (0–7 bytes) from one more word.
    let rem = chunks.into_remainder();
    if !rem.is_empty() {
        let word = next_random_u64().to_le_bytes();
        rem.copy_from_slice(&word[..rem.len()]);
    }
}

#[inline]
fn next_random_u64() -> u64 {
    rdrand().unwrap_or_else(|| {
        let s = LFSR.load(Ordering::Relaxed);
        let s = s ^ (s << 13) ^ (s >> 7) ^ (s << 17);
        LFSR.store(s, Ordering::Relaxed);
        s
    })
}

fn rdrand() -> Option<u64> {
    let mut val: u64 = 0;
    let mut ok: u8;
    for _ in 0..10 {
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {ok}",
                v  = out(reg) val,
                ok = out(reg_byte) ok,
                options(nostack)
            );
        }
        if ok != 0 { return Some(val); }
    }
    None
}

// ── Serial I/O (COM1 = 0x3F8) ───────────────────────────────────────────────────────────────

const COM1: u16 = 0x3F8;

fn serial_write_byte(b: u8) {
    unsafe {
        loop {
            let lsr: u8;
            core::arch::asm!("in al, dx", out("al") lsr, in("dx") COM1 + 5, options(nostack));
            if lsr & 0x20 != 0 { break; }
        }
        core::arch::asm!("out dx, al", in("dx") COM1, in("al") b, options(nostack));
    }
}

fn serial_read_byte() -> Option<u8> {
    unsafe {
        let lsr: u8;
        core::arch::asm!("in al, dx", out("al") lsr, in("dx") COM1 + 5, options(nostack));
        if lsr & 0x01 == 0 { return None; }
        let data: u8;
        core::arch::asm!("in al, dx", out("al") data, in("dx") COM1, options(nostack));
        Some(data)
    }
}
