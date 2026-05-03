//! Thin user-space I/O syscalls: read, write, open, close.
//!
//! These wrap the vfs:: kernel-internal functions with:
//!   - user-pointer bounds checking (reject null / kernel addrs)
//!   - a kernel bounce buffer for read/write  (avoids passing raw user VAs
//!     into the VFS layer, which expects valid kernel slices)
//!   - path string copying via proc::exec::read_cstr_safe
//!
//! NR  0  read (fd, buf_va, count)   → bytes read / -errno
//! NR  1  write(fd, buf_va, count)   → bytes written / -errno
//! NR  2  open (path_va, flags, mode)→ fd / -errno
//! NR  3  close(fd)                  → 0 / -errno

extern crate alloc;
use alloc::vec;

use crate::fs::vfs;
use crate::proc::exec::read_cstr_safe;

/// Maximum single read/write transfer (64 KiB bounce buffer cap).
const MAX_IO: usize = 65536;

// ── user-pointer guard ─────────────────────────────────────────────────────────────

/// Returns true if [va, va+len) is a valid user-space range.
#[inline]
fn user_ptr_ok(va: usize, len: usize) -> bool {
    va >= 0x1000
        && va.saturating_add(len) <= 0x0000_8000_0000_0000
}

// ── NR 0: sys_read ─────────────────────────────────────────────────────────────

/// sys_read(fd, buf_va, count) → bytes_read / -errno
///
/// Reads into a kernel bounce buffer, then copies to user VA.
/// This keeps raw user pointers out of the VFS layer.
pub fn sys_read(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !user_ptr_ok(buf_va, count) { return -14; } // EFAULT
    let n = count.min(MAX_IO);
    let mut kbuf = vec![0u8; n];
    let got = vfs::read(fd, &mut kbuf);
    if got <= 0 { return got; }
    let got = got as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(kbuf.as_ptr(), buf_va as *mut u8, got);
    }
    got as isize
}

// ── NR 1: sys_write ────────────────────────────────────────────────────────────

/// sys_write(fd, buf_va, count) → bytes_written / -errno
///
/// Copies from user VA into a kernel bounce buffer, then writes.
pub fn sys_write(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !user_ptr_ok(buf_va, count) { return -14; } // EFAULT
    let n = count.min(MAX_IO);
    let mut kbuf = vec![0u8; n];
    unsafe {
        core::ptr::copy_nonoverlapping(buf_va as *const u8, kbuf.as_mut_ptr(), n);
    }
    vfs::write(fd, &kbuf[..n])
}

// ── NR 2: sys_open ────────────────────────────────────────────────────────────

/// sys_open(path_va, flags, _mode) → fd / -errno
pub fn sys_open(path_va: usize, flags: u32, _mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) {
        Some(p) => p,
        None    => return -14, // EFAULT
    };
    match vfs::open(&path, flags) {
        Ok(fd)  => fd as isize,
        Err(e)  => e as isize,
    }
}

// ── NR 3: sys_close ───────────────────────────────────────────────────────────

/// sys_close(fd) → 0 / -errno
pub fn sys_close(fd: usize) -> isize {
    vfs::close(fd)
}
