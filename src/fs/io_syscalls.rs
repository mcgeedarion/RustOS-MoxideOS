//! Core file I/O syscalls: read, write, open, close, pread64, writev, dup2.
//!
//! ## Dispatch order for sys_open
//!   1. /dev/…       → devfs::try_open
//!   2. /proc/…      → procfs::procfs_open   (0x6000_0000 range)
//!   3. /sys/…       → sysfs::sysfs_open     (0x7000_0000 range)
//!   4. everything   → vfs::open (ext2 / ramfs / …)
//!
//! ## Dispatch order for sys_read
//!   stdin(0)        → tty
//!   devfs fd        → devfs::read
//!   procfs fd       → procfs::procfs_read
//!   sysfs fd        → sysfs::sysfs_read
//!   inotify fd      → inotify::inotify_read
//!   fanotify fd     → fanotify::fanotify_read
//!   default         → vfs::read
//!
//! ## Dispatch order for sys_write
//!   stdout/stderr   → tty
//!   devfs fd        → devfs::write
//!   fanotify fd     → fanotify::fanotify_write  (permission responses)
//!   default         → vfs::write
//!
//! ## Dispatch order for sys_close
//!   devfs / procfs / sysfs / inotify / fanotify → respective close fn
//!   default → vfs::close

extern crate alloc;
use alloc::vec::Vec;
use crate::fs::vfs;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ─── Seek-offset table for procfs / sysfs synthetic fds ─────────────────────

use spin::Mutex;
static SYNTH_OFFSET: Mutex<alloc::collections::BTreeMap<usize, usize>> =
    Mutex::new(alloc::collections::BTreeMap::new());

fn synth_offset_get(fd: usize) -> usize {
    *SYNTH_OFFSET.lock().get(&fd).unwrap_or(&0)
}
fn synth_offset_advance(fd: usize, n: usize) {
    *SYNTH_OFFSET.lock().entry(fd).or_insert(0) += n;
}
fn synth_offset_reset(fd: usize, v: usize) {
    SYNTH_OFFSET.lock().insert(fd, v);
}
fn synth_offset_remove(fd: usize) {
    SYNTH_OFFSET.lock().remove(&fd);
}

// ─── sys_read ────────────────────────────────────────────────────────────────

/// sys_read(fd, buf_va, count)  [NR 0]
pub fn sys_read(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    let n: isize;
    if fd == 0 {
        n = crate::shell::tty::read_line(&mut kbuf);
    } else if crate::fs::devfs::get_dev_fd(fd).is_some() {
        n = crate::fs::devfs::read(fd, &mut kbuf);
    } else if crate::fs::procfs::is_procfs_fd(fd) {
        let off = synth_offset_get(fd);
        n = crate::fs::procfs::procfs_read(fd, &mut kbuf, off);
        if n > 0 { synth_offset_advance(fd, n as usize); }
    } else if crate::fs::sysfs::is_sysfs_fd(fd) {
        let off = synth_offset_get(fd);
        n = crate::fs::sysfs::sysfs_read(fd, &mut kbuf, off);
        if n > 0 { synth_offset_advance(fd, n as usize); }
    } else if crate::fs::inotify::is_inotify_fd(fd) {
        n = crate::fs::inotify::inotify_read(fd, &mut kbuf);
    } else if crate::fs::fanotify::is_fanotify_fd(fd) {
        n = crate::fs::fanotify::fanotify_read(fd, &mut kbuf);
    } else {
        n = vfs::read(fd, &mut kbuf);
    }
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

// ─── sys_write ───────────────────────────────────────────────────────────────

/// sys_write(fd, buf_va, count)  [NR 1]
pub fn sys_write(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }
    if fd == 1 || fd == 2 {
        return crate::shell::tty::write(&kbuf);
    }
    if crate::fs::devfs::get_dev_fd(fd).is_some() {
        return crate::fs::devfs::write(fd, &kbuf);
    }
    if crate::fs::fanotify::is_fanotify_fd(fd) {
        return crate::fs::fanotify::fanotify_write(fd, &kbuf);
    }
    vfs::write(fd, &kbuf)
}

// ─── sys_open ────────────────────────────────────────────────────────────────

/// sys_open(path_va, flags, mode)  [NR 2]
pub fn sys_open(path_va: usize, flags: u32, _mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };

    // 1. /dev/
    if path.starts_with("/dev/") {
        if let Some(fd) = crate::fs::devfs::try_open(&path, flags) {
            return fd as isize;
        }
    }

    // 2. /proc/
    if path.starts_with("/proc/") || path == "/proc" {
        let fd = crate::fs::procfs::procfs_open(&path);
        if fd >= 0 { synth_offset_reset(fd as usize, 0); }
        return fd;
    }

    // 3. /sys/
    if path.starts_with("/sys/") || path == "/sys" {
        let fd = crate::fs::sysfs::sysfs_open(&path);
        if fd >= 0 { synth_offset_reset(fd as usize, 0); }
        return fd;
    }

    // 4. real VFS (ext2, ramfs, …)
    match vfs::open(&path, flags) {
        Ok(fd)  => fd as isize,
        Err(e)  => e as isize,
    }
}

// ─── sys_close ───────────────────────────────────────────────────────────────

/// sys_close(fd)  [NR 3]
pub fn sys_close(fd: usize) -> isize {
    synth_offset_remove(fd);
    if crate::fs::devfs::get_dev_fd(fd).is_some() {
        crate::fs::devfs::close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    if crate::fs::procfs::is_procfs_fd(fd) {
        crate::fs::procfs::procfs_close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    if crate::fs::sysfs::is_sysfs_fd(fd) {
        crate::fs::sysfs::sysfs_close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    if crate::fs::inotify::is_inotify_fd(fd) {
        crate::fs::inotify::inotify_close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    if crate::fs::fanotify::is_fanotify_fd(fd) {
        crate::fs::fanotify::fanotify_close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    crate::fs::fcntl::close_fd_meta(fd);
    vfs::close(fd)
}

// ─── sys_pread64 ─────────────────────────────────────────────────────────────

/// sys_pread64(fd, buf_va, count, offset)  [NR 17]
pub fn sys_pread64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }

    if crate::fs::procfs::is_procfs_fd(fd) {
        let mut kbuf = alloc::vec![0u8; count];
        let n = crate::fs::procfs::procfs_read(fd, &mut kbuf, offset as usize);
        if n <= 0 { return n; }
        if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
        return n;
    }
    if crate::fs::sysfs::is_sysfs_fd(fd) {
        let mut kbuf = alloc::vec![0u8; count];
        let n = crate::fs::sysfs::sysfs_read(fd, &mut kbuf, offset as usize);
        if n <= 0 { return n; }
        if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
        return n;
    }

    let saved = vfs::seek(fd, 0, vfs::SEEK_CUR) as i64;
    vfs::seek(fd, offset, vfs::SEEK_SET);
    let mut kbuf = alloc::vec![0u8; count];
    let n = vfs::read(fd, &mut kbuf);
    vfs::seek(fd, saved, vfs::SEEK_SET);
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

// ─── sys_writev ──────────────────────────────────────────────────────────────

/// sys_writev(fd, iov_va, iovcnt)  [NR 20]
pub fn sys_writev(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; }
    if !validate_user_ptr(iov_va, iovcnt * 16) { return -14; }
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let mut iov_buf = [0u8; 16];
        if copy_from_user(&mut iov_buf, iov_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(iov_buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(iov_buf[8..16].try_into().unwrap());
        if len == 0 { continue; }
        let n = sys_write(fd, base, len);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
    }
    total
}

// ─── sys_dup2 ────────────────────────────────────────────────────────────────

/// sys_dup2(oldfd, newfd)  [NR 33]
pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    crate::fs::fcntl::sys_dup2(oldfd, newfd)
}
