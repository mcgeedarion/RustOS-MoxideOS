//! Core file I/O syscalls: read, write, open, close, pread64, pwrite64,
//! writev, readv, dup2, ftruncate, link, rmdir.
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
//!   eventfd fd      → eventfd::eventfd_read
//!   timerfd fd      → timerfd::timerfd_read
//!   socket fd       → socket::socket_read
//!   default         → vfs::read
//!
//! ## Dispatch order for sys_write
//!   stdout/stderr   → tty
//!   devfs fd        → devfs::write
//!   fanotify fd     → fanotify::fanotify_write  (permission responses)
//!   socket fd       → socket::socket_write
//!   default         → vfs::write
//!
//! ## Dispatch order for sys_close
//!   devfs / procfs / sysfs / inotify / fanotify / eventfd / timerfd / socket
//!                   → respective close fn
//!   default → vfs::close

extern crate alloc;
use alloc::vec::Vec;
use crate::fs::vfs;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── Seek-offset table for procfs / sysfs synthetic fds ────────────────

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

// ── sys_read ───────────────────────────────────────────────────────────────────────

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
    } else if crate::fs::eventfd::is_eventfd(fd) {
        n = crate::fs::eventfd::eventfd_read(fd, &mut kbuf);
    } else if crate::fs::timerfd::is_timerfd(fd) {
        n = crate::fs::timerfd::timerfd_read(fd, &mut kbuf);
    } else if crate::net::socket::is_socket_fd(fd) {
        n = crate::net::socket::socket_read(fd, &mut kbuf);
    } else {
        n = vfs::read(fd, &mut kbuf);
    }
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

// ── sys_write ─────────────────────────────────────────────────────────────────────

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
    if crate::net::socket::is_socket_fd(fd) {
        return crate::net::socket::socket_write(fd, &kbuf);
    }
    vfs::write(fd, &kbuf)
}

// ── sys_open ─────────────────────────────────────────────────────────────────────

/// sys_open(path_va, flags, mode)  [NR 2]
pub fn sys_open(path_va: usize, flags: u32, mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) {
        Some(p) => p,
        None    => return -14,
    };
    // 1. devfs
    if let Some(fd) = crate::fs::devfs::try_open(&path, flags) {
        return fd as isize;
    }
    // 2. procfs
    if path.starts_with("/proc") {
        return crate::fs::procfs::procfs_open(&path, flags);
    }
    // 3. sysfs
    if path.starts_with("/sys") {
        return crate::fs::sysfs::sysfs_open(&path, flags);
    }
    // 4. vfs (ext2 / ramfs / fat32 / overlayfs)
    match vfs::open(&path, flags) {
        Ok(fd)  => fd as isize,
        Err(e)  => {
            // O_CREAT: create if missing
            if flags & 0o100 != 0 {
                if vfs::create(&path).is_ok() {
                    return match vfs::open(&path, flags) {
                        Ok(fd) => fd as isize,
                        Err(e) => e,
                    };
                }
            }
            e
        }
    }
}

// ── sys_close ────────────────────────────────────────────────────────────────────

/// sys_close(fd)  [NR 3]
pub fn sys_close(fd: usize) -> isize {
    crate::fs::fcntl::close_fd_meta(fd);
    // Dispatch to the appropriate subsystem.
    if crate::fs::devfs::get_dev_fd(fd).is_some() {
        crate::fs::devfs::close(fd);
        return 0;
    }
    if crate::fs::procfs::is_procfs_fd(fd) {
        synth_offset_remove(fd);
        return 0;
    }
    if crate::fs::sysfs::is_sysfs_fd(fd) {
        synth_offset_remove(fd);
        return 0;
    }
    if crate::fs::inotify::is_inotify_fd(fd) {
        crate::fs::inotify::inotify_close(fd);
        return 0;
    }
    if crate::fs::fanotify::is_fanotify_fd(fd) {
        crate::fs::fanotify::fanotify_close(fd);
        return 0;
    }
    if crate::fs::eventfd::is_eventfd(fd) {
        crate::fs::eventfd::sys_close_efd(fd);
        return 0;
    }
    if crate::fs::timerfd::is_timerfd(fd) {
        crate::fs::timerfd::sys_close_tfd(fd);
        return 0;
    }
    if crate::fs::pipe::is_pipe(fd) {
        crate::fs::pipe::sys_close_pipe(fd);
        return 0;
    }
    if crate::net::socket::is_socket_fd(fd) {
        crate::net::socket::sys_close_socket(fd);
        return 0;
    }
    vfs::close(fd);
    0
}

// ── sys_pread64 ──────────────────────────────────────────────────────────────────

/// sys_pread64(fd, buf_va, count, offset)  [NR 17]
pub fn sys_pread64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    let n = vfs::pread(fd, kbuf.as_mut_ptr(), count, offset);
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

// ── sys_writev ───────────────────────────────────────────────────────────────────

#[repr(C)]
struct IoVec { base: usize, len: usize }

/// sys_writev(fd, iov_va, iovcnt)  [NR 20]
pub fn sys_writev(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    let mut total = 0isize;
    let iov_size = core::mem::size_of::<IoVec>();
    for i in 0..iovcnt {
        let ptr = iov_va + i * iov_size;
        let mut raw = [0u8; 16];
        if copy_from_user(&mut raw, ptr).is_err() { return -14; }
        let iov: IoVec = unsafe { core::mem::transmute(raw) };
        if iov.len == 0 { continue; }
        let n = sys_write(fd, iov.base, iov.len);
        if n < 0 { return n; }
        total += n;
    }
    total
}

/// sys_readv(fd, iov_va, iovcnt)  [NR 19]
pub fn sys_readv(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    let mut total = 0isize;
    let iov_size = core::mem::size_of::<IoVec>();
    for i in 0..iovcnt {
        let ptr = iov_va + i * iov_size;
        let mut raw = [0u8; 16];
        if copy_from_user(&mut raw, ptr).is_err() { return -14; }
        let iov: IoVec = unsafe { core::mem::transmute(raw) };
        if iov.len == 0 { continue; }
        let n = sys_read(fd, iov.base, iov.len);
        if n < 0 { return n; }
        total += n;
        if (n as usize) < iov.len { break; } // short read
    }
    total
}

// ── ftruncate ────────────────────────────────────────────────────────────────────

/// sys_ftruncate(fd, length)  [NR 77]
pub fn sys_ftruncate(fd: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    match crate::fs::vfs_ops::truncate_fd(fd, length as usize) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

// ── link / rmdir ─────────────────────────────────────────────────────────────────

/// sys_link(oldpath_va, newpath_va)  [NR 86]
pub fn sys_link(old_va: usize, new_va: usize) -> isize {
    let old = match read_cstr_safe(old_va) { Some(s) => s, None => return -14 };
    let new = match read_cstr_safe(new_va) { Some(s) => s, None => return -14 };
    match vfs::link(&old, &new) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

/// sys_rmdir(path_va)  [NR 84]
pub fn sys_rmdir(path_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    match vfs::rmdir(&path) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}
