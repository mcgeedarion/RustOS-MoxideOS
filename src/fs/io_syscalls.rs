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
//!   default         → vfs::read
//!
//! ## Dispatch order for sys_write
//!   stdout/stderr   → tty
//!   devfs fd        → devfs::write
//!   fanotify fd     → fanotify::fanotify_write  (permission responses)
//!   default         → vfs::write
//!
//! ## Dispatch order for sys_close
//!   devfs / procfs / sysfs / inotify / fanotify / eventfd / timerfd
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
    vfs::write(fd, &kbuf)
}

// ── sys_open ─────────────────────────────────────────────────────────────────────

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

// ── sys_close ─────────────────────────────────────────────────────────────────────

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
    if crate::fs::eventfd::is_eventfd(fd) {
        crate::fs::eventfd::eventfd_close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    if crate::fs::timerfd::is_timerfd(fd) {
        crate::fs::timerfd::timerfd_close(fd);
        crate::fs::fcntl::close_fd_meta(fd);
        return 0;
    }
    crate::fs::fcntl::close_fd_meta(fd);
    vfs::close(fd)
}

// ── sys_pread64 ────────────────────────────────────────────────────────────────

/// sys_pread64(fd, buf_va, count, offset)  [NR 17]
///
/// For real-VFS (tmpfs, ext2, fat32) FDs we route through `vfs_ops::pread`
/// so the file-offset in the FD is NOT perturbed.  For synthetic
/// (procfs/sysfs) FDs we do the direct read-at-offset path.
pub fn sys_pread64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    if offset < 0 { return -22; }

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

    // Real VFS path: use vfs_ops::pread so the FD offset is not perturbed.
    if let Some(path) = vfs::fd_path(fd) {
        match crate::fs::vfs_ops::pread(&path, offset as usize, count) {
            Ok(data) => {
                let n = data.len();
                if copy_to_user(buf_va, &data).is_err() { return -14; }
                return n as isize;
            }
            Err(e) => return e,
        }
    }

    // Fallback for FDs without a stored path (shouldn't happen for real files).
    let saved = vfs::seek(fd, 0, vfs::SEEK_CUR) as i64;
    vfs::seek(fd, offset, vfs::SEEK_SET);
    let mut kbuf = alloc::vec![0u8; count];
    let n = vfs::read(fd, &mut kbuf);
    vfs::seek(fd, saved, vfs::SEEK_SET);
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

// ── sys_pwrite64 ───────────────────────────────────────────────────────────────

/// sys_pwrite64(fd, buf_va, count, offset)  [NR 18]
///
/// Writes `count` bytes from userspace at `buf_va` to the file at `offset`
/// without changing the FD's current position.
pub fn sys_pwrite64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    if offset < 0 { return -22; }

    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }

    // Real VFS path: use vfs_ops::pwrite (does not perturb FD offset).
    if let Some(path) = vfs::fd_path(fd) {
        return match crate::fs::vfs_ops::pwrite(&path, offset as usize, &kbuf) {
            Ok(n)  => n as isize,
            Err(e) => e,
        };
    }

    // Fallback: save/restore seek position.
    let saved = vfs::seek(fd, 0, vfs::SEEK_CUR) as i64;
    vfs::seek(fd, offset, vfs::SEEK_SET);
    let n = vfs::write(fd, &kbuf);
    vfs::seek(fd, saved, vfs::SEEK_SET);
    n
}

// ── sys_ftruncate ──────────────────────────────────────────────────────────────

/// sys_ftruncate(fd, length)  [NR 77]
///
/// Resize the file open on `fd` to exactly `length` bytes.
/// This is the direct enabler for `shm_open() + ftruncate() + mmap()`:
///   fd = shm_open("/myshm", O_RDWR|O_CREAT, 0600);
///   ftruncate(fd, 4096);        // ← this syscall
///   ptr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
pub fn sys_ftruncate(fd: usize, length: i64) -> isize {
    if length < 0 { return -22; } // EINVAL: negative size
    let len = length as usize;
    let path = match vfs::fd_path(fd) {
        Some(p) => p,
        None    => return -9,  // EBADF
    };
    match crate::fs::vfs_ops::truncate(&path, len) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

// ── sys_writev ────────────────────────────────────────────────────────────────────

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

// ── sys_readv ──────────────────────────────────────────────────────────────────────

/// sys_readv(fd, iov_va, iovcnt)  [NR 19]
pub fn sys_readv(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
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
        let n = sys_read(fd, base, len);
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
    }
    total
}

// ── sys_dup2 ──────────────────────────────────────────────────────────────────────

/// sys_dup2(oldfd, newfd)  [NR 33]
pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    crate::fs::fcntl::sys_dup2(oldfd, newfd)
}

// ── sys_link ──────────────────────────────────────────────────────────────────────

/// sys_link(old_va, new_va)  [NR 86]
pub fn sys_link(old_va: usize, new_va: usize) -> isize {
    let old = match read_cstr_safe(old_va) { Some(s) => s, None => return -14 };
    let new = match read_cstr_safe(new_va) { Some(s) => s, None => return -14 };
    match crate::fs::vfs_ops::link(&old, &new) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

// ── sys_rmdir ─────────────────────────────────────────────────────────────────────

/// sys_rmdir(path_va)  [NR 84]
pub fn sys_rmdir(path_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    match crate::fs::vfs_ops::rmdir(&path) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}
