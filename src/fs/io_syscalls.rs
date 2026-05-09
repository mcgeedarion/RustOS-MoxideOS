//! Core file I/O syscalls: read, write, open, close, pread64, pwrite64,
//! writev, readv, dup, dup2, dup3, ftruncate, link, rmdir.
//!
//! ## fd translation
//! Every syscall that takes a user-visible fd now calls `proc_fd_backing` to
//! translate it to a kernel-internal *backing fd* before dispatching to any
//! subsystem (vfs, devfs, pipe, socket, …).  fds 0/1/2 translate to
//! themselves for zero overhead on the hot tty path.
//!
//! ## Dispatch order for sys_open
//! Delegated to `process_fd::proc_fd_open` which owns the full dispatch chain
//! (devfs → procfs → sysfs → vfs) plus O_CREAT / O_TRUNC handling and
//! RLIMIT_NOFILE enforcement.
//!
//! ## Dispatch order for sys_read  (on backing fd)
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
//! ## Dispatch order for sys_write  (on backing fd)
//!   stdout/stderr   → tty
//!   devfs fd        → devfs::write
//!   fanotify fd     → fanotify::fanotify_write  (permission responses)
//!   socket fd       → socket::socket_write
//!   default         → vfs::write  (RLIMIT_FSIZE enforced before this call)
//!
//! ## RLIMIT_FSIZE enforcement
//!   Before any regular-file write (vfs path), the current file size is
//!   obtained via vfs::file_size(fd).  If adding `count` bytes would push
//!   the file past the soft FSIZE limit:
//!     * SIGXFSZ is delivered to the current process.
//!     * -EFBIG (-27) is returned (POSIX.1-2017, §2.4.1).

extern crate alloc;
use alloc::vec::Vec;
use crate::fs::vfs;
use crate::fs::process_fd::{proc_fd_backing, proc_fd_close, proc_fd_dup2,
                             proc_fd_install, proc_fd_open};
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── Current pid shorthand ────────────────────────────────────────────────────
#[inline(always)]
fn cpid() -> usize { crate::proc::scheduler::current_pid() }

// ── Seek-offset table for procfs / sysfs synthetic fds ──────────────────────
// Keyed on *backing* fd numbers so the offset is stable across the local→
// backing translation.

use spin::Mutex;
static SYNTH_OFFSET: Mutex<alloc::collections::BTreeMap<usize, usize>> =
    Mutex::new(alloc::collections::BTreeMap::new());

fn synth_offset_get(bfd: usize) -> usize {
    *SYNTH_OFFSET.lock().get(&bfd).unwrap_or(&0)
}
fn synth_offset_advance(bfd: usize, n: usize) {
    *SYNTH_OFFSET.lock().entry(bfd).or_insert(0) += n;
}
fn synth_offset_reset(bfd: usize, v: usize) {
    SYNTH_OFFSET.lock().insert(bfd, v);
}
fn synth_offset_remove(bfd: usize) {
    SYNTH_OFFSET.lock().remove(&bfd);
}

// ── Translate user fd → backing fd ──────────────────────────────────────────
//
// For fds 0/1/2 (stdin/stdout/stderr) the local fd IS the backing fd;
// skip the table lookup to keep the common tty path fast.
// Returns a negative errno if the fd is not open.

#[inline]
fn resolve(fd: usize) -> isize {
    if fd <= 2 { return fd as isize; }
    proc_fd_backing(cpid(), fd)
}

// ── RLIMIT_FSIZE helper ──────────────────────────────────────────────────────

const RLIMIT_FSIZE: usize = 1;
const RLIM_INFINITY: u64 = u64::MAX;
const SIGXFSZ: u32 = 25;
const EFBIG:   isize = -27;

fn check_fsize_limit(bfd: usize, count: usize) -> Result<usize, isize> {
    let pid = cpid();
    let (soft, _) = crate::proc::rlimit::getrlimit_for(0, RLIMIT_FSIZE);
    if soft == RLIM_INFINITY { return Ok(count); }
    let cur_size = vfs::file_size(bfd).unwrap_or(0) as u64;
    let new_end  = cur_size.saturating_add(count as u64);
    if cur_size >= soft || new_end > soft {
        crate::proc::signal::send_signal(pid, SIGXFSZ);
        return Err(EFBIG);
    }
    Ok(count)
}

// ── sys_read ─────────────────────────────────────────────────────────────────

/// sys_read(fd, buf_va, count)  [NR 0]
pub fn sys_read(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }

    let bfd = match resolve(fd) {
        n if n < 0 => return n,
        n          => n as usize,
    };

    let mut kbuf = alloc::vec![0u8; count];
    let n: isize;

    if bfd == 0 {
        n = crate::shell::tty::read_line(&mut kbuf);
    } else if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        n = crate::fs::devfs::read(bfd, &mut kbuf);
    } else if crate::fs::procfs::is_procfs_fd(bfd) {
        let off = synth_offset_get(bfd);
        n = crate::fs::procfs::procfs_read(bfd, &mut kbuf, off);
        if n > 0 { synth_offset_advance(bfd, n as usize); }
    } else if crate::fs::sysfs::is_sysfs_fd(bfd) {
        let off = synth_offset_get(bfd);
        n = crate::fs::sysfs::sysfs_read(bfd, &mut kbuf, off);
        if n > 0 { synth_offset_advance(bfd, n as usize); }
    } else if crate::fs::inotify::is_inotify_fd(bfd) {
        n = crate::fs::inotify::inotify_read(bfd, &mut kbuf);
    } else if crate::fs::fanotify::is_fanotify_fd(bfd) {
        n = crate::fs::fanotify::fanotify_read(bfd, &mut kbuf);
    } else if crate::fs::eventfd::is_eventfd(bfd) {
        n = crate::fs::eventfd::eventfd_read(bfd, &mut kbuf);
    } else if crate::fs::timerfd::is_timerfd(bfd) {
        n = crate::fs::timerfd::timerfd_read(bfd, &mut kbuf);
    } else if crate::net::socket::is_socket_fd(bfd) {
        n = crate::net::socket::socket_read(bfd, &mut kbuf);
    } else {
        n = vfs::read(bfd, &mut kbuf);
    }

    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

// ── sys_write ────────────────────────────────────────────────────────────────

/// sys_write(fd, buf_va, count)  [NR 1]
pub fn sys_write(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }

    let bfd = match resolve(fd) {
        n if n < 0 => return n,
        n          => n as usize,
    };

    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }

    if bfd == 1 || bfd == 2 {
        return crate::shell::tty::write(&kbuf);
    }
    if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        return crate::fs::devfs::write(bfd, &kbuf);
    }
    if crate::fs::fanotify::is_fanotify_fd(bfd) {
        return crate::fs::fanotify::fanotify_write(bfd, &kbuf);
    }
    if crate::net::socket::is_socket_fd(bfd) {
        return crate::net::socket::socket_write(bfd, &kbuf);
    }

    let safe_count = match check_fsize_limit(bfd, count) {
        Ok(n)  => n,
        Err(e) => return e,
    };
    vfs::write(bfd, &kbuf[..safe_count])
}

// ── sys_open ─────────────────────────────────────────────────────────────────

/// sys_open(path_va, flags, mode)  [NR 2]
pub fn sys_open(path_va: usize, flags: u32, mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) {
        Some(p) => p,
        None    => return -14,
    };
    proc_fd_open(cpid(), &path, flags, mode)
}

/// sys_openat(dirfd, path_va, flags, mode)  [NR 257]
///
/// dirfd == AT_FDCWD (-100) → use cwd, same as sys_open.
/// dirfd is a real fd → resolve relative paths against it.
/// Absolute paths always ignore dirfd (POSIX).
pub fn sys_openat(dirfd: i32, path_va: usize, flags: u32, mode: u32) -> isize {
    let path = match read_cstr_safe(path_va) {
        Some(p) => p,
        None    => return -14,
    };
    let pid = cpid();

    // Absolute path or AT_FDCWD: behave exactly like sys_open.
    if path.starts_with('/') || dirfd == -100 {
        return proc_fd_open(pid, &path, flags, mode);
    }

    // Relative path + real dirfd: prefix with dirfd's path.
    let dir_path = match crate::fs::process_fd::proc_fd_path(pid, dirfd as usize) {
        Some(p) => p,
        None    => return -9, // EBADF
    };
    let full = if dir_path.ends_with('/') {
        alloc::format!("{}{}", dir_path, path)
    } else {
        alloc::format!("{}/{}", dir_path, path)
    };
    proc_fd_open(pid, &full, flags, mode)
}

// ── sys_close ────────────────────────────────────────────────────────────────

/// sys_close(fd)  [NR 3]
pub fn sys_close(fd: usize) -> isize {
    // synth_offset cleanup: need the backing fd before we remove the entry.
    if fd > 2 {
        let bfd = proc_fd_backing(cpid(), fd);
        if bfd >= 0 {
            let bfd = bfd as usize;
            if crate::fs::procfs::is_procfs_fd(bfd) || crate::fs::sysfs::is_sysfs_fd(bfd) {
                synth_offset_remove(bfd);
            }
        }
    }
    proc_fd_close(cpid(), fd)
}

// ── sys_dup / sys_dup2 / sys_dup3 ────────────────────────────────────────────

/// sys_dup(fd)  [NR 32]
/// Duplicate fd using the lowest available process-local fd >= 3.
pub fn sys_dup(fd: usize) -> isize {
    let pid = cpid();
    let bfd_r = proc_fd_backing(pid, fd);
    if bfd_r < 0 { return bfd_r; }
    let bfd = bfd_r as usize;

    // Duplicate backing fd.
    let new_bfd_r = crate::fs::vfs::dup_from(bfd, bfd);
    let new_bfd = if new_bfd_r >= 0 { new_bfd_r as usize } else { bfd };

    // Retrieve entry metadata to preserve flags.
    let entry = match crate::fs::process_fd::proc_fd_get(pid, fd) {
        Some(e) => e,
        None    => return -9,
    };

    // Install without cloexec (dup always clears it).
    let flags = (entry.fl_flags as u32) & !crate::fs::process_fd::O_CLOEXEC_FLAG;
    proc_fd_install(pid, new_bfd, entry.path.clone(), flags, None) as isize
}

/// sys_dup2(old_fd, new_fd)  [NR 33]
pub fn sys_dup2(old_fd: usize, new_fd: usize) -> isize {
    proc_fd_dup2(cpid(), old_fd, new_fd)
}

/// sys_dup3(old_fd, new_fd, flags)  [NR 292]
/// Like dup2 but errors if old_fd == new_fd, and honours O_CLOEXEC in flags.
pub fn sys_dup3(old_fd: usize, new_fd: usize, flags: u32) -> isize {
    if old_fd == new_fd { return -22; } // EINVAL
    let r = proc_fd_dup2(cpid(), old_fd, new_fd);
    if r >= 0 && flags & 0o2000000 != 0 {
        crate::fs::process_fd::proc_fd_set_cloexec(cpid(), new_fd, true);
    }
    r
}

// ── sys_pread64 ──────────────────────────────────────────────────────────────

/// sys_pread64(fd, buf_va, count, offset)  [NR 17]
pub fn sys_pread64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let bfd = match resolve(fd) { n if n < 0 => return n, n => n as usize };
    let mut kbuf = alloc::vec![0u8; count];
    let n = vfs::pread(bfd, kbuf.as_mut_ptr(), count, offset);
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

// ── sys_pwrite64 (RLIMIT_FSIZE-aware) ────────────────────────────────────────

/// sys_pwrite64(fd, buf_va, count, offset)  [NR 18]
pub fn sys_pwrite64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if offset < 0  { return -22; }
    let bfd = match resolve(fd) { n if n < 0 => return n, n => n as usize };
    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }

    let pid = cpid();
    let (soft, _) = crate::proc::rlimit::getrlimit_for(0, RLIMIT_FSIZE);
    if soft != RLIM_INFINITY {
        let end = (offset as u64).saturating_add(count as u64);
        if end > soft {
            crate::proc::signal::send_signal(pid, SIGXFSZ);
            return EFBIG;
        }
    }

    let old_pos = vfs::seek(bfd, 0, vfs::SEEK_CUR) as i64;
    vfs::seek(bfd, offset, vfs::SEEK_SET);
    let n = vfs::write(bfd, &kbuf);
    vfs::seek(bfd, old_pos, vfs::SEEK_SET);
    n
}

// ── sys_writev ────────────────────────────────────────────────────────────────

#[repr(C)]
struct IoVec { base: usize, len: usize }

/// sys_writev(fd, iov_va, iovcnt)  [NR 20]
pub fn sys_writev(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; }

    let bfd = match resolve(fd) { n if n < 0 => return n, n => n as usize };
    let iov_size = core::mem::size_of::<IoVec>();
    if !validate_user_ptr(iov_va, iovcnt * iov_size) { return -14; }

    let mut total_len: usize = 0;
    for i in 0..iovcnt {
        let mut raw = [0u8; 16];
        if copy_from_user(&mut raw, iov_va + i * iov_size).is_err() { return -14; }
        let iov: IoVec = unsafe { core::mem::transmute(raw) };
        total_len = total_len.saturating_add(iov.len);
    }

    let is_vfs = bfd != 1 && bfd != 2
        && crate::fs::devfs::get_dev_fd(bfd).is_none()
        && !crate::fs::fanotify::is_fanotify_fd(bfd)
        && !crate::net::socket::is_socket_fd(bfd);

    if is_vfs && total_len > 0 {
        match check_fsize_limit(bfd, total_len) {
            Ok(_)  => {}
            Err(e) => return e,
        }
    }

    // Re-use sys_write with the already-resolved bfd to avoid double lookup.
    let mut written = 0isize;
    for i in 0..iovcnt {
        let mut raw = [0u8; 16];
        if copy_from_user(&mut raw, iov_va + i * iov_size).is_err() { return -14; }
        let iov: IoVec = unsafe { core::mem::transmute(raw) };
        if iov.len == 0 { continue; }
        // Write directly via backing fd (skip the local→backing resolve again).
        let n = write_bfd(bfd, iov.base, iov.len);
        if n < 0 { return if written > 0 { written } else { n }; }
        written += n;
    }
    written
}

/// sys_readv(fd, iov_va, iovcnt)  [NR 19]
pub fn sys_readv(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    let bfd = match resolve(fd) { n if n < 0 => return n, n => n as usize };
    let iov_size = core::mem::size_of::<IoVec>();
    let mut total = 0isize;
    for i in 0..iovcnt {
        let ptr = iov_va + i * iov_size;
        let mut raw = [0u8; 16];
        if copy_from_user(&mut raw, ptr).is_err() { return -14; }
        let iov: IoVec = unsafe { core::mem::transmute(raw) };
        if iov.len == 0 { continue; }
        // Read directly via backing fd.
        let n = read_bfd(bfd, iov.base, iov.len);
        if n < 0 { return n; }
        total += n;
        if (n as usize) < iov.len { break; }
    }
    total
}

// ── Internal bfd-direct read/write (skip process-fd lookup) ─────────────────
// Used by readv/writev after the one-time resolve at the top of each syscall.

fn read_bfd(bfd: usize, buf_va: usize, count: usize) -> isize {
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    let n: isize;
    if bfd == 0 {
        n = crate::shell::tty::read_line(&mut kbuf);
    } else if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        n = crate::fs::devfs::read(bfd, &mut kbuf);
    } else if crate::fs::procfs::is_procfs_fd(bfd) {
        let off = synth_offset_get(bfd);
        n = crate::fs::procfs::procfs_read(bfd, &mut kbuf, off);
        if n > 0 { synth_offset_advance(bfd, n as usize); }
    } else if crate::fs::sysfs::is_sysfs_fd(bfd) {
        let off = synth_offset_get(bfd);
        n = crate::fs::sysfs::sysfs_read(bfd, &mut kbuf, off);
        if n > 0 { synth_offset_advance(bfd, n as usize); }
    } else if crate::fs::inotify::is_inotify_fd(bfd) {
        n = crate::fs::inotify::inotify_read(bfd, &mut kbuf);
    } else if crate::fs::fanotify::is_fanotify_fd(bfd) {
        n = crate::fs::fanotify::fanotify_read(bfd, &mut kbuf);
    } else if crate::fs::eventfd::is_eventfd(bfd) {
        n = crate::fs::eventfd::eventfd_read(bfd, &mut kbuf);
    } else if crate::fs::timerfd::is_timerfd(bfd) {
        n = crate::fs::timerfd::timerfd_read(bfd, &mut kbuf);
    } else if crate::net::socket::is_socket_fd(bfd) {
        n = crate::net::socket::socket_read(bfd, &mut kbuf);
    } else {
        n = vfs::read(bfd, &mut kbuf);
    }
    if n <= 0 { return n; }
    if copy_to_user(buf_va, &kbuf[..n as usize]).is_err() { return -14; }
    n
}

fn write_bfd(bfd: usize, buf_va: usize, count: usize) -> isize {
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }
    if bfd == 1 || bfd == 2 {
        return crate::shell::tty::write(&kbuf);
    }
    if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        return crate::fs::devfs::write(bfd, &kbuf);
    }
    if crate::fs::fanotify::is_fanotify_fd(bfd) {
        return crate::fs::fanotify::fanotify_write(bfd, &kbuf);
    }
    if crate::net::socket::is_socket_fd(bfd) {
        return crate::net::socket::socket_write(bfd, &kbuf);
    }
    vfs::write(bfd, &kbuf)
}

// ── ftruncate ────────────────────────────────────────────────────────────────

/// sys_ftruncate(fd, length)  [NR 77]
pub fn sys_ftruncate(fd: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    let bfd = match resolve(fd) { n if n < 0 => return n, n => n as usize };
    let (soft, _) = crate::proc::rlimit::getrlimit_for(0, RLIMIT_FSIZE);
    if soft != RLIM_INFINITY && (length as u64) > soft {
        let pid = cpid();
        crate::proc::signal::send_signal(pid, SIGXFSZ);
        return EFBIG;
    }
    match crate::fs::vfs_ops::truncate_fd(bfd, length as usize) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

// ── link / rmdir ─────────────────────────────────────────────────────────────

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
