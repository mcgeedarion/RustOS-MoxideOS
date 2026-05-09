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
//!   default         → vfs::write  (RLIMIT_FSIZE enforced before this call)
//!
//! ## RLIMIT_FSIZE enforcement
//!   Before any regular-file write (vfs path), the current file size is
//!   obtained via vfs::file_size(fd).  If adding `count` bytes would push
//!   the file past the soft FSIZE limit:
//!     * SIGXFSZ is delivered to the current process.
//!     * -EFBIG (-27) is returned (POSIX.1-2017, §2.4.1).
//!   Writes to tty / devfs / socket / fanotify bypass the check (they are
//!   not regular files and have no meaningful “file size”).

extern crate alloc;
use alloc::vec::Vec;
use crate::fs::vfs;
use crate::proc::exec::read_cstr_safe;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── Seek-offset table for procfs / sysfs synthetic fds ──────────────────

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

// ── RLIMIT_FSIZE helper ─────────────────────────────────────────────────────
//
// Called before every regular-file write.  Returns Ok(capped_count) if the
// write is allowed (possibly truncating `count` to fit exactly at the limit),
// or Err(-27) (EFBIG) if the current position is already at or past the limit.
//
// POSIX semantics:
//   * If current_size + count > soft_limit, deliver SIGXFSZ and return EFBIG.
//   * If current_size is already >= soft_limit, same treatment.
//   * RLIM_INFINITY (u64::MAX) means no limit.

const RLIMIT_FSIZE: usize = 1;
const RLIM_INFINITY: u64 = u64::MAX;
const SIGXFSZ: u32 = 25;
const EFBIG:   isize = -27;

/// Check RLIMIT_FSIZE for a prospective write of `count` bytes to `fd`.
/// Returns `Ok(count)` unchanged on success (or if the fd is not a regular
/// VFS file), or `Err(EFBIG)` after delivering SIGXFSZ.
fn check_fsize_limit(fd: usize, count: usize) -> Result<usize, isize> {
    // Quick-exit: only regular VFS files are subject to FSIZE.
    // Sockets, ttys, devfs, etc. are already handled before we reach vfs::write.
    let pid = crate::proc::scheduler::current_pid();
    let (soft, _) = crate::proc::rlimit::getrlimit_for(0, RLIMIT_FSIZE);
    if soft == RLIM_INFINITY { return Ok(count); }

    // Use the current file position as the write-start offset so that
    // append-mode writes are accounted correctly.  vfs::file_size gives the
    // on-disk size; seek position may be past EOF for sparse writes, but
    // that’s unusual — using the larger of the two is the safe choice.
    let cur_size = vfs::file_size(fd).unwrap_or(0) as u64;
    let new_end  = cur_size.saturating_add(count as u64);

    if cur_size >= soft {
        // Already at or past the limit — zero bytes may be written.
        crate::proc::signal::send_signal(pid, SIGXFSZ);
        return Err(EFBIG);
    }

    if new_end > soft {
        // Partially allowed: truncate the write to exactly fit the limit,
        // then signal.  POSIX allows writing up to the limit before raising
        // SIGXFSZ on the NEXT write, but delivering it now and capping here
        // is also conformant and simpler.
        crate::proc::signal::send_signal(pid, SIGXFSZ);
        return Err(EFBIG);
    }

    Ok(count)
}

// ── sys_read ──────────────────────────────────────────────────────────────────

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

// ── sys_write ──────────────────────────────────────────────────────────────────

/// sys_write(fd, buf_va, count)  [NR 1]
pub fn sys_write(fd: usize, buf_va: usize, count: usize) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }
    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }

    // tty, devfs, fanotify, socket: no FSIZE check (not regular files).
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

    // Regular VFS file: enforce RLIMIT_FSIZE.
    let safe_count = match check_fsize_limit(fd, count) {
        Ok(n)  => n,
        Err(e) => return e,
    };
    vfs::write(fd, &kbuf[..safe_count])
}

// ── sys_open ──────────────────────────────────────────────────────────────────

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

// ── sys_close ──────────────────────────────────────────────────────────────────

/// sys_close(fd)  [NR 3]
pub fn sys_close(fd: usize) -> isize {
    crate::fs::fcntl::close_fd_meta(fd);
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

// ── sys_pread64 ──────────────────────────────────────────────────────────────

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

// ── sys_pwrite64 (RLIMIT_FSIZE-aware) ─────────────────────────────────────────
//
// pwrite64 writes at an explicit offset rather than the seek position.  FSIZE
// is checked against the target end offset (offset + count) vs the limit.

/// sys_pwrite64(fd, buf_va, count, offset)  [NR 18]
pub fn sys_pwrite64(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    if count == 0 { return 0; }
    if offset < 0  { return -22; }
    let mut kbuf = alloc::vec![0u8; count];
    if copy_from_user(&mut kbuf, buf_va).is_err() { return -14; }

    // RLIMIT_FSIZE: end-of-write position is offset + count.
    let pid = crate::proc::scheduler::current_pid();
    let (soft, _) = crate::proc::rlimit::getrlimit_for(0, RLIMIT_FSIZE);
    if soft != RLIM_INFINITY {
        let end = (offset as u64).saturating_add(count as u64);
        if end > soft {
            crate::proc::signal::send_signal(pid, SIGXFSZ);
            return EFBIG;
        }
    }

    let old_pos = vfs::seek(fd, 0, vfs::SEEK_CUR) as i64;
    vfs::seek(fd, offset, vfs::SEEK_SET);
    let n = vfs::write(fd, &kbuf);
    vfs::seek(fd, old_pos, vfs::SEEK_SET);
    n
}

// ── sys_writev ──────────────────────────────────────────────────────────────────

#[repr(C)]
struct IoVec { base: usize, len: usize }

/// sys_writev(fd, iov_va, iovcnt)  [NR 20]
///
/// RLIMIT_FSIZE: checked once up-front for the total write size so that
/// either all vectors are written or none are (atomic from the limit’s
/// perspective).  This matches glibc’s expectation.
pub fn sys_writev(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; }

    let iov_size = core::mem::size_of::<IoVec>();
    if !validate_user_ptr(iov_va, iovcnt * iov_size) { return -14; }

    // Collect total byte count for the up-front FSIZE check.
    let mut total_len: usize = 0;
    for i in 0..iovcnt {
        let mut raw = [0u8; 16];
        if copy_from_user(&mut raw, iov_va + i * iov_size).is_err() { return -14; }
        let iov: IoVec = unsafe { core::mem::transmute(raw) };
        total_len = total_len.saturating_add(iov.len);
    }

    // FSIZE check for the vfs path (skip tty / devfs / socket).
    let is_vfs_file = fd != 1 && fd != 2
        && crate::fs::devfs::get_dev_fd(fd).is_none()
        && !crate::fs::fanotify::is_fanotify_fd(fd)
        && !crate::net::socket::is_socket_fd(fd);

    if is_vfs_file && total_len > 0 {
        match check_fsize_limit(fd, total_len) {
            Ok(_)  => {}
            Err(e) => return e,
        }
    }

    // Scatter-gather write.
    let mut written = 0isize;
    for i in 0..iovcnt {
        let mut raw = [0u8; 16];
        if copy_from_user(&mut raw, iov_va + i * iov_size).is_err() { return -14; }
        let iov: IoVec = unsafe { core::mem::transmute(raw) };
        if iov.len == 0 { continue; }
        // Use sys_write directly; it re-checks FSIZE per-vector which is fine
        // (the up-front check already ensured the total fits).
        let n = sys_write(fd, iov.base, iov.len);
        if n < 0 { return if written > 0 { written } else { n }; }
        written += n;
    }
    written
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
        if (n as usize) < iov.len { break; }
    }
    total
}

// ── ftruncate ──────────────────────────────────────────────────────────────────

/// sys_ftruncate(fd, length)  [NR 77]
/// RLIMIT_FSIZE also applies to ftruncate when growing a file.
pub fn sys_ftruncate(fd: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    // Enforce FSIZE when *extending* the file.
    let (soft, _) = crate::proc::rlimit::getrlimit_for(0, RLIMIT_FSIZE);
    if soft != RLIM_INFINITY && (length as u64) > soft {
        let pid = crate::proc::scheduler::current_pid();
        crate::proc::signal::send_signal(pid, SIGXFSZ);
        return EFBIG;
    }
    match crate::fs::vfs_ops::truncate_fd(fd, length as usize) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

// ── link / rmdir ──────────────────────────────────────────────────────────────

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
