//! VFS kernel-internal helpers.
//!
//! The full per-fd dispatch layer lives in the individual fs modules
//! (ext2, devfs, pipe, etc.) and is wired through the fd table in fcntl.rs.
//! This file exposes thin wrappers that kernel subsystems use to read/write
//! files without going through syscall user-space copy paths.

extern crate alloc;
use crate::core::fast_hash::KernelFastMap;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use spin::Mutex;

// Re-export the seek constants used by callers.
pub use crate::fs::fcntl::{SEEK_CUR, SEEK_END, SEEK_SET};

const RAW_FD_BASE: usize = 1024;
const RAW_FD_END: usize = 4096;
const O_ACCMODE: u32 = 3;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 0o100;
pub const O_CLOEXEC: u32 = 0o2000000;

#[derive(Clone)]
struct RawFd {
    path: String,
    offset: usize,
    flags: u32,
}

/// Compatibility stat shape used by older ext2-facing callers.
#[derive(Clone, Debug)]
pub struct VfsStat {
    pub ino: u64,
    pub mode: u16,
    pub nlink: u64,
    pub size: u64,
    pub is_dir: bool,
}

/// Fast map is safe here: keys are bounded kernel-assigned raw fd numbers and
/// iteration order is never exposed as an ABI.
static RAW_FDS: Mutex<KernelFastMap<usize, RawFd>> = Mutex::new(KernelFastMap::new());

fn alloc_raw_fd() -> Option<usize> {
    let fds = RAW_FDS.lock();
    (RAW_FD_BASE..RAW_FD_END).find(|fd| !fds.contains_key(fd))
}

fn lsm_ctx_for_stat(st: &crate::fs::vfs_ops::KStat) -> crate::security::lsm::LsmCtx {
    let pid = crate::proc::scheduler::current_pid();
    let (euid, egid, caps, supp_groups) = crate::proc::scheduler::with_proc(pid, |p| {
        (p.euid, p.egid, p.caps.effective, p.supp_groups.clone())
    })
    .unwrap_or((0, 0, u64::MAX, Vec::new()));
    let mut ctx =
        crate::security::lsm::LsmCtx::with_creds(pid, euid, egid, caps, st.uid, st.gid, st.mode);
    ctx.supp_groups = supp_groups;
    ctx
}

fn lsm_check_existing(path: &str, flags: u32) -> Result<(), isize> {
    let st = crate::fs::vfs_ops::stat(path)?;
    let ctx = lsm_ctx_for_stat(&st);
    crate::security::lsm::lsm_dispatch(crate::security::lsm::Hook::FileOpen, &ctx)
        .map_err(|e| e as isize)?;
    if flags & O_ACCMODE == O_WRONLY || flags & O_ACCMODE == O_RDWR {
        crate::security::lsm::lsm_dispatch(crate::security::lsm::Hook::FileWrite, &ctx)
            .map_err(|e| e as isize)?;
    }
    Ok(())
}

pub fn open_raw(path: &str, flags: u32) -> Result<usize, isize> {
    match lsm_check_existing(path, flags) {
        Ok(()) => {},
        Err(-2) if flags & O_CREAT != 0 => {
            let ctx = crate::security::lsm::LsmCtx::for_current_task("", 0, 0o666);
            crate::security::lsm::lsm_dispatch(crate::security::lsm::Hook::InodeCreate, &ctx)
                .map_err(|e| e as isize)?;
            crate::fs::vfs_ops::create(path)?;
        },
        Err(e) => return Err(e),
    }

    let fd = alloc_raw_fd().ok_or(-24isize)?;
    RAW_FDS.lock().insert(
        fd,
        RawFd {
            path: path.to_string(),
            offset: 0,
            flags,
        },
    );
    Ok(fd)
}

/// Allocate an anonymous raw fd for synthetic descriptors such as eventfd.
pub fn open_anon(flags: u32) -> Result<usize, isize> {
    let fd = alloc_raw_fd().ok_or(-24isize)?;
    RAW_FDS.lock().insert(
        fd,
        RawFd {
            path: String::new(),
            offset: 0,
            flags,
        },
    );
    Ok(fd)
}

pub fn close_raw(fd: usize) -> isize {
    if RAW_FDS.lock().remove(&fd).is_some() {
        0
    } else {
        -9
    }
}

pub fn path_of_raw(fd: usize) -> Option<String> {
    RAW_FDS.lock().get(&fd).and_then(|r| {
        if r.path.is_empty() {
            None
        } else {
            Some(r.path.clone())
        }
    })
}

pub fn read_raw(fd: usize, buf: &mut [u8]) -> isize {
    let (path, off, flags) = match RAW_FDS.lock().get(&fd) {
        Some(r) => (r.path.clone(), r.offset, r.flags),
        None => return -9,
    };
    if flags & O_ACCMODE == O_WRONLY {
        return -9;
    }
    let st = match crate::fs::vfs_ops::stat(&path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = lsm_ctx_for_stat(&st);
    if let Err(e) = crate::security::lsm::lsm_dispatch(crate::security::lsm::Hook::FileRead, &ctx) {
        return e as isize;
    }
    let data = match crate::fs::vfs_ops::read_all(&path) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let n = buf.len().min(data.len().saturating_sub(off));
    if n > 0 {
        buf[..n].copy_from_slice(&data[off..off + n]);
    }
    if let Some(r) = RAW_FDS.lock().get_mut(&fd) {
        r.offset = r.offset.saturating_add(n);
    }
    n as isize
}

pub fn write_raw(fd: usize, buf: &[u8]) -> isize {
    let (path, off, flags) = match RAW_FDS.lock().get(&fd) {
        Some(r) => (r.path.clone(), r.offset, r.flags),
        None => return -9,
    };
    match flags & O_ACCMODE {
        O_WRONLY | O_RDWR => {},
        _ => return -9,
    }
    let st = match crate::fs::vfs_ops::stat(&path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ctx = lsm_ctx_for_stat(&st);
    if let Err(e) = crate::security::lsm::lsm_dispatch(crate::security::lsm::Hook::FileWrite, &ctx)
    {
        return e as isize;
    }
    let mut data = crate::fs::vfs_ops::read_all(&path).unwrap_or_default();
    if off > data.len() {
        data.resize(off, 0);
    }
    if off + buf.len() > data.len() {
        data.resize(off + buf.len(), 0);
    }
    data[off..off + buf.len()].copy_from_slice(buf);
    if let Err(e) = crate::fs::vfs_ops::write_all(&path, &data) {
        return e;
    }
    if let Some(r) = RAW_FDS.lock().get_mut(&fd) {
        r.offset = r.offset.saturating_add(buf.len());
    }
    buf.len() as isize
}

pub fn size_of_raw(fd: usize) -> Option<usize> {
    let path = path_of_raw(fd)?;
    crate::fs::vfs_ops::stat(&path)
        .ok()
        .map(|s| s.size as usize)
}

pub fn dup_as_raw(old_fd: usize, new_fd: usize) -> isize {
    let raw = match RAW_FDS.lock().get(&old_fd).cloned() {
        Some(r) => r,
        None => return -9,
    };
    RAW_FDS.lock().insert(new_fd, raw);
    new_fd as isize
}

pub fn dup_from_raw(fd: usize, min_fd: usize) -> isize {
    let raw = match RAW_FDS.lock().get(&fd).cloned() {
        Some(r) => r,
        None => return -9,
    };
    let mut fds = RAW_FDS.lock();
    let new_fd =
        (min_fd.max(RAW_FD_BASE)..RAW_FD_END).find(|candidate| !fds.contains_key(candidate));
    match new_fd {
        Some(n) => {
            fds.insert(n, raw);
            n as isize
        },
        None => -24,
    }
}

pub fn seek_raw(fd: usize, offset: i64, whence: i32) -> isize {
    let (path, cur) = match RAW_FDS.lock().get(&fd) {
        Some(r) => (r.path.clone(), r.offset as i64),
        None => return -9,
    };
    let size = crate::fs::vfs_ops::stat(&path)
        .map(|s| s.size as i64)
        .unwrap_or(0);
    let new = match whence {
        SEEK_SET => offset,
        SEEK_CUR => cur + offset,
        SEEK_END => size + offset,
        _ => return -22,
    };
    if new < 0 {
        return -22;
    }
    if let Some(r) = RAW_FDS.lock().get_mut(&fd) {
        r.offset = new as usize;
    }
    new as isize
}

// These are thin forwarders into the raw fd table for backing fds.
pub fn read(fd: usize, buf: &mut [u8]) -> isize {
    read_raw(fd, buf)
}

pub fn write(fd: usize, buf: &[u8]) -> isize {
    write_raw(fd, buf)
}

pub fn open(path: &str, flags: u32) -> Result<usize, isize> {
    open_raw(path, flags)
}

pub fn close(fd: usize) -> isize {
    close_raw(fd)
}

pub fn seek(fd: usize, offset: i64, whence: i32) -> isize {
    seek_raw(fd, offset, whence)
}

/// POSIX-facing lseek wrapper.  `fd` is process-local and is translated to the
/// kernel backing fd before the raw seek is performed.
pub fn lseek(fd: usize, offset: i64, whence: i32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let bfd = match crate::fs::process_fd::proc_fd_backing(pid, fd) {
        n if n < 0 => return n,
        n => n as usize,
    };
    seek_raw(bfd, offset, whence)
}

pub fn file_size(fd: usize) -> Option<usize> {
    crate::fs::fcntl::fd_size(fd)
}

pub fn fd_to_path(fd: usize) -> Option<String> {
    crate::fs::fcntl::fd_get_path(fd)
}

#[inline(always)]
pub fn fd_path(fd: usize) -> Option<String> {
    crate::fs::fcntl::fd_get_path(fd)
}

pub fn fd_set_debug_name(fd: usize, name: String) {
    crate::fs::fcntl::fd_set_debug_name(fd, name);
}

pub fn fd_get_debug_name(fd: usize) -> Option<String> {
    crate::fs::fcntl::fd_get_debug_name(fd)
}

pub fn dup_as(old_fd: usize, new_fd: usize) -> isize {
    dup_as_raw(old_fd, new_fd)
}

pub fn dup_from(fd: usize, min_fd: usize) -> isize {
    dup_from_raw(fd, min_fd)
}

pub fn create(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::create(path)
}

pub fn unlink(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::unlink(path)
}

pub fn link(old: &str, new: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::link(old, new)
}

pub fn rmdir(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::rmdir(path)
}

pub fn stat(path: &str) -> Option<VfsStat> {
    crate::fs::vfs_ops::stat(path).ok().map(|s| VfsStat {
        ino: s.ino,
        mode: s.mode,
        nlink: s.nlink as u64,
        size: s.size,
        is_dir: s.is_dir,
    })
}

pub fn inode_id_of_fd(fd: usize) -> Option<u64> {
    let path = crate::fs::fcntl::fd_get_path(fd)?;
    let st = crate::fs::vfs_ops::stat(&path).ok()?;
    Some(st.ino)
}

pub fn flush_fd(fd: usize, include_metadata: bool) -> isize {
    let path = match crate::fs::fcntl::fd_get_path(fd) {
        Some(p) => p,
        None => return -9,
    };

    let h = match crate::fs::mount::resolve(&path) {
        Ok(h) => h,
        Err(e) => return e,
    };

    use crate::fs::mount::FsType;
    match h.fstype {
        FsType::Ext2 => {
            let _ = include_metadata;
            crate::fs::ext2::sync_inode(&path);
            0
        },
        _ => 0,
    }
}

pub fn flush_all_dirty() {
    const MAX_FD: usize = 256;
    for fd in 0..MAX_FD {
        let _ = flush_fd(fd, true);
    }
}

pub struct InodeMeta {
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub(crate) _path: String,
}

pub fn with_inode_mut<F>(path: &str, f: F)
where
    F: FnOnce(&mut InodeMeta),
{
    let st = match crate::fs::vfs_ops::stat(path) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut meta = InodeMeta {
        atime_ns: st.atime,
        mtime_ns: st.mtime,
        _path: alloc::string::ToString::to_string(path),
    };

    f(&mut meta);
    let _ = crate::fs::vfs_ops::utimens(path, meta.atime_ns, meta.mtime_ns);
}

pub fn pread(fd: usize, buf: *mut u8, len: usize, offset: i64) -> isize {
    if len == 0 {
        return 0;
    }

    let saved = seek(fd, 0, SEEK_CUR);
    if saved < 0 {
        return saved;
    }

    let seeked = seek(fd, offset, SEEK_SET);
    if seeked < 0 {
        seek(fd, saved, SEEK_SET);
        return seeked;
    }

    let kbuf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let n = read(fd, kbuf);
    seek(fd, saved, SEEK_SET);
    n
}

pub fn pwrite(fd: usize, buf: *const u8, len: usize, offset: i64) -> isize {
    if len == 0 {
        return 0;
    }

    let saved = seek(fd, 0, SEEK_CUR);
    if saved < 0 {
        return saved;
    }

    let seeked = seek(fd, offset, SEEK_SET);
    if seeked < 0 {
        seek(fd, saved, SEEK_SET);
        return seeked;
    }

    let kbuf = unsafe { core::slice::from_raw_parts(buf, len) };
    let n = write(fd, kbuf);
    seek(fd, saved, SEEK_SET);
    n
}
