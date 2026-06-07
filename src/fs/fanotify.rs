//! fanotify — file access notification (NR 300 / 301 / 302).
//!
//! ## Syscalls implemented
//!   fanotify_init  (NR 300) — create a fanotify fd
//!   fanotify_mark  (NR 301) — add/remove/flush marks
//!   read(fd, buf)           — dequeue fanotify_event_metadata records
//!   write(fd, buf)          — permission response (FAN_ACCESS_PERM etc.)
//!   close(fd)               — destroy the instance
//!
//! ## Scheme integration
//!
//! `sys_fanotify_init` allocates a scheme backing fd via
//! `alloc_scheme_backing_fd` and registers a `FanotifyScheme` in
//! `SCHEME_FD_STORE`.  The scheme backing fd is installed into the process
//! fd table; the raw TABLE entry is still inserted first.
//!
//! `sys_fanotify_mark` receives the scheme backing fd and uses
//! `scheme_bfd_to_table_fdno` to recover the TABLE key.

extern crate alloc;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;

use crate::fs::scheme_table::Scheme;
use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
pub const FAN_CLOEXEC: u32 = 0x0000_0001;
pub const FAN_NONBLOCK: u32 = 0x0000_0002;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
pub const FAN_REPORT_TID: u32 = 0x0000_0100;
pub const FAN_REPORT_FID: u32 = 0x0000_0200;
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;

pub const FAN_MARK_ADD: u32 = 0x0000_0001;
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
pub const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
pub const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;
pub const FAN_MARK_INODE: u32 = 0x0000_0000;
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

pub const FAN_ACCESS: u64 = 0x0000_0001;
pub const FAN_MODIFY: u64 = 0x0000_0002;
pub const FAN_ATTRIB: u64 = 0x0000_0004;
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
pub const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
pub const FAN_OPEN: u64 = 0x0000_0020;
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
pub const FAN_MOVE: u64 = FAN_MOVED_FROM | FAN_MOVED_TO;
pub const FAN_CREATE: u64 = 0x0000_0100;
pub const FAN_DELETE: u64 = 0x0000_0200;
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
pub const FAN_ONDIR: u64 = 0x4000_0000;
pub const FAN_ALL_EVENTS: u64 = FAN_ACCESS
    | FAN_MODIFY
    | FAN_CLOSE
    | FAN_OPEN
    | FAN_MOVE
    | FAN_CREATE
    | FAN_DELETE
    | FAN_DELETE_SELF
    | FAN_MOVE_SELF;

pub const FAN_ALLOW: u32 = 1;
pub const FAN_DENY: u32 = 2;

pub const FAN_EVENT_METADATA_LEN: usize = 24;
pub const FAN_EVENT_METADATA_VERSION: u8 = 3;
pub const FAN_NOFD: i32 = -1;

pub const FANOTIFY_FD_BASE: usize = 0x8800_0000;

struct QueuedEvent {
    mask: u64,
    pid: i32,
}

struct Mark {
    path: String,
    mask: u64,
    ignored: u64,
    mount_wide: bool,
}

struct FanotifyInstance {
    class: u32,
    flags: u32,
    nonblock: bool,
    queue: Vec<QueuedEvent>,
    marks: Vec<Mark>,
    refs: usize,
}

const MAX_QUEUE: usize = 16384;

static TABLE: Mutex<BTreeMap<usize, FanotifyInstance>> = Mutex::new(BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Translate a scheme backing fd to the fanotify TABLE fdno.
pub fn scheme_bfd_to_table_fdno(scheme_bfd: usize) -> Option<usize> {
    let (_, fid) = crate::fs::scheme_fd::scheme_fd_get_fid(scheme_bfd)?;
    let table_fdno = fid.0 as usize;
    if table_fdno >= FANOTIFY_FD_BASE && TABLE.lock().contains_key(&table_fdno) {
        Some(table_fdno)
    } else {
        None
    }
}

pub struct FanotifyScheme;

impl Scheme for FanotifyScheme {
    fn open(&self, _url: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let fdno = fid.0 as usize;
        let n = fanotify_read(fdno, buf);
        if n < 0 {
            Err(SchemeError::Io)
        } else {
            Ok(n as usize)
        }
    }

    /// Permission response write (struct fanotify_response).
    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let fdno = fid.0 as usize;
        let n = fanotify_write(fdno, buf);
        if n < 0 {
            Err(SchemeError::Io)
        } else {
            Ok(n as usize)
        }
    }

    fn seek(&self, _fid: SchemeFileId, _offset: i64, _whence: u8) -> Result<u64, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn ioctl(&self, _fid: SchemeFileId, _cmd: u64, _arg: usize) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        fanotify_close(fid.0 as usize);
        Ok(())
    }
}

pub fn sys_fanotify_init(flags: u32, _event_f_flags: u32) -> isize {
    use crate::fs::process_fd::proc_fd_install;
    use crate::fs::scheme_fd::{alloc_scheme_backing_fd, scheme_fd_register};
    use alloc::sync::Arc;

    let id = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let table_fdno = FANOTIFY_FD_BASE + id;
    let nonblock = flags & FAN_NONBLOCK != 0;
    let class = flags & (FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT);
    TABLE.lock().insert(
        table_fdno,
        FanotifyInstance {
            class,
            flags,
            nonblock,
            queue: Vec::new(),
            marks: Vec::new(),
            refs: 1,
        },
    );

    let scheme: Arc<dyn Scheme> = Arc::new(FanotifyScheme);
    let scheme_bfd = alloc_scheme_backing_fd();
    scheme_fd_register(scheme_bfd, scheme, SchemeFileId(table_fdno as u64));

    let pid = crate::proc::scheduler::current_pid();
    let install_flags = if flags & FAN_CLOEXEC != 0 {
        FAN_CLOEXEC
    } else {
        0
    };
    let user_fd = proc_fd_install(pid, scheme_bfd, None, install_flags, None);
    user_fd as isize
}

// Called with the scheme bfd (already resolved from user fd).

pub fn sys_fanotify_mark(
    scheme_bfd: usize,
    flags: u32,
    mask: u64,
    _dirfd: i32,
    path_va: usize,
) -> isize {
    if flags & FAN_MARK_FLUSH != 0 {
        let fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
            Some(f) => f,
            None => return -9,
        };
        let mut tbl = TABLE.lock();
        if let Some(inst) = tbl.get_mut(&fdno) {
            inst.marks.clear();
        }
        return 0;
    }

    let path = if path_va != 0 {
        match crate::proc::exec::read_cstr_safe(path_va) {
            Some(p) => p,
            None => return -14,
        }
    } else {
        String::from("/")
    };

    let fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
        Some(f) => f,
        None => return -9,
    };
    let mut tbl = TABLE.lock();
    let inst = match tbl.get_mut(&fdno) {
        Some(i) => i,
        None => return -9,
    };

    if flags & FAN_MARK_REMOVE != 0 {
        inst.marks.retain(|m| m.path != path);
        return 0;
    }

    if flags & FAN_MARK_ADD != 0 {
        let mount_wide = flags & FAN_MARK_MOUNT != 0 || flags & FAN_MARK_FILESYSTEM != 0;
        for m in inst.marks.iter_mut() {
            if m.path == path {
                if flags & FAN_MARK_IGNORED_MASK != 0 {
                    m.ignored |= mask;
                } else {
                    m.mask |= mask;
                }
                return 0;
            }
        }
        if flags & FAN_MARK_IGNORED_MASK != 0 {
            inst.marks.push(Mark {
                path,
                mask: 0,
                ignored: mask,
                mount_wide,
            });
        } else {
            inst.marks.push(Mark {
                path,
                mask,
                ignored: 0,
                mount_wide,
            });
        }
    }
    0
}

pub fn fanotify_read(fdno: usize, buf: &mut [u8]) -> isize {
    if buf.len() < FAN_EVENT_METADATA_LEN {
        return -22;
    }
    let deadline = crate::time::monotonic_ns() + 5_000_000_000;
    loop {
        {
            let mut tbl = TABLE.lock();
            let inst = match tbl.get_mut(&fdno) {
                Some(i) => i,
                None => return -9,
            };
            if !inst.queue.is_empty() {
                let mut written = 0usize;
                while !inst.queue.is_empty() {
                    if written + FAN_EVENT_METADATA_LEN > buf.len() {
                        break;
                    }
                    let ev = inst.queue.remove(0);
                    let b = &mut buf[written..];
                    b[0..4].copy_from_slice(&(FAN_EVENT_METADATA_LEN as u32).to_le_bytes());
                    b[4] = FAN_EVENT_METADATA_VERSION;
                    b[5] = 0;
                    b[6..8].copy_from_slice(&(FAN_EVENT_METADATA_LEN as u16).to_le_bytes());
                    b[8..16].copy_from_slice(&ev.mask.to_le_bytes());
                    b[16..20].copy_from_slice(&FAN_NOFD.to_le_bytes());
                    b[20..24].copy_from_slice(&ev.pid.to_le_bytes());
                    written += FAN_EVENT_METADATA_LEN;
                }
                if written > 0 {
                    return written as isize;
                }
            }
            if inst.nonblock {
                return -11;
            }
        }
        if crate::time::monotonic_ns() >= deadline {
            return -11;
        }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

pub fn fanotify_write(fdno: usize, buf: &[u8]) -> isize {
    if buf.len() < 8 {
        return -22;
    }
    if TABLE.lock().contains_key(&fdno) {
        8
    } else {
        -9
    }
}

pub fn fanotify_close(fdno: usize) {
    let mut table = TABLE.lock();
    if let Some(entry) = table.get_mut(&fdno) {
        if entry.refs > 1 {
            entry.refs -= 1;
            return;
        }
    }
    table.remove(&fdno);
}

/// Compatibility close hook used by generic fd lifecycle code.
pub fn sys_close_fanotify(fdno: usize) {
    if crate::fs::scheme_fd::is_scheme_fd(fdno) {
        crate::fs::scheme_fd::scheme_fd_close(fdno);
    } else {
        fanotify_close(fdno);
    }
}

/// Duplicate hook for process-local fd aliases. Fanotify state is shared by the
/// backing fd.
pub fn fanotify_dup(fdno: usize) {
    if let Some(entry) = TABLE.lock().get_mut(&fdno) {
        entry.refs = entry.refs.saturating_add(1);
    }
}

pub fn is_fanotify_fd(fdno: usize) -> bool {
    fdno >= FANOTIFY_FD_BASE && TABLE.lock().contains_key(&fdno)
}

pub fn fanotify_poll(fdno: usize, events: u32) -> u32 {
    let tbl = TABLE.lock();
    match tbl.get(&fdno) {
        None => crate::fs::poll::POLLNVAL,
        Some(inst) => {
            if events & crate::fs::poll::POLLIN != 0 && !inst.queue.is_empty() {
                crate::fs::poll::POLLIN
            } else {
                0
            }
        },
    }
}

pub fn fanotify_emit(path: &str, mask: u64, pid: i32) {
    let mut tbl = TABLE.lock();
    for inst in tbl.values_mut() {
        let matches = inst.marks.iter().any(|m| {
            let path_match = if m.mount_wide {
                path.starts_with(m.path.as_str())
            } else {
                m.path == path
            };
            path_match && (m.mask & mask != 0) && (m.ignored & mask == 0)
        });
        if !matches {
            continue;
        }
        if inst.queue.len() >= MAX_QUEUE {
            continue;
        }
        inst.queue.push(QueuedEvent { mask, pid });
    }
}
