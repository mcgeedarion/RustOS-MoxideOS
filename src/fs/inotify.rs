//! inotify — filesystem event notification.
//!
//! ## Syscalls implemented
//!   inotify_init1  (NR 294)  — create an inotify fd
//!   inotify_init   (NR 253)  — inotify_init1(0) alias
//!   inotify_add_watch (NR 254) — add or update a watch descriptor
//!   inotify_rm_watch  (NR 255) — remove a watch descriptor
//!   read(fd, buf, n)          — dequeue inotify_event records
//!   close(fd)                 — destroy the instance
//!
//! ## Scheme integration
//!
//! `sys_inotify_init1` allocates a scheme backing fd via
//! `alloc_scheme_backing_fd` and registers an `InotifyScheme` in
//! `SCHEME_FD_STORE`.  The scheme backing fd is installed into the process
//! fd table; the raw TABLE entry is still inserted first.
//!
//! `sys_inotify_add_watch` and `sys_inotify_rm_watch` receive the scheme
//! backing fd and use `scheme_bfd_to_table_fdno` to recover the TABLE key.

extern crate alloc;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;

use crate::fs::scheme_table::Scheme;
use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

pub const IN_ACCESS: u32 = 0x0000_0001;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
pub const IN_OPEN: u32 = 0x0000_0020;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
pub const IN_UNMOUNT: u32 = 0x0000_2000;
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const IN_IGNORED: u32 = 0x0000_8000;
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub const IN_MASK_CREATE: u32 = 0x1000_0000;
pub const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ISDIR: u32 = 0x4000_0000;
pub const IN_ONESHOT: u32 = 0x8000_0000;
pub const IN_ALL_EVENTS: u32 = 0x0000_0FFF;

pub const IN_CLOEXEC: u32 = 0x0008_0000;
pub const IN_NONBLOCK: u32 = 0x0000_0800;

const MAX_QUEUE: usize = 16384;

pub const INOTIFY_FD_BASE: usize = 0x8000_0000;

struct QueuedEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Option<String>,
}

struct Watch {
    path: String,
    mask: u32,
    wd: i32,
    oneshot: bool,
}

struct InotifyInstance {
    nonblock: bool,
    queue: Vec<QueuedEvent>,
    watches: Vec<Watch>,
    next_wd: i32,
}

static TABLE: Mutex<BTreeMap<usize, InotifyInstance>> = Mutex::new(BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Translate a scheme backing fd to the inotify TABLE fdno.
pub fn scheme_bfd_to_table_fdno(scheme_bfd: usize) -> Option<usize> {
    let (_, fid) = crate::fs::scheme_fd::scheme_fd_get_fid(scheme_bfd)?;
    let table_fdno = fid.0 as usize;
    if table_fdno >= INOTIFY_FD_BASE && TABLE.lock().contains_key(&table_fdno) {
        Some(table_fdno)
    } else {
        None
    }
}

pub struct InotifyScheme;

impl Scheme for InotifyScheme {
    fn open(&self, _url: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let fdno = fid.0 as usize;
        let n = inotify_read(fdno, buf);
        if n < 0 {
            Err(SchemeError::Io)
        } else {
            Ok(n as usize)
        }
    }

    fn write(&self, _fid: SchemeFileId, _buf: &[u8]) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg) // inotify fds are not writable
    }

    fn seek(&self, _fid: SchemeFileId, _offset: i64, _whence: u8) -> Result<u64, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn ioctl(&self, _fid: SchemeFileId, _cmd: u64, _arg: usize) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        inotify_close(fid.0 as usize);
        Ok(())
    }
}

pub fn sys_inotify_init1(flags: u32) -> isize {
    use crate::fs::process_fd::proc_fd_install;
    use crate::fs::scheme_fd::{alloc_scheme_backing_fd, scheme_fd_register};
    use alloc::sync::Arc;

    let id = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let table_fdno = INOTIFY_FD_BASE + id;
    TABLE.lock().insert(
        table_fdno,
        InotifyInstance {
            nonblock: flags & IN_NONBLOCK != 0,
            queue: Vec::new(),
            watches: Vec::new(),
            next_wd: 1,
        },
    );

    let scheme: Arc<dyn Scheme> = Arc::new(InotifyScheme);
    let scheme_bfd = alloc_scheme_backing_fd();
    scheme_fd_register(scheme_bfd, scheme, SchemeFileId(table_fdno as u64));

    let pid = crate::proc::scheduler::current_pid();
    let install_flags = if flags & IN_CLOEXEC != 0 {
        IN_CLOEXEC
    } else {
        0
    };
    let user_fd = proc_fd_install(pid, scheme_bfd, None, install_flags, None);
    user_fd as isize
}

// Called with the scheme bfd (already resolved from user fd).

pub fn sys_inotify_add_watch(scheme_bfd: usize, path_va: usize, mask: u32) -> isize {
    let fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
        Some(f) => f,
        None => return -9, // EBADF
    };
    let path = match crate::proc::exec::read_cstr_safe(path_va) {
        Some(p) => p,
        None => return -14, // EFAULT
    };
    let mut tbl = TABLE.lock();
    let inst = match tbl.get_mut(&fdno) {
        Some(i) => i,
        None => return -9,
    };
    for w in inst.watches.iter_mut() {
        if w.path == path {
            if mask & IN_MASK_ADD != 0 {
                w.mask |= mask & IN_ALL_EVENTS;
            } else {
                w.mask = mask & IN_ALL_EVENTS;
            }
            w.oneshot = mask & IN_ONESHOT != 0;
            return w.wd as isize;
        }
    }
    let wd = inst.next_wd;
    inst.next_wd += 1;
    inst.watches.push(Watch {
        path,
        mask: mask & (IN_ALL_EVENTS | IN_ISDIR | IN_ONESHOT | IN_EXCL_UNLINK),
        wd,
        oneshot: mask & IN_ONESHOT != 0,
    });
    wd as isize
}

pub fn sys_inotify_rm_watch(scheme_bfd: usize, wd: i32) -> isize {
    let fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
        Some(f) => f,
        None => return -9,
    };
    let mut tbl = TABLE.lock();
    let inst = match tbl.get_mut(&fdno) {
        Some(i) => i,
        None => return -9,
    };
    let before = inst.watches.len();
    inst.watches.retain(|w| w.wd != wd);
    if inst.watches.len() == before {
        return -22;
    } // EINVAL
    if inst.queue.len() < MAX_QUEUE {
        inst.queue.push(QueuedEvent {
            wd,
            mask: IN_IGNORED,
            cookie: 0,
            name: None,
        });
    }
    0
}

pub fn inotify_read(fdno: usize, buf: &mut [u8]) -> isize {
    const HDR: usize = 16;
    if buf.len() < HDR {
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
                while let Some(ev) = inst.queue.first() {
                    let name_bytes = ev.name.as_ref().map(|n| n.as_bytes()).unwrap_or(&[]);
                    let len: u32 = if name_bytes.is_empty() {
                        0
                    } else {
                        ((name_bytes.len() + 1 + 3) & !3) as u32
                    };
                    let rec = HDR + len as usize;
                    if written + rec > buf.len() {
                        break;
                    }
                    let b = &mut buf[written..];
                    b[0..4].copy_from_slice(&ev.wd.to_le_bytes());
                    b[4..8].copy_from_slice(&ev.mask.to_le_bytes());
                    b[8..12].copy_from_slice(&ev.cookie.to_le_bytes());
                    b[12..16].copy_from_slice(&len.to_le_bytes());
                    if len > 0 {
                        let nl = name_bytes.len();
                        b[16..16 + nl].copy_from_slice(name_bytes);
                    }
                    written += rec;
                    inst.queue.remove(0);
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

pub fn inotify_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

pub fn is_inotify_fd(fdno: usize) -> bool {
    fdno >= INOTIFY_FD_BASE && TABLE.lock().contains_key(&fdno)
}

pub fn inotify_poll(fdno: usize, events: u32) -> u32 {
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

pub fn inotify_emit(path: &str, mask: u32, cookie: u32, name: Option<&str>) {
    let parent: &str = match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => "/",
    };
    let leaf = path.rfind('/').map(|i| &path[i + 1..]).unwrap_or(path);

    let mut tbl = TABLE.lock();
    for inst in tbl.values_mut() {
        let mut to_remove: Vec<i32> = Vec::new();
        for w in inst.watches.iter() {
            let watches_exact = w.path == path;
            let watches_parent = w.path == parent;
            if !watches_exact && !watches_parent {
                continue;
            }
            if w.mask & mask == 0 {
                continue;
            }
            if inst.queue.len() >= MAX_QUEUE {
                inst.queue.push(QueuedEvent {
                    wd: -1,
                    mask: IN_Q_OVERFLOW,
                    cookie: 0,
                    name: None,
                });
                break;
            }
            let event_name: Option<String> = if watches_parent {
                Some(name.unwrap_or(leaf).into())
            } else {
                None
            };
            inst.queue.push(QueuedEvent {
                wd: w.wd,
                mask: mask
                    | if watches_parent && is_directory(path) {
                        IN_ISDIR
                    } else {
                        0
                    },
                cookie,
                name: event_name,
            });
            if w.oneshot {
                to_remove.push(w.wd);
            }
        }
        for wd in to_remove {
            inst.watches.retain(|w| w.wd != wd);
        }
    }
}

fn is_directory(path: &str) -> bool {
    crate::fs::ext2::stat(path)
        .map(|_ino| crate::fs::ext2::is_dir(path))
        .unwrap_or(false)
}
