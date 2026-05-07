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
//! ## Event mask constants (IN_*) — match Linux uapi/linux/inotify.h
//!   Callers typically combine these with OR.
//!
//! ## inotify_event wire format (read(2) output)
//!   struct inotify_event {
//!       i32  wd;       // watch descriptor
//!       u32  mask;     // event mask
//!       u32  cookie;   // rename cookie (0 if not rename)
//!       u32  len;      // length of name[] incl. NUL and padding
//!       char name[];   // optional NUL-padded name (only for dir watches)
//!   };
//!   Total size = 16 + len.  len is always a multiple of 4 (aligned).
//!
//! ## Kernel-side event delivery
//!   Other fs operations (vfs::create, vfs::unlink, vfs::write, etc.) call
//!   inotify_emit(path, mask) after completing successfully.  This function
//!   scans all active watches and enqueues inotify_event records on every
//!   matching inotify instance.
//!
//! ## poll/select readiness
//!   POLLIN when the event queue is non-empty.

extern crate alloc;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;

// ─── Public event mask constants ────────────────────────────────────────────

pub const IN_ACCESS:        u32 = 0x0000_0001;
pub const IN_MODIFY:        u32 = 0x0000_0002;
pub const IN_ATTRIB:        u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE:   u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_CLOSE:         u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
pub const IN_OPEN:          u32 = 0x0000_0020;
pub const IN_MOVED_FROM:    u32 = 0x0000_0040;
pub const IN_MOVED_TO:      u32 = 0x0000_0080;
pub const IN_MOVE:          u32 = IN_MOVED_FROM | IN_MOVED_TO;
pub const IN_CREATE:        u32 = 0x0000_0100;
pub const IN_DELETE:        u32 = 0x0000_0200;
pub const IN_DELETE_SELF:   u32 = 0x0000_0400;
pub const IN_MOVE_SELF:     u32 = 0x0000_0800;
pub const IN_UNMOUNT:       u32 = 0x0000_2000;
pub const IN_Q_OVERFLOW:    u32 = 0x0000_4000;
pub const IN_IGNORED:       u32 = 0x0000_8000;
pub const IN_ONLYDIR:       u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW:   u32 = 0x0200_0000;
pub const IN_EXCL_UNLINK:   u32 = 0x0400_0000;
pub const IN_MASK_CREATE:   u32 = 0x1000_0000;
pub const IN_MASK_ADD:      u32 = 0x2000_0000;
pub const IN_ISDIR:         u32 = 0x4000_0000;
pub const IN_ONESHOT:       u32 = 0x8000_0000;
pub const IN_ALL_EVENTS:    u32 = 0x0000_0FFF;

// inotify_init1 flags
pub const IN_CLOEXEC:  u32 = 0x0008_0000; // O_CLOEXEC
pub const IN_NONBLOCK: u32 = 0x0000_0800; // O_NONBLOCK

// Maximum queued events per instance before IN_Q_OVERFLOW is emitted.
const MAX_QUEUE: usize = 16384;

// ─── fd base ────────────────────────────────────────────────────────────────

pub const INOTIFY_FD_BASE: usize = 0x8000_0000;

// ─── Internal structures ─────────────────────────────────────────────────────

/// A single queued event ready to be read by userspace.
struct QueuedEvent {
    wd:     i32,
    mask:   u32,
    cookie: u32,
    name:   Option<String>,
}

/// A single watch inside an inotify instance.
struct Watch {
    path:    String,
    mask:    u32,
    wd:      i32,
    oneshot: bool,
}

/// One inotify instance (one fd).
struct InotifyInstance {
    nonblock:   bool,
    queue:      Vec<QueuedEvent>,
    watches:    Vec<Watch>,
    next_wd:    i32,
}

static TABLE: Mutex<BTreeMap<usize, InotifyInstance>> =
    Mutex::new(BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// ─── Syscall implementations ────────────────────────────────────────────────

/// inotify_init1(flags)  [NR 294]
/// inotify_init()  [NR 253]  — call with flags = 0
pub fn sys_inotify_init1(flags: u32) -> isize {
    let id   = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let fdno = INOTIFY_FD_BASE + id;
    let nonblock = flags & IN_NONBLOCK != 0;
    TABLE.lock().insert(fdno, InotifyInstance {
        nonblock,
        queue:    Vec::new(),
        watches:  Vec::new(),
        next_wd:  1,
    });
    if flags & IN_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fdno, true);
    }
    fdno as isize
}

/// inotify_add_watch(fd, path_va, mask)  [NR 254]
/// Returns watch descriptor (wd >= 1) or -errno.
pub fn sys_inotify_add_watch(fdno: usize, path_va: usize, mask: u32) -> isize {
    let path = match crate::proc::exec::read_cstr_safe(path_va) {
        Some(p) => p,
        None    => return -14, // EFAULT
    };
    let mut tbl = TABLE.lock();
    let inst = match tbl.get_mut(&fdno) {
        Some(i) => i,
        None    => return -9, // EBADF
    };
    // If a watch for this path already exists, update its mask.
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
    // New watch.
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

/// inotify_rm_watch(fd, wd)  [NR 255]
pub fn sys_inotify_rm_watch(fdno: usize, wd: i32) -> isize {
    let mut tbl = TABLE.lock();
    let inst = match tbl.get_mut(&fdno) {
        Some(i) => i,
        None    => return -9, // EBADF
    };
    let before = inst.watches.len();
    inst.watches.retain(|w| w.wd != wd);
    if inst.watches.len() == before {
        return -22; // EINVAL — wd not found
    }
    // Enqueue IN_IGNORED to notify userspace the watch was removed.
    if inst.queue.len() < MAX_QUEUE {
        inst.queue.push(QueuedEvent { wd, mask: IN_IGNORED, cookie: 0, name: None });
    }
    0
}

// ─── read — dequeue inotify_event records ───────────────────────────────────

/// Dequeue events into `buf`, encoding as packed inotify_event structs.
/// Returns the number of bytes written, or -EAGAIN / -EINVAL.
pub fn inotify_read(fdno: usize, buf: &mut [u8]) -> isize {
    const HDR: usize = 16; // sizeof(inotify_event) without name[]
    if buf.len() < HDR { return -22; } // EINVAL
    let deadline = crate::time::monotonic_ns() + 5_000_000_000;
    loop {
        {
            let mut tbl = TABLE.lock();
            let inst = match tbl.get_mut(&fdno) {
                Some(i) => i,
                None    => return -9,
            };
            if !inst.queue.is_empty() {
                let mut written = 0usize;
                while let Some(ev) = inst.queue.first() {
                    // Compute len: 0 if no name, else align4(name_bytes + 1).
                    let name_bytes = ev.name.as_ref().map(|n| n.as_bytes()).unwrap_or(&[]);
                    let len: u32 = if name_bytes.is_empty() { 0 } else {
                        ((name_bytes.len() + 1 + 3) & !3) as u32
                    };
                    let rec = HDR + len as usize;
                    if written + rec > buf.len() { break; }
                    let b = &mut buf[written..];
                    b[0..4].copy_from_slice(&ev.wd.to_le_bytes());
                    b[4..8].copy_from_slice(&ev.mask.to_le_bytes());
                    b[8..12].copy_from_slice(&ev.cookie.to_le_bytes());
                    b[12..16].copy_from_slice(&len.to_le_bytes());
                    if len > 0 {
                        let nl = name_bytes.len();
                        b[16..16 + nl].copy_from_slice(name_bytes);
                        // zero padding already zero (kbuf was zeroed by caller)
                    }
                    written += rec;
                    inst.queue.remove(0);
                }
                if written > 0 { return written as isize; }
            }
            if inst.nonblock { return -11; } // EAGAIN
        }
        if crate::time::monotonic_ns() >= deadline { return -11; }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

// ─── close ──────────────────────────────────────────────────────────────────

pub fn inotify_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

// ─── Predicate ──────────────────────────────────────────────────────────────

pub fn is_inotify_fd(fdno: usize) -> bool {
    fdno >= INOTIFY_FD_BASE && TABLE.lock().contains_key(&fdno)
}

// ─── poll readiness ──────────────────────────────────────────────────────────

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
        }
    }
}

// ─── Kernel-internal event emission ─────────────────────────────────────────
//
// Called by vfs write/create/unlink/rename paths after a successful operation.
// Scans every inotify instance for watches matching `path`, and enqueues the
// appropriate event if the watch's mask covers it.
//
// `path`   — absolute path of the affected file/directory
// `mask`   — one of the IN_* event bits (single event per call)
// `cookie` — non-zero only for IN_MOVED_FROM / IN_MOVED_TO pairs
// `name`   — leaf name to embed in the event (None for self-events)

pub fn inotify_emit(path: &str, mask: u32, cookie: u32, name: Option<&str>) {
    // Derive the parent directory of `path` for directory watches.
    let parent: &str = match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None    => "/",
    };
    let leaf = path.rfind('/')
        .map(|i| &path[i + 1..])
        .unwrap_or(path);

    let mut tbl = TABLE.lock();
    for inst in tbl.values_mut() {
        // Collect matching wd indices (avoid borrow-checker issues with retain later).
        let mut to_remove: Vec<i32> = Vec::new();
        for w in inst.watches.iter() {
            let watches_exact  = w.path == path;
            let watches_parent = w.path == parent;
            if !watches_exact && !watches_parent { continue; }
            if w.mask & mask == 0 { continue; }

            if inst.queue.len() >= MAX_QUEUE {
                // Overflow: emit IN_Q_OVERFLOW and stop filling.
                inst.queue.push(QueuedEvent {
                    wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: None,
                });
                break;
            }

            let event_name: Option<String> = if watches_parent {
                // Parent-dir watch: embed the leaf name.
                Some(name.unwrap_or(leaf).into())
            } else {
                // Exact-path watch: no name field.
                None
            };

            inst.queue.push(QueuedEvent {
                wd:     w.wd,
                mask:   mask | if watches_parent && is_directory(path) { IN_ISDIR } else { 0 },
                cookie,
                name:   event_name,
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

// Cheap heuristic: treat a path as a directory if it has no extension-like
// suffix and the ext2 layer confirms it, or fall back to false.
fn is_directory(path: &str) -> bool {
    crate::fs::ext2::stat(path)
        .map(|ino| crate::fs::ext2::is_dir(path))
        .unwrap_or(false)
}
