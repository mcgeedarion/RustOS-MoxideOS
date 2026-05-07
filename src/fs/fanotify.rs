//! fanotify — file access notification (NR 300 / 301 / 302).
//!
//! ## Syscalls implemented
//!   fanotify_init  (NR 300) — create a fanotify fd
//!   fanotify_mark  (NR 301) — add/remove/flush marks
//!   read(fd, buf)           — dequeue fanotify_event_metadata records
//!   write(fd, buf)          — permission response (FAN_ACCESS_PERM etc.)
//!   close(fd)               — destroy the instance
//!
//! ## fanotify_event_metadata wire format (read(2) output)
//!   struct fanotify_event_metadata {
//!       u32  event_len;     // total length of this record (always FAN_EVENT_METADATA_LEN)
//!       u8   vers;          // FAN_EVENT_METADATA_VERSION (3)
//!       u8   _reserved;     // 0
//!       u16  metadata_len;  // sizeof(fanotify_event_metadata) = 24
//!       u64  mask;          // event mask (FAN_*)
//!       i32  fd;            // open fd for the file (-1 if FAN_NOFD)
//!       i32  pid;           // pid that triggered the event
//!   };
//!   FAN_EVENT_METADATA_LEN = 24
//!
//! ## fanotify_response wire format (write(2) response for permission events)
//!   struct fanotify_response {
//!       i32  fd;
//!       u32  response;  // FAN_ALLOW (1) or FAN_DENY (2)
//!   };
//!
//! ## Permission events
//!   FAN_OPEN_PERM / FAN_ACCESS_PERM: the kernel delivers the event and
//!   the notifier process must write FAN_ALLOW or FAN_DENY back.  In this
//!   implementation permission events always auto-allow because we have no
//!   blocking mechanism between VFS calls and userspace; the fd is set to -1.
//!
//! ## Integration
//!   VFS paths call fanotify_emit() the same way as inotify_emit().
//!   fanotify_mark() watches are matched by mount-point prefix or exact path
//!   depending on FAN_MARK_MOUNT vs FAN_MARK_INODE.

extern crate alloc;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;

// ─── fanotify_init flags ─────────────────────────────────────────────────────

pub const FAN_CLASS_NOTIF:      u32 = 0x0000_0000;
pub const FAN_CLASS_CONTENT:    u32 = 0x0000_0004;
pub const FAN_CLASS_PRE_CONTENT:u32 = 0x0000_0008;
pub const FAN_CLOEXEC:          u32 = 0x0000_0001;
pub const FAN_NONBLOCK:         u32 = 0x0000_0002;
pub const FAN_UNLIMITED_QUEUE:  u32 = 0x0000_0010;
pub const FAN_UNLIMITED_MARKS:  u32 = 0x0000_0020;
pub const FAN_REPORT_TID:       u32 = 0x0000_0100;
pub const FAN_REPORT_FID:       u32 = 0x0000_0200;
pub const FAN_REPORT_DIR_FID:   u32 = 0x0000_0400;
pub const FAN_REPORT_NAME:      u32 = 0x0000_0800;

// ─── fanotify_mark flags ─────────────────────────────────────────────────────

pub const FAN_MARK_ADD:         u32 = 0x0000_0001;
pub const FAN_MARK_REMOVE:      u32 = 0x0000_0002;
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
pub const FAN_MARK_ONLYDIR:     u32 = 0x0000_0008;
pub const FAN_MARK_MOUNT:       u32 = 0x0000_0010;
pub const FAN_MARK_IGNORED_MASK:u32 = 0x0000_0020;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
pub const FAN_MARK_FLUSH:       u32 = 0x0000_0080;
pub const FAN_MARK_INODE:       u32 = 0x0000_0000; // default
pub const FAN_MARK_FILESYSTEM:  u32 = 0x0000_0100;

// ─── fanotify event mask bits ────────────────────────────────────────────────

pub const FAN_ACCESS:           u64 = 0x0000_0001;
pub const FAN_MODIFY:           u64 = 0x0000_0002;
pub const FAN_ATTRIB:           u64 = 0x0000_0004;
pub const FAN_CLOSE_WRITE:      u64 = 0x0000_0008;
pub const FAN_CLOSE_NOWRITE:    u64 = 0x0000_0010;
pub const FAN_CLOSE:            u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
pub const FAN_OPEN:             u64 = 0x0000_0020;
pub const FAN_MOVED_FROM:       u64 = 0x0000_0040;
pub const FAN_MOVED_TO:         u64 = 0x0000_0080;
pub const FAN_MOVE:             u64 = FAN_MOVED_FROM | FAN_MOVED_TO;
pub const FAN_CREATE:           u64 = 0x0000_0100;
pub const FAN_DELETE:           u64 = 0x0000_0200;
pub const FAN_DELETE_SELF:      u64 = 0x0000_0400;
pub const FAN_MOVE_SELF:        u64 = 0x0000_0800;
pub const FAN_OPEN_PERM:        u64 = 0x0001_0000;
pub const FAN_ACCESS_PERM:      u64 = 0x0002_0000;
pub const FAN_OPEN_EXEC:        u64 = 0x0000_1000;
pub const FAN_OPEN_EXEC_PERM:   u64 = 0x0004_0000;
pub const FAN_EVENT_ON_CHILD:   u64 = 0x0800_0000;
pub const FAN_ONDIR:            u64 = 0x4000_0000;
pub const FAN_ALL_EVENTS:       u64 = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE
    | FAN_OPEN | FAN_MOVE | FAN_CREATE | FAN_DELETE
    | FAN_DELETE_SELF | FAN_MOVE_SELF;

// ─── fanotify_response values ────────────────────────────────────────────────

pub const FAN_ALLOW: u32 = 1;
pub const FAN_DENY:  u32 = 2;

// ─── Wire format constants ───────────────────────────────────────────────────

pub const FAN_EVENT_METADATA_LEN: usize = 24;
pub const FAN_EVENT_METADATA_VERSION: u8 = 3;
pub const FAN_NOFD: i32 = -1;

// ─── fd base ─────────────────────────────────────────────────────────────────

pub const FANOTIFY_FD_BASE: usize = 0x8800_0000;

// ─── Internal structures ──────────────────────────────────────────────────────

struct QueuedEvent {
    mask: u64,
    pid:  i32,
    // fd field: we always use FAN_NOFD (-1); opening a live fd per event
    // would require a complete VFS dup here and is deferred for later.
}

struct Mark {
    path:       String,
    mask:       u64,
    ignored:    u64,
    mount_wide: bool,
}

struct FanotifyInstance {
    class:     u32,
    flags:     u32,
    nonblock:  bool,
    queue:     Vec<QueuedEvent>,
    marks:     Vec<Mark>,
}

const MAX_QUEUE: usize = 16384;

static TABLE: Mutex<BTreeMap<usize, FanotifyInstance>> =
    Mutex::new(BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// ─── Syscall implementations ──────────────────────────────────────────────────

/// fanotify_init(flags, event_f_flags)  [NR 300]
pub fn sys_fanotify_init(flags: u32, _event_f_flags: u32) -> isize {
    let id   = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let fdno = FANOTIFY_FD_BASE + id;
    let nonblock = flags & FAN_NONBLOCK != 0;
    let class = flags & (FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT);
    TABLE.lock().insert(fdno, FanotifyInstance {
        class,
        flags,
        nonblock,
        queue: Vec::new(),
        marks: Vec::new(),
    });
    if flags & FAN_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fdno, true);
    }
    fdno as isize
}

/// fanotify_mark(fanotify_fd, flags, mask, dirfd, path_va)  [NR 301]
///
/// `dirfd` is accepted but only AT_FDCWD semantics are emulated
/// (we always resolve relative to root since we have no cwd abstraction here).
pub fn sys_fanotify_mark(
    fdno:     usize,
    flags:    u32,
    mask:     u64,
    _dirfd:   i32,
    path_va:  usize,
) -> isize {
    // FAN_MARK_FLUSH: remove all marks.
    if flags & FAN_MARK_FLUSH != 0 {
        let mut tbl = TABLE.lock();
        if let Some(inst) = tbl.get_mut(&fdno) {
            inst.marks.clear();
        }
        return 0;
    }

    let path = if path_va != 0 {
        match crate::proc::exec::read_cstr_safe(path_va) {
            Some(p) => p,
            None    => return -14,
        }
    } else {
        String::from("/")
    };

    let mut tbl = TABLE.lock();
    let inst = match tbl.get_mut(&fdno) {
        Some(i) => i,
        None    => return -9,
    };

    if flags & FAN_MARK_REMOVE != 0 {
        // Remove matching marks.
        inst.marks.retain(|m| m.path != path);
        return 0;
    }

    if flags & FAN_MARK_ADD != 0 {
        let mount_wide = flags & FAN_MARK_MOUNT != 0
            || flags & FAN_MARK_FILESYSTEM != 0;
        // Update existing mark for this path.
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
        // New mark.
        if flags & FAN_MARK_IGNORED_MASK != 0 {
            inst.marks.push(Mark { path, mask: 0, ignored: mask, mount_wide });
        } else {
            inst.marks.push(Mark { path, mask, ignored: 0, mount_wide });
        }
    }
    0
}

// ─── read — dequeue fanotify_event_metadata records ──────────────────────────

pub fn fanotify_read(fdno: usize, buf: &mut [u8]) -> isize {
    if buf.len() < FAN_EVENT_METADATA_LEN { return -22; }
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
                while !inst.queue.is_empty() {
                    if written + FAN_EVENT_METADATA_LEN > buf.len() { break; }
                    let ev = inst.queue.remove(0);
                    let b = &mut buf[written..];
                    let event_len = FAN_EVENT_METADATA_LEN as u32;
                    b[0..4].copy_from_slice(&event_len.to_le_bytes());
                    b[4]   = FAN_EVENT_METADATA_VERSION;
                    b[5]   = 0;
                    let meta_len = FAN_EVENT_METADATA_LEN as u16;
                    b[6..8].copy_from_slice(&meta_len.to_le_bytes());
                    b[8..16].copy_from_slice(&ev.mask.to_le_bytes());
                    let fd_val: i32 = FAN_NOFD;
                    b[16..20].copy_from_slice(&fd_val.to_le_bytes());
                    b[20..24].copy_from_slice(&ev.pid.to_le_bytes());
                    written += FAN_EVENT_METADATA_LEN;
                }
                if written > 0 { return written as isize; }
            }
            if inst.nonblock { return -11; }
        }
        if crate::time::monotonic_ns() >= deadline { return -11; }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

// ─── write — permission response ─────────────────────────────────────────────
//
// Userspace writes struct fanotify_response { i32 fd; u32 response; }.
// We accept the write and always succeed (auto-allow semantics).

pub fn fanotify_write(fdno: usize, buf: &[u8]) -> isize {
    if buf.len() < 8 { return -22; }
    // We don't block on permission events, so there's nothing to unblock.
    // Just validate the fd is a real fanotify fd and return 8.
    if TABLE.lock().contains_key(&fdno) { 8 } else { -9 }
}

// ─── close ────────────────────────────────────────────────────────────────────

pub fn fanotify_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

// ─── Predicates ───────────────────────────────────────────────────────────────

pub fn is_fanotify_fd(fdno: usize) -> bool {
    fdno >= FANOTIFY_FD_BASE && TABLE.lock().contains_key(&fdno)
}

// ─── poll readiness ───────────────────────────────────────────────────────────

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
        }
    }
}

// ─── Kernel-internal event emission ──────────────────────────────────────────
//
// Called from VFS write/create/unlink/rename paths.
// `path` — absolute path, `mask` — single FAN_* bit, `pid` — originating pid.

pub fn fanotify_emit(path: &str, mask: u64, pid: i32) {
    let mut tbl = TABLE.lock();
    for inst in tbl.values_mut() {
        let matches = inst.marks.iter().any(|m| {
            // mount-wide: path starts with the mark path
            // inode: exact match
            let path_match = if m.mount_wide {
                path.starts_with(m.path.as_str())
            } else {
                m.path == path
            };
            path_match && (m.mask & mask != 0) && (m.ignored & mask == 0)
        });
        if !matches { continue; }
        if inst.queue.len() >= MAX_QUEUE { continue; }
        inst.queue.push(QueuedEvent { mask, pid });
    }
}
