//! POSIX message queues (`<mqueue.h>`).
//!
//! ## API
//!
//!   mq_open(name, oflag, mode, attr)  -> mqd_t  (fd-like handle)
//!   mq_close(mqd)                     -> 0
//!   mq_unlink(name)                   -> 0
//!   mq_send(mqd, msg, len, prio)      -> 0
//!   mq_receive(mqd, buf, buflen, prio_out) -> ssize_t
//!   mq_getattr(mqd, attr)             -> 0
//!   mq_setattr(mqd, newattr, oldattr) -> 0
//!   mq_notify(mqd, sigev)             -> 0   [stub]
//!
//! ## Differences from SysV msg
//!
//! - Named: identified by a path-like name (e.g. `/myqueue`).
//! - Priority-ordered: messages are dequeued in descending priority order;
//!   same-priority messages are FIFO.
//! - Non-blocking I/O: controlled by `O_NONBLOCK` on the mqd.
//! - `mq_notify`: delivers a signal or spawns a thread on arrival.
//!   Currently a stub that records the notification request.
//!
//! ## Storage
//!
//! Messages are stored in a `BinaryHeap<PriMsg>` (max-heap by priority).
//! The queue is reference-counted: `mq_open` bumps a ref, `mq_close` drops
//! it; `mq_unlink` marks it for destruction but keeps it alive until the
//! last `mq_close`.

extern crate alloc;
use alloc::collections::BinaryHeap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::cmp::Ordering;
use spin::Mutex;
use alloc::collections::BTreeMap;

// ── O_* flags (match Linux) ──────────────────────────────────────────────────────────

pub const O_RDONLY:  i32 = 0;
pub const O_WRONLY:  i32 = 1;
pub const O_RDWR:    i32 = 2;
pub const O_CREAT:   i32 = 0o100;
pub const O_EXCL:    i32 = 0o200;
pub const O_NONBLOCK: i32 = 0o4000;
pub const O_CLOEXEC: i32 = 0o2000000;

// ── Limits ────────────────────────────────────────────────────────────────────────────

pub const MQ_MAXMSG:  usize = 10;    // default max messages in queue
pub const MQ_MSGSIZE: usize = 8192;  // default max message size
pub const MQ_PRIO_MAX: u32  = 32768; // max priority value

// ── struct mq_attr ───────────────────────────────────────────────────────────────────

/// `struct mq_attr` — matches Linux POSIX mqueue UAPI.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct MqAttr {
    pub mq_flags:   i64, // O_NONBLOCK state
    pub mq_maxmsg:  i64,
    pub mq_msgsize: i64,
    pub mq_curmsgs: i64,
    _pad: [u8; 16],
}

// ── Internal message ──────────────────────────────────────────────────────────────────

#[derive(Eq, PartialEq)]
struct PriMsg {
    prio: u32,
    seq:  u64,   // tie-breaker for FIFO within same priority
    data: Vec<u8>,
}

impl Ord for PriMsg {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap: higher priority first; lower seq first at same prio.
        other.prio.cmp(&self.prio)
            .then(self.seq.cmp(&other.seq))
            .reverse()
    }
}
impl PartialOrd for PriMsg {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

// ── Queue object ─────────────────────────────────────────────────────────────────────

struct MqInner {
    attr:       MqAttr,
    heap:       BinaryHeap<PriMsg>,
    seq:        u64,
    unlinked:   bool,
    /// Signal/thread notify request (mq_notify stub).
    notify_sig: Option<u32>,
    notify_pid: u32,
}

struct MqObject {
    name:  String,
    inner: Mutex<MqInner>,
    refs:  core::sync::atomic::AtomicUsize,
}

// ── Global name -> queue map ─────────────────────────────────────────────────────────

static QUEUES: Mutex<BTreeMap<String, Arc<MqObject>>> = Mutex::new(BTreeMap::new());
static NEXT_MQD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Open file descriptor table entry for an mq fd.
pub struct MqdEntry {
    pub id:       u64,
    pub oflag:    i32,
    queue:        Arc<MqObject>,
}

// Per-process table of open mqds (integration: fold into fd table).
static MQD_TABLE: Mutex<BTreeMap<u64, MqdEntry>> = Mutex::new(BTreeMap::new());

// ── mq_open ────────────────────────────────────────────────────────────────────────────

pub fn mq_open(
    name:  &str,
    oflag: i32,
    mode:  u32,
    attr:  Option<MqAttr>,
) -> Result<u64, isize> {
    if name.is_empty() || !name.starts_with('/') { return Err(-22); } // EINVAL
    let mut qs = QUEUES.lock();
    if let Some(obj) = qs.get(name) {
        if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 { return Err(-17); } // EEXIST
        if oflag & O_WRONLY != 0 || oflag & O_RDWR != 0 {
            // write/rdwr: check write perm (stub: always ok for single-user)
        }
        let arc = Arc::clone(obj);
        arc.refs.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        let mqd = alloc_mqd(arc, oflag);
        return Ok(mqd);
    }
    if oflag & O_CREAT == 0 { return Err(-2); } // ENOENT
    // Create new queue.
    let a = attr.unwrap_or(MqAttr {
        mq_flags:   0,
        mq_maxmsg:  MQ_MAXMSG as i64,
        mq_msgsize: MQ_MSGSIZE as i64,
        mq_curmsgs: 0,
        _pad: [0; 16],
    });
    if a.mq_maxmsg <= 0 || a.mq_msgsize <= 0 { return Err(-22); }
    let inner = MqInner {
        attr: a,
        heap: BinaryHeap::new(),
        seq:  0,
        unlinked: false,
        notify_sig: None,
        notify_pid: 0,
    };
    let obj = Arc::new(MqObject {
        name: name.into(),
        inner: Mutex::new(inner),
        refs:  core::sync::atomic::AtomicUsize::new(1),
    });
    qs.insert(name.into(), Arc::clone(&obj));
    let mqd = alloc_mqd(obj, oflag);
    Ok(mqd)
}

fn alloc_mqd(queue: Arc<MqObject>, oflag: i32) -> u64 {
    let id = NEXT_MQD.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    MQD_TABLE.lock().insert(id, MqdEntry { id, oflag, queue });
    id
}

// ── mq_close ────────────────────────────────────────────────────────────────────────────

pub fn mq_close(mqd: u64) -> Result<(), isize> {
    let entry = MQD_TABLE.lock().remove(&mqd).ok_or(-9isize)?; // EBADF
    let old = entry.queue.refs.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    if old == 1 {
        // Last reference: if unlinked, remove from global table.
        let name = entry.queue.name.clone();
        let unlinked = entry.queue.inner.lock().unlinked;
        if unlinked { QUEUES.lock().remove(&name); }
    }
    Ok(())
}

// ── mq_unlink ────────────────────────────────────────────────────────────────────────────

pub fn mq_unlink(name: &str) -> Result<(), isize> {
    let mut qs = QUEUES.lock();
    let obj = qs.get(name).ok_or(-2isize)?; // ENOENT
    obj.inner.lock().unlinked = true;
    // Remove from name table; object lives until last mq_close.
    qs.remove(name);
    Ok(())
}

// ── mq_send ────────────────────────────────────────────────────────────────────────────

pub fn mq_send(mqd: u64, data: Vec<u8>, prio: u32) -> Result<(), isize> {
    if prio >= MQ_PRIO_MAX { return Err(-22); }
    loop {
        let tbl = MQD_TABLE.lock();
        let entry = tbl.get(&mqd).ok_or(-9isize)?;
        if entry.oflag & O_RDONLY == 0 {} // write is allowed
        let mut inner = entry.queue.inner.lock();
        if data.len() > inner.attr.mq_msgsize as usize { return Err(-90); } // EMSGSIZE
        if inner.heap.len() as i64 >= inner.attr.mq_maxmsg {
            if entry.oflag & O_NONBLOCK != 0 { return Err(-11); } // EAGAIN
            drop(inner); drop(tbl);
            core::hint::spin_loop(); continue;
        }
        let seq = inner.seq; inner.seq += 1;
        inner.heap.push(PriMsg { prio, seq, data });
        inner.attr.mq_curmsgs += 1;
        // Deliver notification if registered and this is the first message.
        if inner.attr.mq_curmsgs == 1 {
            if let Some(sig) = inner.notify_sig.take() {
                let pid = inner.notify_pid;
                drop(inner); drop(tbl);
                // crate::proc::signal::send_to_pid(pid, sig);
                crate::serial_println!("[mq] notify signal {} -> pid {}", sig, pid);
                return Ok(());
            }
        }
        return Ok(());
    }
}

// ── mq_receive ───────────────────────────────────────────────────────────────────────────

/// Returns `(data, priority)` of the highest-priority message.
pub fn mq_receive(mqd: u64, buflen: usize) -> Result<(Vec<u8>, u32), isize> {
    loop {
        let tbl = MQD_TABLE.lock();
        let entry = tbl.get(&mqd).ok_or(-9isize)?;
        let mut inner = entry.queue.inner.lock();
        if inner.heap.is_empty() {
            if entry.oflag & O_NONBLOCK != 0 { return Err(-11); }
            drop(inner); drop(tbl);
            core::hint::spin_loop(); continue;
        }
        let msg = inner.heap.pop().unwrap();
        if msg.data.len() > buflen { return Err(-90); } // EMSGSIZE
        inner.attr.mq_curmsgs -= 1;
        return Ok((msg.data, msg.prio));
    }
}

// ── mq_getattr / mq_setattr ───────────────────────────────────────────────────────────

pub fn mq_getattr(mqd: u64) -> Result<MqAttr, isize> {
    let tbl = MQD_TABLE.lock();
    let entry = tbl.get(&mqd).ok_or(-9isize)?;
    let inner = entry.queue.inner.lock();
    let mut attr = inner.attr;
    attr.mq_flags = (entry.oflag & O_NONBLOCK) as i64;
    Ok(attr)
}

pub fn mq_setattr(mqd: u64, new_attr: MqAttr) -> Result<MqAttr, isize> {
    let tbl = MQD_TABLE.lock();
    let entry = tbl.get(&mqd).ok_or(-9isize)?;
    let mut inner = entry.queue.inner.lock();
    let old = inner.attr;
    // Only mq_flags (O_NONBLOCK) is settable via mq_setattr.
    // mq_maxmsg and mq_msgsize are immutable after creation.
    inner.attr.mq_flags = new_attr.mq_flags & O_NONBLOCK as i64;
    Ok(old)
}

// ── mq_notify (stub) ────────────────────────────────────────────────────────────────────

/// Register a signal notification for when the queue transitions from empty
/// to non-empty.  Pass `sig = 0` to deregister.
pub fn mq_notify(mqd: u64, sig: u32, pid: u32) -> Result<(), isize> {
    let tbl = MQD_TABLE.lock();
    let entry = tbl.get(&mqd).ok_or(-9isize)?;
    let mut inner = entry.queue.inner.lock();
    if sig == 0 {
        inner.notify_sig = None;
        inner.notify_pid = 0;
    } else {
        if inner.notify_sig.is_some() { return Err(-16); } // EBUSY
        inner.notify_sig = Some(sig);
        inner.notify_pid = pid;
    }
    Ok(())
}
