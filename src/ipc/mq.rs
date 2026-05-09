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
//! ## RLIMIT_MSGQUEUE
//!
//! Linux charges both the queue metadata and each message's payload against
//! the process's `RLIMIT_MSGQUEUE` byte budget.  We replicate this:
//!
//!   mq_open(O_CREAT) — charges `QUEUE_OVERHEAD + mq_maxmsg * (MSG_OVERHEAD +
//!                       mq_msgsize)` against the **creating** process's budget.
//!   mq_send          — additionally charges `MSG_OVERHEAD + len` per message.
//!   mq_receive       — refunds `MSG_OVERHEAD + len` per message dequeued.
//!   mq_unlink/close  — the queue is freed when the last descriptor is closed;
//!                      the full queue allocation is refunded to the creator.
//!
//! The per-process byte counter is stored in an atomic side-table keyed by
//! PID (we cannot store it in the PCB without adding a field, which is done
//! in the PCB via `mq_bytes`).
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
use core::sync::atomic::{AtomicU64, Ordering as AOrdering};
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

/// Linux charges this many bytes of overhead per queue (struct mqueue_inode_info).
const QUEUE_OVERHEAD: u64 = 272;
/// Linux charges this many bytes of overhead per queued message (struct msg_msg).
const MSG_OVERHEAD: u64 = 48;

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
    /// PID of the process that created this queue (RLIMIT_MSGQUEUE charged to them).
    creator_pid: usize,
    /// Bytes charged against `creator_pid`'s RLIMIT_MSGQUEUE for the queue
    /// metadata + capacity reservation.
    queue_charge: u64,
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
static NEXT_MQD: AtomicU64 = AtomicU64::new(1);

/// Open file descriptor table entry for an mq fd.
pub struct MqdEntry {
    pub id:       u64,
    pub oflag:    i32,
    queue:        Arc<MqObject>,
}

// Per-process table of open mqds (integration: fold into fd table).
static MQD_TABLE: Mutex<BTreeMap<u64, MqdEntry>> = Mutex::new(BTreeMap::new());

// ── Per-process MSGQUEUE byte accounting ──────────────────────────────────────────────
//
// We keep a side-table of AtomicU64 instead of requiring a PCB field add
// (the PCB already has `mq_bytes` — see process.rs).  The table is keyed by
// PID and lazily initialised.

static MQ_BYTES: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

fn mq_bytes_charge(pid: usize, bytes: u64) -> isize {
    use crate::proc::rlimit::{RLIMIT_MSGQUEUE, RLIM_INFINITY};
    use crate::proc::scheduler::with_proc;
    let (soft, _) = with_proc(pid, |p| p.rlimits.get(RLIMIT_MSGQUEUE))
        .unwrap_or((RLIM_INFINITY, RLIM_INFINITY));
    let mut tbl = MQ_BYTES.lock();
    let current = tbl.entry(pid).or_insert(0);
    let new_val = current.saturating_add(bytes);
    if soft != RLIM_INFINITY && new_val > soft {
        return -12; // ENOMEM — Linux returns ENOMEM for this case
    }
    *current = new_val;
    0
}

fn mq_bytes_discharge(pid: usize, bytes: u64) {
    let mut tbl = MQ_BYTES.lock();
    if let Some(v) = tbl.get_mut(&pid) {
        *v = v.saturating_sub(bytes);
    }
}

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
        let arc = Arc::clone(obj);
        arc.refs.fetch_add(1, AOrdering::SeqCst);
        let mqd = alloc_mqd(arc, oflag);
        return Ok(mqd);
    }
    if oflag & O_CREAT == 0 { return Err(-2); } // ENOENT

    // ── RLIMIT_MSGQUEUE: charge the queue metadata + capacity reservation ────
    let a = attr.unwrap_or(MqAttr {
        mq_flags:   0,
        mq_maxmsg:  MQ_MAXMSG as i64,
        mq_msgsize: MQ_MSGSIZE as i64,
        mq_curmsgs: 0,
        _pad: [0; 16],
    });
    if a.mq_maxmsg <= 0 || a.mq_msgsize <= 0 { return Err(-22); }

    // Formula from Linux mqueue.c:
    //   charge = QUEUE_OVERHEAD
    //          + mq_maxmsg * (MSG_OVERHEAD + mq_msgsize)
    let queue_charge: u64 = QUEUE_OVERHEAD
        + (a.mq_maxmsg as u64) * (MSG_OVERHEAD + a.mq_msgsize as u64);

    let creator_pid = crate::proc::scheduler::current_pid();
    drop(qs); // release global lock before charging
    let rc = mq_bytes_charge(creator_pid, queue_charge);
    if rc < 0 { return Err(rc as isize); }
    let mut qs = QUEUES.lock();

    // Re-check name (another thread may have raced).
    if qs.contains_key(name) {
        mq_bytes_discharge(creator_pid, queue_charge);
        return Err(-17); // EEXIST in the degenerate race
    }

    let inner = MqInner {
        attr: a,
        heap: BinaryHeap::new(),
        seq:  0,
        unlinked: false,
        creator_pid,
        queue_charge,
        notify_sig: None,
        notify_pid: 0,
    };
    let obj = Arc::new(MqObject {
        name: name.into(),
        inner: Mutex::new(inner),
        refs: core::sync::atomic::AtomicUsize::new(1),
    });
    qs.insert(name.into(), Arc::clone(&obj));
    let mqd = alloc_mqd(obj, oflag);
    Ok(mqd)
}

fn alloc_mqd(queue: Arc<MqObject>, oflag: i32) -> u64 {
    let id = NEXT_MQD.fetch_add(1, AOrdering::SeqCst);
    MQD_TABLE.lock().insert(id, MqdEntry { id, oflag, queue });
    id
}

// ── mq_close ────────────────────────────────────────────────────────────────────────────

pub fn mq_close(mqd: u64) -> Result<(), isize> {
    let entry = MQD_TABLE.lock().remove(&mqd).ok_or(-9isize)?; // EBADF
    let old = entry.queue.refs.fetch_sub(1, AOrdering::SeqCst);
    if old == 1 {
        let name     = entry.queue.name.clone();
        let inner    = entry.queue.inner.lock();
        let unlinked = inner.unlinked;
        let creator  = inner.creator_pid;
        let charge   = inner.queue_charge;
        // Remaining per-message bytes were already refunded on mq_receive.
        // Refund the queue metadata charge.
        drop(inner);
        mq_bytes_discharge(creator, charge);
        if unlinked { QUEUES.lock().remove(&name); }
    }
    Ok(())
}

// ── mq_unlink ────────────────────────────────────────────────────────────────────────────

pub fn mq_unlink(name: &str) -> Result<(), isize> {
    let mut qs = QUEUES.lock();
    let obj = qs.get(name).ok_or(-2isize)?; // ENOENT
    obj.inner.lock().unlinked = true;
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
        // Charge per-message bytes against creator's RLIMIT_MSGQUEUE.
        let msg_charge = MSG_OVERHEAD + data.len() as u64;
        let creator    = inner.creator_pid;
        drop(inner); drop(tbl);
        let rc = mq_bytes_charge(creator, msg_charge);
        if rc < 0 { return Err(rc as isize); }
        // Re-acquire and insert.
        let tbl2  = MQD_TABLE.lock();
        let entry2 = tbl2.get(&mqd).ok_or(-9isize)?;
        let mut inner2 = entry2.queue.inner.lock();
        // Re-check capacity (could have changed during the RLIMIT check).
        if inner2.heap.len() as i64 >= inner2.attr.mq_maxmsg {
            mq_bytes_discharge(creator, msg_charge);
            if entry2.oflag & O_NONBLOCK != 0 { return Err(-11); }
            drop(inner2); drop(tbl2);
            core::hint::spin_loop(); continue;
        }
        let seq = inner2.seq; inner2.seq += 1;
        inner2.heap.push(PriMsg { prio, seq, data });
        inner2.attr.mq_curmsgs += 1;
        if inner2.attr.mq_curmsgs == 1 {
            if let Some(sig) = inner2.notify_sig.take() {
                let pid = inner2.notify_pid;
                drop(inner2); drop(tbl2);
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
        let creator     = inner.creator_pid;
        let msg_charge  = MSG_OVERHEAD + msg.data.len() as u64;
        drop(inner); drop(tbl);
        // Refund per-message bytes.
        mq_bytes_discharge(creator, msg_charge);
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
    inner.attr.mq_flags = new_attr.mq_flags & O_NONBLOCK as i64;
    Ok(old)
}

// ── mq_notify (stub) ────────────────────────────────────────────────────────────────────

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
