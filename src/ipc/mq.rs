//! POSIX message queues (`<mqueue.h>`).
//!
//! ## API
//!
//! | Function                              | Returns   |
//! |---------------------------------------|----------|
//! | `mq_open(name, oflag, mode, attr)`    | `mqd_t`  |
//! | `mq_close(mqd)`                       | `0`      |
//! | `mq_unlink(name)`                     | `0`      |
//! | `mq_send(mqd, msg, len, prio)`        | `0`      |
//! | `mq_receive(mqd, buf, buflen, prio*)` | `ssize_t`|
//! | `mq_getattr(mqd, attr)`               | `0`      |
//! | `mq_setattr(mqd, new, old)`           | `0`      |
//! | `mq_notify(mqd, sigev)`               | `0` (stub)|
//!
//! ## RLIMIT_MSGQUEUE accounting
//!
//! `mq_open(O_CREAT)` charges `QUEUE_OVERHEAD + mq_maxmsg * (MSG_OVERHEAD +
//! mq_msgsize)` against the creating process's budget.  `mq_send` charges
//! `MSG_OVERHEAD + len`; `mq_receive` refunds it.  The queue reservation is
//! refunded when the last descriptor is closed.
//!
//! ## Storage
//!
//! Messages are stored in a `BinaryHeap<PriMsg>` (max-heap by priority).
//! Same-priority messages are FIFO (tie-broken by a monotone sequence
//! counter).  Queues are reference-counted; `mq_unlink` marks for
//! destruction but keeps the queue alive until the last `mq_close`.

extern crate alloc;
use alloc::{
    collections::{BTreeMap, BinaryHeap},
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::{
    cmp::Ordering,
    sync::atomic::{AtomicU64, Ordering as AOrdering},
};
use spin::Mutex;

// ── O_* flags (match Linux) ─────────────────────────────────────────────────
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0o100;
pub const O_EXCL: i32 = 0o200;
pub const O_NONBLOCK: i32 = 0o4000;
pub const O_CLOEXEC: i32 = 0o2000000;

// ── Limits ──────────────────────────────────────────────────────────────────
pub const MQ_MAXMSG: usize = 10;
pub const MQ_MSGSIZE: usize = 8192;
pub const MQ_PRIO_MAX: u32 = 32768;

/// Bytes of overhead per queue (mirrors `struct mqueue_inode_info`).
const QUEUE_OVERHEAD: u64 = 272;
/// Bytes of overhead per queued message (mirrors `struct msg_msg`).
const MSG_OVERHEAD: u64 = 48;

// ── struct mq_attr ──────────────────────────────────────────────────────────

/// `struct mq_attr` — matches Linux POSIX mqueue UAPI.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct MqAttr {
    pub mq_flags: i64, // O_NONBLOCK state
    pub mq_maxmsg: i64,
    pub mq_msgsize: i64,
    pub mq_curmsgs: i64,
    _pad: [u8; 16],
}

// ── Internal message ────────────────────────────────────────────────────────

#[derive(Eq, PartialEq)]
struct PriMsg {
    prio: u32,
    seq: u64, // FIFO tie-breaker within the same priority
    data: Vec<u8>,
}

impl Ord for PriMsg {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .prio
            .cmp(&self.prio)
            .then(self.seq.cmp(&other.seq))
            .reverse()
    }
}
impl PartialOrd for PriMsg {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ── Queue internals ──────────────────────────────────────────────────────────

struct MqInner {
    attr: MqAttr,
    heap: BinaryHeap<PriMsg>,
    seq: u64,
    unlinked: bool,
    creator_pid: usize, // RLIMIT_MSGQUEUE is charged to this PID
    queue_charge: u64,  // bytes charged for queue metadata + capacity
    notify_sig: Option<u32>,
    notify_pid: u32,
}

struct MqObject {
    name: String,
    inner: Mutex<MqInner>,
    refs: core::sync::atomic::AtomicUsize,
}

// ── Global tables ────────────────────────────────────────────────────────────

static QUEUES: Mutex<BTreeMap<String, Arc<MqObject>>> = Mutex::new(BTreeMap::new());
static NEXT_MQD: AtomicU64 = AtomicU64::new(1);

/// Open-file-table entry for an mq fd.
pub struct MqdEntry {
    pub id: u64,
    pub oflag: i32,
    queue: Arc<MqObject>,
}

static MQD_TABLE: Mutex<BTreeMap<u64, MqdEntry>> = Mutex::new(BTreeMap::new());

// ── Per-process MSGQUEUE byte accounting ─────────────────────────────────────
//
// Side-table keyed by PID (the PCB already has `mq_bytes`; this table avoids
// requiring a PCB field add).

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
        return -12; // ENOMEM
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

// ── mq_open ──────────────────────────────────────────────────────────────────

pub fn mq_open(name: &str, oflag: i32, _mode: u32, attr: Option<MqAttr>) -> Result<u64, isize> {
    if name.is_empty() || !name.starts_with('/') {
        return Err(-22);
    } // EINVAL

    let mut qs = QUEUES.lock();
    if let Some(obj) = qs.get(name) {
        if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 {
            return Err(-17);
        } // EEXIST
        let arc = Arc::clone(obj);
        arc.refs.fetch_add(1, AOrdering::SeqCst);
        return Ok(alloc_mqd(arc, oflag));
    }
    if oflag & O_CREAT == 0 {
        return Err(-2);
    } // ENOENT

    let a = attr.unwrap_or(MqAttr {
        mq_flags: 0,
        mq_maxmsg: MQ_MAXMSG as i64,
        mq_msgsize: MQ_MSGSIZE as i64,
        mq_curmsgs: 0,
        _pad: [0; 16],
    });
    if a.mq_maxmsg <= 0 || a.mq_msgsize <= 0 {
        return Err(-22);
    }

    // charge = QUEUE_OVERHEAD + mq_maxmsg * (MSG_OVERHEAD + mq_msgsize)
    let queue_charge: u64 =
        QUEUE_OVERHEAD + (a.mq_maxmsg as u64) * (MSG_OVERHEAD + a.mq_msgsize as u64);

    let creator_pid = crate::proc::scheduler::current_pid();
    drop(qs); // release global lock before the RLIMIT check
    let rc = mq_bytes_charge(creator_pid, queue_charge);
    if rc < 0 {
        return Err(rc as isize);
    }

    let mut qs = QUEUES.lock();
    if qs.contains_key(name) {
        // Lost a creation race — refund and report EEXIST.
        mq_bytes_discharge(creator_pid, queue_charge);
        return Err(-17);
    }

    let inner = MqInner {
        attr: a,
        heap: BinaryHeap::new(),
        seq: 0,
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
    Ok(alloc_mqd(obj, oflag))
}

#[inline]
fn alloc_mqd(queue: Arc<MqObject>, oflag: i32) -> u64 {
    let id = NEXT_MQD.fetch_add(1, AOrdering::SeqCst);
    MQD_TABLE.lock().insert(id, MqdEntry { id, oflag, queue });
    id
}

// ── mq_close ─────────────────────────────────────────────────────────────────

pub fn mq_close(mqd: u64) -> Result<(), isize> {
    let entry = MQD_TABLE.lock().remove(&mqd).ok_or(-9isize)?; // EBADF
    let old = entry.queue.refs.fetch_sub(1, AOrdering::SeqCst);
    if old == 1 {
        // Last descriptor closed — refund queue metadata charge.
        let name = entry.queue.name.clone();
        let inner = entry.queue.inner.lock();
        let (unlinked, creator, charge) = (inner.unlinked, inner.creator_pid, inner.queue_charge);
        drop(inner);
        mq_bytes_discharge(creator, charge);
        if unlinked {
            QUEUES.lock().remove(&name);
        }
    }
    Ok(())
}

// ── mq_unlink ────────────────────────────────────────────────────────────────

pub fn mq_unlink(name: &str) -> Result<(), isize> {
    let mut qs = QUEUES.lock();
    let obj = qs.get(name).ok_or(-2isize)?; // ENOENT
    obj.inner.lock().unlinked = true;
    qs.remove(name);
    Ok(())
}

// ── mq_send ──────────────────────────────────────────────────────────────────

pub fn mq_send(mqd: u64, data: Vec<u8>, prio: u32) -> Result<(), isize> {
    if prio >= MQ_PRIO_MAX {
        return Err(-22);
    }
    loop {
        let tbl = MQD_TABLE.lock();
        let entry = tbl.get(&mqd).ok_or(-9isize)?;
        let mut inner = entry.queue.inner.lock();
        if data.len() > inner.attr.mq_msgsize as usize {
            return Err(-90);
        } // EMSGSIZE
        if inner.heap.len() as i64 >= inner.attr.mq_maxmsg {
            if entry.oflag & O_NONBLOCK != 0 {
                return Err(-11);
            } // EAGAIN
            drop(inner);
            drop(tbl);
            core::hint::spin_loop();
            continue;
        }
        let msg_charge = MSG_OVERHEAD + data.len() as u64;
        let creator = inner.creator_pid;
        drop(inner);
        drop(tbl);

        let rc = mq_bytes_charge(creator, msg_charge);
        if rc < 0 {
            return Err(rc as isize);
        }

        // Re-acquire and insert (capacity may have changed during RLIMIT check).
        let tbl2 = MQD_TABLE.lock();
        let entry2 = tbl2.get(&mqd).ok_or(-9isize)?;
        let mut inner2 = entry2.queue.inner.lock();
        if inner2.heap.len() as i64 >= inner2.attr.mq_maxmsg {
            mq_bytes_discharge(creator, msg_charge);
            if entry2.oflag & O_NONBLOCK != 0 {
                return Err(-11);
            }
            drop(inner2);
            drop(tbl2);
            core::hint::spin_loop();
            continue;
        }
        let seq = inner2.seq;
        inner2.seq += 1;
        inner2.heap.push(PriMsg { prio, seq, data });
        inner2.attr.mq_curmsgs += 1;
        // Fire mq_notify if this was the first message.
        if inner2.attr.mq_curmsgs == 1 {
            if let Some(sig) = inner2.notify_sig.take() {
                let pid = inner2.notify_pid;
                drop(inner2);
                drop(tbl2);
                crate::proc::signal::send_signal(pid as usize, sig);
                return Ok(());
            }
        }
        return Ok(());
    }
}

// ── mq_receive ───────────────────────────────────────────────────────────────

pub fn mq_receive(mqd: u64, max_len: usize) -> Result<(Vec<u8>, u32), isize> {
    loop {
        let tbl = MQD_TABLE.lock();
        let entry = tbl.get(&mqd).ok_or(-9isize)?;
        if entry.oflag & O_WRONLY != 0 {
            return Err(-9);
        } // EBADF — write-only
        let mut inner = entry.queue.inner.lock();
        if inner.attr.mq_msgsize > max_len as i64 {
            return Err(-90);
        } // EMSGSIZE
        if let Some(msg) = inner.heap.pop() {
            inner.attr.mq_curmsgs -= 1;
            let charge = MSG_OVERHEAD + msg.data.len() as u64;
            let creator = inner.creator_pid;
            drop(inner);
            drop(tbl);
            mq_bytes_discharge(creator, charge);
            return Ok((msg.data, msg.prio));
        }
        if entry.oflag & O_NONBLOCK != 0 {
            return Err(-11);
        } // EAGAIN
        drop(inner);
        drop(tbl);
        core::hint::spin_loop();
    }
}

// ── mq_getattr / mq_setattr ──────────────────────────────────────────────────

pub fn mq_getattr(mqd: u64) -> Result<MqAttr, isize> {
    let tbl = MQD_TABLE.lock();
    let entry = tbl.get(&mqd).ok_or(-9isize)?;
    let inner = entry.queue.inner.lock();
    let mut a = inner.attr;
    a.mq_flags = if entry.oflag & O_NONBLOCK != 0 {
        O_NONBLOCK as i64
    } else {
        0
    };
    Ok(a)
}

pub fn mq_setattr(mqd: u64, new: MqAttr) -> Result<MqAttr, isize> {
    let tbl = MQD_TABLE.lock();
    let entry = tbl.get(&mqd).ok_or(-9isize)?;
    let mut inner = entry.queue.inner.lock();
    let old = inner.attr;
    // Only mq_flags (O_NONBLOCK) is settable via mq_setattr.
    inner.attr.mq_flags = new.mq_flags;
    Ok(old)
}

// ── mq_notify ────────────────────────────────────────────────────────────────

/// Register a signal-based notification for the next message arrival.
/// `signo == 0` cancels any existing registration.
/// `pid == 0` uses the calling process.
pub fn mq_notify(mqd: u64, signo: u32, pid: u32) -> Result<(), isize> {
    let pid = if pid == 0 {
        crate::proc::scheduler::current_pid() as u32
    } else {
        pid
    };
    let tbl = MQD_TABLE.lock();
    let entry = tbl.get(&mqd).ok_or(-9isize)?;
    let mut inner = entry.queue.inner.lock();
    if signo == 0 {
        inner.notify_sig = None;
        inner.notify_pid = 0;
    } else {
        inner.notify_sig = Some(signo);
        inner.notify_pid = pid;
    }
    Ok(())
}
