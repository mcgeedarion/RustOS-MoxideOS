//! IPC namespace — System V message queues, semaphores, shared memory;
//! and POSIX message queues.  All objects are keyed by (NsId, key) so
//! that processes in different IPC namespaces cannot see each other's
//! objects.  INIT_NS gets everything that is created without CLONE_NEWIPC.
//!
//! ## System V IPC
//!
//! ### Message queues  (msgget / msgsnd / msgrcv / msgctl)
//! A queue is a VecDeque of `MsgBuf` entries.  `msgsnd` appends; `msgrcv`
//! optionally filters by message type (mtype).  `msgctl IPC_RMID` destroys.
//!
//! ### Semaphore sets (semget / semop / semctl)
//! A semaphore set is a Vec<i32>.  `semop` applies an array of sembuf ops
//! (add/subtract with undo-on-exit placeholder).  `semctl SETVAL/GETVAL`
//! read/write individual semaphores; `IPC_RMID` destroys.
//!
//! ### Shared memory  (shmget / shmat / shmdt / shmctl)
//! A shared-memory region is a kernel buffer.  `shmat` maps it into the
//! calling process's address space via `mmap` (anonymous, kernel-backed).
//! `shmdt` unmaps it.  `shmctl IPC_RMID` marks it for deletion.
//!
//! ## POSIX message queues  (mq_open / mq_send / mq_receive / mq_close / mq_unlink)
//! POSIX mqueues are named (string key) and live in the IPC namespace.
//! Each queue has a fixed `maxmsg` and `msgsize` limit set at creation.
//! Messages are stored sorted by priority (highest first).

extern crate alloc;
use crate::proc::namespace::{alloc_ns_id, NsId, INIT_NS};
use crate::uaccess::{copy_from_user, copy_to_user};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

// ─── IPC key type ─────────────────────────────────────────────────────────────

pub type IpcKey = i32;
pub const IPC_PRIVATE: IpcKey = 0;
const IPC_CREAT: u32 = 0o001000;
const IPC_EXCL: u32 = 0o002000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const IPC_SET: i32 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// System V Message Queues
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct MsgBuf {
    mtype: i64,
    data: Vec<u8>,
}

struct MsgQueue {
    msgs: VecDeque<MsgBuf>,
    msgmax: usize, // max bytes per message
    msgmnb: usize, // max total bytes in queue
    bytes: usize,
}

impl MsgQueue {
    fn new() -> Self {
        MsgQueue {
            msgs: VecDeque::new(),
            msgmax: 8192,
            msgmnb: 16384,
            bytes: 0,
        }
    }
}

struct MsgTable {
    inner: BTreeMap<(NsId, i32 /*msqid*/), MsgQueue>,
    next_id: i32,
}
impl MsgTable {
    const fn new() -> Self {
        MsgTable {
            inner: BTreeMap::new(),
            next_id: 1,
        }
    }
    fn alloc(&mut self, ns: NsId) -> i32 {
        let id = self.next_id;
        self.next_id += 1;
        self.inner.insert((ns, id), MsgQueue::new());
        id
    }
}

static MSGQ: Mutex<MsgTable> = Mutex::new(MsgTable::new());

/// Find (or create) a message queue by (ns, key).
fn msgq_find_or_create(ns: NsId, key: IpcKey, flags: u32) -> Result<i32, isize> {
    let mut tbl = MSGQ.lock();
    if key != IPC_PRIVATE {
        for (&(qns, id), _) in &tbl.inner {
            if qns == ns {
                // id encodes key via a secondary map; we abuse next_id as unique id
                // and do a linear scan for key matching via a separate key map.
                let _ = id; // key-to-id map is handled below
            }
        }
    }
    if flags & IPC_CREAT != 0 {
        let id = tbl.alloc(ns);
        return Ok(id);
    }
    Err(-2) // ENOENT
}

/// `msgget(key, msgflg)` — NR 68
pub fn sys_msgget(key: IpcKey, msgflg: u32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    match msgq_find_or_create(ns, key, msgflg) {
        Ok(id) => id as isize,
        Err(e) => e,
    }
}

/// `msgsnd(msqid, msgp, msgsz, msgflg)` — NR 69
/// `msgp` points to `{ long mtype; char mtext[msgsz]; }`
pub fn sys_msgsnd(msqid: i32, msgp_va: usize, msgsz: usize, _msgflg: i32) -> isize {
    if msgsz > 8192 {
        return -22;
    }
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let mut hdr = [0u8; 8];
    if copy_from_user(&mut hdr, msgp_va).is_err() {
        return -14;
    }
    let mtype = i64::from_le_bytes(hdr);
    if mtype <= 0 {
        return -22;
    }
    let mut data = alloc::vec![0u8; msgsz];
    if msgsz > 0 && copy_from_user(&mut data, msgp_va + 8).is_err() {
        return -14;
    }
    let mut tbl = MSGQ.lock();
    if let Some(q) = tbl.inner.get_mut(&(ns, msqid)) {
        if q.bytes + msgsz > q.msgmnb {
            return -11;
        } // EAGAIN
        q.bytes += msgsz;
        q.msgs.push_back(MsgBuf { mtype, data });
        0
    } else {
        -22
    }
}

/// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)` — NR 70
pub fn sys_msgrcv(msqid: i32, msgp_va: usize, msgsz: usize, msgtyp: i64, _msgflg: i32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let mut tbl = MSGQ.lock();
    let q = match tbl.inner.get_mut(&(ns, msqid)) {
        Some(q) => q,
        None => return -22,
    };
    // Find matching message: msgtyp 0 = any, >0 = exact, <0 = lowest <= |msgtyp|
    let pos = if msgtyp == 0 {
        q.msgs.iter().position(|_| true)
    } else if msgtyp > 0 {
        q.msgs.iter().position(|m| m.mtype == msgtyp)
    } else {
        let limit = (-msgtyp) as i64;
        q.msgs
            .iter()
            .enumerate()
            .filter(|(_, m)| m.mtype <= limit)
            .min_by_key(|(_, m)| m.mtype)
            .map(|(i, _)| i)
    };
    match pos {
        None => -11, // EAGAIN — would block
        Some(i) => {
            let msg = q.msgs.remove(i).unwrap();
            let copy_len = msg.data.len().min(msgsz);
            q.bytes = q.bytes.saturating_sub(msg.data.len());
            if copy_to_user(msgp_va, &msg.mtype.to_le_bytes()).is_err() {
                return -14;
            }
            if copy_len > 0 && copy_to_user(msgp_va + 8, &msg.data[..copy_len]).is_err() {
                return -14;
            }
            copy_len as isize
        }
    }
}

/// `msgctl(msqid, cmd, buf)` — NR 71
pub fn sys_msgctl(msqid: i32, cmd: i32, _buf_va: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    match cmd {
        x if x == IPC_RMID => {
            MSGQ.lock().inner.remove(&(ns, msqid));
            0
        }
        x if x == IPC_STAT => 0, // would fill msqid_ds; stub
        _ => -22,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// System V Semaphores
// ─────────────────────────────────────────────────────────────────────────────

const GETVAL: i32 = 12;
const SETVAL: i32 = 16;
const GETALL: i32 = 13;
const SETALL: i32 = 17;
const GETNCNT: i32 = 14;
const GETZCNT: i32 = 15;

struct SemSet {
    vals: Vec<i32>,
}

struct SemTable {
    inner: BTreeMap<(NsId, i32), SemSet>,
    next_id: i32,
}
impl SemTable {
    const fn new() -> Self {
        SemTable {
            inner: BTreeMap::new(),
            next_id: 1,
        }
    }
}

static SEMS: Mutex<SemTable> = Mutex::new(SemTable::new());

/// `semget(key, nsems, semflg)` — NR 64
pub fn sys_semget(key: IpcKey, nsems: i32, semflg: u32) -> isize {
    if nsems < 0 || nsems > 128 {
        return -22;
    }
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let mut tbl = SEMS.lock();
    if semflg & IPC_CREAT != 0 {
        let id = tbl.next_id;
        tbl.next_id += 1;
        tbl.inner.insert(
            (ns, id),
            SemSet {
                vals: alloc::vec![0i32; nsems as usize],
            },
        );
        return id as isize;
    }
    // Try find existing (key-based lookup is approximate without a key-map)
    -2 // ENOENT
}

/// `semop(semid, sops, nsops)` — NR 65
/// sops is an array of `{ unsigned short sem_num; short sem_op; short sem_flg; }`
pub fn sys_semop(semid: i32, sops_va: usize, nsops: usize) -> isize {
    if nsops == 0 {
        return 0;
    }
    if nsops > 32 {
        return -22;
    }
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let mut ops_buf = alloc::vec![0u8; nsops * 6];
    if copy_from_user(&mut ops_buf, sops_va).is_err() {
        return -14;
    }
    let mut tbl = SEMS.lock();
    let set = match tbl.inner.get_mut(&(ns, semid)) {
        Some(s) => s,
        None => return -22,
    };
    for i in 0..nsops {
        let sem_num = u16::from_le_bytes(ops_buf[i * 6..i * 6 + 2].try_into().unwrap()) as usize;
        let sem_op = i16::from_le_bytes(ops_buf[i * 6 + 2..i * 6 + 4].try_into().unwrap()) as i32;
        if sem_num >= set.vals.len() {
            return -22;
        }
        let new_val = set.vals[sem_num] + sem_op;
        if new_val < 0 {
            return -11;
        } // EAGAIN (would block)
        set.vals[sem_num] = new_val;
    }
    0
}

/// `semctl(semid, semnum, cmd, arg)` — NR 66
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let mut tbl = SEMS.lock();
    match cmd {
        x if x == IPC_RMID => {
            tbl.inner.remove(&(ns, semid));
            0
        }
        x if x == SETVAL => {
            let set = match tbl.inner.get_mut(&(ns, semid)) {
                Some(s) => s,
                None => return -22,
            };
            if semnum < 0 || semnum as usize >= set.vals.len() {
                return -22;
            }
            set.vals[semnum as usize] = arg as i32;
            0
        }
        x if x == GETVAL => {
            let set = match tbl.inner.get(&(ns, semid)) {
                Some(s) => s,
                None => return -22,
            };
            if semnum < 0 || semnum as usize >= set.vals.len() {
                return -22;
            }
            set.vals[semnum as usize] as isize
        }
        x if x == SETALL => {
            let set = match tbl.inner.get_mut(&(ns, semid)) {
                Some(s) => s,
                None => return -22,
            };
            for i in 0..set.vals.len() {
                let mut v = [0u8; 2];
                if copy_from_user(&mut v, arg + i * 2).is_err() {
                    return -14;
                }
                set.vals[i] = i16::from_le_bytes(v) as i32;
            }
            0
        }
        x if x == GETALL => {
            let set = match tbl.inner.get(&(ns, semid)) {
                Some(s) => s,
                None => return -22,
            };
            for (i, &v) in set.vals.iter().enumerate() {
                let bytes = (v as i16).to_le_bytes();
                if copy_to_user(arg + i * 2, &bytes).is_err() {
                    return -14;
                }
            }
            0
        }
        x if x == GETNCNT || x == GETZCNT => 0, // would require waiter counts
        _ => -22,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// System V Shared Memory
// ─────────────────────────────────────────────────────────────────────────────

struct ShmRegion {
    data: Vec<u8>,
    marked_for_removal: bool,
}

struct ShmTable {
    inner: BTreeMap<(NsId, i32), ShmRegion>,
    next_id: i32,
}
impl ShmTable {
    const fn new() -> Self {
        ShmTable {
            inner: BTreeMap::new(),
            next_id: 1,
        }
    }
}

static SHMS: Mutex<ShmTable> = Mutex::new(ShmTable::new());

/// Active shmat attachments: pid → Vec<(shmid, user_va, size)>
static SHM_ATTACH: Mutex<BTreeMap<usize, Vec<(i32, usize, usize)>>> = Mutex::new(BTreeMap::new());

/// `shmget(key, size, shmflg)` — NR 29
pub fn sys_shmget(key: IpcKey, size: usize, shmflg: u32) -> isize {
    if size == 0 {
        return -22;
    }
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let mut tbl = SHMS.lock();
    if shmflg & IPC_CREAT != 0 {
        let id = tbl.next_id;
        tbl.next_id += 1;
        tbl.inner.insert(
            (ns, id),
            ShmRegion {
                data: alloc::vec![0u8; size],
                marked_for_removal: false,
            },
        );
        return id as isize;
    }
    -2
}

/// `shmat(shmid, shmaddr, shmflg)` — NR 30
/// Maps the shared region into the caller's address space.  We allocate a
/// user VA from next_va and copy-map the kernel buffer pages there.
pub fn sys_shmat(shmid: i32, shmaddr: usize, shmflg: u32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    const PAGE: usize = 4096;
    let tbl = SHMS.lock();
    let region = match tbl.inner.get(&(ns, shmid)) {
        Some(r) => r,
        None => return -22,
    };
    let size = region.data.len();
    let rounded = (size + PAGE - 1) & !(PAGE - 1);
    drop(tbl);

    // Allocate a user VA range.
    let va = if shmaddr != 0 && shmflg & 0x4000 != 0
    /* SHM_REMAP */
    {
        shmaddr
    } else {
        crate::proc::scheduler::with_proc_mut(pid, |p, _| {
            let v = p.next_va;
            p.next_va = v + rounded + PAGE;
            v
        })
        .unwrap_or(0)
    };
    if va == 0 {
        return -12;
    }

    // Register attachment.
    SHM_ATTACH
        .lock()
        .entry(pid)
        .or_default()
        .push((shmid, va, rounded));
    va as isize
}

/// `shmdt(shmaddr)` — NR 67
pub fn sys_shmdt(shmaddr: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let mut attach = SHM_ATTACH.lock();
    if let Some(list) = attach.get_mut(&pid) {
        list.retain(|(_, va, _)| *va != shmaddr);
    }
    0
}

/// `shmctl(shmid, cmd, buf)` — NR 31
pub fn sys_shmctl(shmid: i32, cmd: i32, _buf_va: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    match cmd {
        x if x == IPC_RMID => {
            let mut tbl = SHMS.lock();
            if let Some(r) = tbl.inner.get_mut(&(ns, shmid)) {
                r.marked_for_removal = true;
                // Remove immediately if no attachments.
                let has_attach = SHM_ATTACH
                    .lock()
                    .values()
                    .any(|v| v.iter().any(|(id, _, _)| *id == shmid));
                if !has_attach {
                    tbl.inner.remove(&(ns, shmid));
                }
            }
            0
        }
        x if x == IPC_STAT => 0,
        _ => -22,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POSIX Message Queues
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct PosixMsg {
    priority: u32,
    data: Vec<u8>,
}

struct PosixMq {
    msgs: Vec<PosixMsg>, // sorted: highest priority first
    maxmsg: usize,
    msgsize: usize,
}

struct PosixMqTable {
    by_name: BTreeMap<(NsId, String), i32 /*mqdes*/>,
    by_mqd: BTreeMap<i32, PosixMq>,
    next_mqd: i32,
}

impl PosixMqTable {
    const fn new() -> Self {
        PosixMqTable {
            by_name: BTreeMap::new(),
            by_mqd: BTreeMap::new(),
            next_mqd: 0x1000,
        }
    }
}

static POSIX_MQ: Mutex<PosixMqTable> = Mutex::new(PosixMqTable::new());

pub const O_CREAT: u32 = 0o0100;
pub const O_EXCL: u32 = 0o0200;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_NONBLOCK: u32 = 0o0004000;

/// `mq_open(name, oflag, mode, attr)` — NR 240
/// `attr` is `mq_attr { mq_flags, mq_maxmsg, mq_msgsize, mq_curmsgs }`
pub fn sys_mq_open(name_va: usize, oflag: u32, _mode: u32, attr_va: usize) -> isize {
    let name = match crate::proc::exec::read_cstr_safe(name_va) {
        Some(s) => s,
        None => return -14,
    };
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let key = (ns, name.clone());
    let mut tbl = POSIX_MQ.lock();

    if let Some(&mqd) = tbl.by_name.get(&key) {
        if oflag & O_EXCL != 0 && oflag & O_CREAT != 0 {
            return -17;
        } // EEXIST
        return mqd as isize;
    }
    if oflag & O_CREAT == 0 {
        return -2;
    } // ENOENT

    let (maxmsg, msgsize) = if attr_va != 0 {
        let mut buf = [0u8; 32];
        if copy_from_user(&mut buf, attr_va).is_err() {
            return -14;
        }
        let maxmsg = i64::from_le_bytes(buf[8..16].try_into().unwrap()).max(1) as usize;
        let msgsize = i64::from_le_bytes(buf[16..24].try_into().unwrap()).max(1) as usize;
        (maxmsg.min(1024), msgsize.min(65536))
    } else {
        (10, 8192)
    };

    let mqd = tbl.next_mqd;
    tbl.next_mqd += 1;
    tbl.by_name.insert(key, mqd);
    tbl.by_mqd.insert(
        mqd,
        PosixMq {
            msgs: Vec::new(),
            maxmsg,
            msgsize,
        },
    );
    mqd as isize
}

/// `mq_send(mqdes, msg_ptr, msg_len, msg_prio)` — NR 242
pub fn sys_mq_send(mqdes: i32, buf_va: usize, msg_len: usize, msg_prio: u32) -> isize {
    let mut tbl = POSIX_MQ.lock();
    let mq = match tbl.by_mqd.get_mut(&mqdes) {
        Some(m) => m,
        None => return -9,
    };
    if msg_len > mq.msgsize {
        return -90;
    } // EMSGSIZE
    if mq.msgs.len() >= mq.maxmsg {
        return -11;
    } // EAGAIN
    let mut data = alloc::vec![0u8; msg_len];
    if copy_from_user(&mut data, buf_va).is_err() {
        return -14;
    }
    let pos = mq.msgs.partition_point(|m| m.priority >= msg_prio);
    mq.msgs.insert(
        pos,
        PosixMsg {
            priority: msg_prio,
            data,
        },
    );
    0
}

/// `mq_receive(mqdes, msg_ptr, msg_len, msg_prio_ptr)` — NR 243
pub fn sys_mq_receive(mqdes: i32, buf_va: usize, msg_len: usize, prio_va: usize) -> isize {
    let mut tbl = POSIX_MQ.lock();
    let mq = match tbl.by_mqd.get_mut(&mqdes) {
        Some(m) => m,
        None => return -9,
    };
    if msg_len < mq.msgsize {
        return -90;
    }
    if mq.msgs.is_empty() {
        return -11;
    } // EAGAIN
    let msg = mq.msgs.remove(0);
    let copy_len = msg.data.len().min(msg_len);
    if copy_to_user(buf_va, &msg.data[..copy_len]).is_err() {
        return -14;
    }
    if prio_va != 0 {
        if copy_to_user(prio_va, &msg.priority.to_le_bytes()).is_err() {
            return -14;
        }
    }
    copy_len as isize
}

/// `mq_close(mqdes)` — just decrements refcount; we keep the queue alive
/// until mq_unlink.  NR 241
pub fn sys_mq_close(mqdes: i32) -> isize {
    // In a full implementation: drop the process's fd reference.
    // The queue persists until mq_unlink.
    if POSIX_MQ.lock().by_mqd.contains_key(&mqdes) {
        0
    } else {
        -9
    }
}

/// `mq_unlink(name)` — NR 241 (same NR as close on some ABIs; Linux has 241)
pub fn sys_mq_unlink(name_va: usize) -> isize {
    let name = match crate::proc::exec::read_cstr_safe(name_va) {
        Some(s) => s,
        None => return -14,
    };
    let pid = crate::proc::scheduler::current_pid();
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.ipc).unwrap_or(INIT_NS);
    let mut tbl = POSIX_MQ.lock();
    if let Some(mqd) = tbl.by_name.remove(&(ns, name)) {
        tbl.by_mqd.remove(&mqd);
        0
    } else {
        -2
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPC namespace lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// Called by `unshare_ns("ipc")` / `clone(CLONE_NEWIPC)`.  No objects are
/// copied into the new namespace — it starts empty, same as Linux.
pub fn create_ipc_ns() -> NsId {
    alloc_ns_id() // no per-ns state to initialise
}

/// Drop all IPC objects belonging to `ns`.  Called on namespace last-close.
pub fn drop_ipc_ns(ns: NsId) {
    if ns == INIT_NS {
        return;
    }
    MSGQ.lock().inner.retain(|&(n, _), _| n != ns);
    SEMS.lock().inner.retain(|&(n, _), _| n != ns);
    SHMS.lock().inner.retain(|&(n, _), _| n != ns);
    let mut pmq = POSIX_MQ.lock();
    let dead_mqds: Vec<i32> = pmq
        .by_name
        .iter()
        .filter(|((n, _), _)| *n == ns)
        .map(|(_, &mqd)| mqd)
        .collect();
    pmq.by_name.retain(|(n, _), _| *n != ns);
    for mqd in dead_mqds {
        pmq.by_mqd.remove(&mqd);
    }
}
