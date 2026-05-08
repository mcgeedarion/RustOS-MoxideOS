//! System V message queues.
//!
//! ## API
//!
//!   msgget(key, msgflg)          -> msqid  (i32)
//!   msgsnd(msqid, msgp, msgsz, msgflg) -> 0
//!   msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) -> ssize_t
//!   msgctl(msqid, cmd, buf)      -> varies
//!
//! ## `struct msgbuf` layout (matches Linux UAPI)
//!
//!   long  mtype;   // message type, must be > 0
//!   char  mtext[]; // message data
//!
//! ## Key semantics
//!
//! - `IPC_PRIVATE` always creates a new private queue.
//! - `IPC_CREAT | IPC_EXCL` fails with EEXIST if key already exists.
//! - `IPC_CREAT` alone creates-or-opens.
//!
//! ## `msgrcv` type matching
//!
//! | `msgtyp` | Behaviour |
//! |----------|-----------|
//! | 0        | First message in queue |
//! | > 0      | First message with `mtype == msgtyp` |
//! | < 0      | First message with `mtype <= abs(msgtyp)` |

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;
use alloc::collections::BTreeMap;

use crate::ipc::{IpcPerm, IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_NOWAIT,
                 IPC_RMID, IPC_SET, IPC_STAT, check_perm};

// ── Limits (match Linux defaults) ───────────────────────────────────────────────

pub const MSGMAX: usize = 8192;   // max single message size
pub const MSGMNB: usize = 16384;  // max bytes in a queue
pub const MSGMNI: usize = 32000;  // max queues system-wide

// ── msgctl commands ────────────────────────────────────────────────────────────────
pub const MSG_STAT: i32 = 11;
pub const MSG_INFO: i32 = 12;
pub const MSG_STAT_ANY: i32 = 15;

// ── Data structures ───────────────────────────────────────────────────────────────────

struct Message {
    mtype: i64,
    data:  Vec<u8>,
}

/// `struct msqid_ds` — matches Linux x86_64 UAPI.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct MsqidDs {
    pub msg_perm:   IpcPerm,
    pub msg_stime:  i64,
    pub msg_rtime:  i64,
    pub msg_ctime:  i64,
    pub msg_cbytes: u64,
    pub msg_qnum:   u64,
    pub msg_qbytes: u64,
    pub msg_lspid:  u32,
    pub msg_lrpid:  u32,
    _pad: [u8; 8],
}

struct MsgQueue {
    ds:       MsqidDs,
    messages: VecDeque<Message>,
    key:      i32,
}

static QUEUES: Mutex<BTreeMap<i32, MsgQueue>> = Mutex::new(BTreeMap::new());
static NEXT_ID: spin::Mutex<i32> = spin::Mutex::new(1);

fn alloc_id() -> i32 { let mut n = NEXT_ID.lock(); let id = *n; *n += 1; id }

// ── msgget ────────────────────────────────────────────────────────────────────────────

pub fn msgget(key: i32, msgflg: i32) -> Result<i32, isize> {
    let mut qs = QUEUES.lock();
    if key != IPC_PRIVATE {
        // Search for existing queue with this key.
        if let Some((&id, q)) = qs.iter().find(|(_, q)| q.key == key) {
            if msgflg & IPC_CREAT != 0 && msgflg & IPC_EXCL != 0 {
                return Err(-17); // EEXIST
            }
            return Ok(id);
        }
        if msgflg & IPC_CREAT == 0 {
            return Err(-2); // ENOENT
        }
    }
    if qs.len() >= MSGMNI { return Err(-28); } // ENOSPC
    let id   = alloc_id();
    let mode = (msgflg & 0o777) as u16;
    let perm = IpcPerm::new(key, 0, 0, mode);
    let now  = crate::time::clock::time_secs();
    let ds   = MsqidDs { msg_perm: perm, msg_ctime: now, msg_qbytes: MSGMNB as u64, ..Default::default() };
    qs.insert(id, MsgQueue { ds, messages: VecDeque::new(), key });
    Ok(id)
}

// ── msgsnd ────────────────────────────────────────────────────────────────────────────

/// Send a message.  `data` is the `mtext` portion (already copied from user).
pub fn msgsnd(msqid: i32, mtype: i64, data: Vec<u8>, msgflg: i32) -> Result<(), isize> {
    if mtype <= 0 { return Err(-22); } // EINVAL
    if data.len() > MSGMAX { return Err(-7); } // E2BIG
    let mut qs = QUEUES.lock();
    let q = qs.get_mut(&msqid).ok_or(-43isize)?; // EIDRM / EINVAL
    // Check write permission.
    if !check_perm(&q.ds.msg_perm, 0, 0, 0o2) { return Err(-13); } // EACCES
    let new_bytes = q.ds.msg_cbytes + data.len() as u64;
    if new_bytes > q.ds.msg_qbytes {
        if msgflg & IPC_NOWAIT != 0 { return Err(-11); } // EAGAIN
        // Blocking: spin until space available (scheduler integration point).
        drop(qs);
        loop {
            core::hint::spin_loop();
            let mut qs2 = QUEUES.lock();
            let q2 = qs2.get_mut(&msqid).ok_or(-43isize)?;
            if q2.ds.msg_cbytes + data.len() as u64 <= q2.ds.msg_qbytes {
                q2.ds.msg_cbytes += data.len() as u64;
                q2.ds.msg_qnum   += 1;
                q2.ds.msg_stime   = crate::time::clock::time_secs();
                q2.messages.push_back(Message { mtype, data });
                return Ok(());
            }
        }
    }
    q.ds.msg_cbytes += data.len() as u64;
    q.ds.msg_qnum   += 1;
    q.ds.msg_stime   = crate::time::clock::time_secs();
    q.messages.push_back(Message { mtype, data });
    Ok(())
}

// ── msgrcv ────────────────────────────────────────────────────────────────────────────

/// Receive a message.  Returns `(mtype, data)` or an error.
/// `msgsz` is the maximum `mtext` size the caller can accept.
pub fn msgrcv(
    msqid:   i32,
    msgsz:   usize,
    msgtyp:  i64,
    msgflg:  i32,
) -> Result<(i64, Vec<u8>), isize> {
    loop {
        let mut qs = QUEUES.lock();
        let q = qs.get_mut(&msqid).ok_or(-43isize)?;
        if !check_perm(&q.ds.msg_perm, 0, 0, 0o4) { return Err(-13); }
        let idx = find_message(&q.messages, msgtyp);
        if let Some(i) = idx {
            let msg = q.messages.remove(i).unwrap();
            if msg.data.len() > msgsz {
                // MSG_NOERROR not set: return E2BIG.
                if msgflg & 0o10000 == 0 {
                    q.messages.insert(i, msg);
                    return Err(-7); // E2BIG
                }
                // MSG_NOERROR: truncate.
                let data = msg.data[..msgsz].to_vec();
                q.ds.msg_cbytes  = q.ds.msg_cbytes.saturating_sub(msg.data.len() as u64);
                q.ds.msg_qnum   -= 1;
                q.ds.msg_rtime   = crate::time::clock::time_secs();
                return Ok((msg.mtype, data));
            }
            q.ds.msg_cbytes  = q.ds.msg_cbytes.saturating_sub(msg.data.len() as u64);
            q.ds.msg_qnum   -= 1;
            q.ds.msg_rtime   = crate::time::clock::time_secs();
            return Ok((msg.mtype, msg.data));
        }
        // No matching message.
        if msgflg & IPC_NOWAIT != 0 { return Err(-11); } // EAGAIN
        drop(qs);
        core::hint::spin_loop();
    }
}

fn find_message(q: &VecDeque<Message>, msgtyp: i64) -> Option<usize> {
    if msgtyp == 0 {
        if q.is_empty() { None } else { Some(0) }
    } else if msgtyp > 0 {
        q.iter().position(|m| m.mtype == msgtyp)
    } else {
        // First with mtype <= abs(msgtyp), prefer smallest mtype.
        let limit = (-msgtyp) as i64;
        let mut best: Option<(usize, i64)> = None;
        for (i, m) in q.iter().enumerate() {
            if m.mtype <= limit {
                if best.is_none() || m.mtype < best.unwrap().1 {
                    best = Some((i, m.mtype));
                }
            }
        }
        best.map(|(i, _)| i)
    }
}

// ── msgctl ────────────────────────────────────────────────────────────────────────────

pub fn msgctl(msqid: i32, cmd: i32) -> Result<MsqidDs, isize> {
    let mut qs = QUEUES.lock();
    match cmd {
        IPC_RMID => {
            qs.remove(&msqid).ok_or(-43isize)?;
            Ok(MsqidDs::default())
        }
        IPC_STAT | MSG_STAT => {
            let q = qs.get(&msqid).ok_or(-43isize)?;
            Ok(q.ds)
        }
        IPC_SET => {
            // Caller sets ds.msg_perm / msg_qbytes then calls IPC_SET.
            // We return the current ds; the syscall layer merges the fields.
            let q = qs.get(&msqid).ok_or(-43isize)?;
            Ok(q.ds)
        }
        _ => Err(-22), // EINVAL
    }
}

pub fn msgctl_set(msqid: i32, new_ds: MsqidDs) -> Result<(), isize> {
    let mut qs = QUEUES.lock();
    let q = qs.get_mut(&msqid).ok_or(-43isize)?;
    q.ds.msg_perm.uid  = new_ds.msg_perm.uid;
    q.ds.msg_perm.gid  = new_ds.msg_perm.gid;
    q.ds.msg_perm.mode = new_ds.msg_perm.mode & 0o777;
    q.ds.msg_qbytes    = new_ds.msg_qbytes.min(MSGMNB as u64);
    q.ds.msg_ctime     = crate::time::clock::time_secs();
    Ok(())
}
