//! System V message queues.
//!
//! ## API
//!
//! | Function                                      | Returns   |
//! |-----------------------------------------------|------------|
//! | `msgget(key, msgflg)`                         | `msqid`   |
//! | `msgsnd(msqid, msgp, msgsz, msgflg)`          | `0`       |
//! | `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)` | `ssize_t` |
//! | `msgctl(msqid, cmd, buf)`                     | varies    |
//!
//! ## `struct msgbuf` layout (matches Linux UAPI)
//!
//! ```c
//! long  mtype;   // message type, must be > 0
//! char  mtext[]; // message data
//! ```
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
use alloc::{
    collections::VecDeque,
    string::String,
    sync::Arc,
    vec::Vec,
};
use spin::Mutex;
use crate::ipc::{check_perm, IpcPerm, IPC_CREAT, IPC_EXCL, IPC_NOWAIT, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT};

pub const MSGMAX:  usize = 8192;
pub const MSGMNB:  usize = 16384; // default max queue size in bytes
pub const MSGMNI:  i32   = 32000; // system-wide queue limit

/// One queued message.
struct Message {
    mtype: i64,
    data:  Vec<u8>,
}

/// Kernel-side message queue.
struct MsgQueue {
    perm:      IpcPerm,
    messages:  VecDeque<Message>,
    msg_cbytes: usize, // current bytes in queue
    msg_qnum:  usize,
    msg_qbytes: usize, // max bytes allowed
    msg_lspid: u32,
    msg_lrpid: u32,
    msg_stime: u64,
    msg_rtime: u64,
    msg_ctime: u64,
}

use alloc::collections::BTreeMap;
static MSG_TABLE: Mutex<BTreeMap<i32, Arc<Mutex<MsgQueue>>>> = Mutex::new(BTreeMap::new());
static NEXT_ID:   spin::Mutex<i32>                           = spin::Mutex::new(1);

fn alloc_id() -> i32 {
    let mut id = NEXT_ID.lock();
    let v = *id;
    *id += 1;
    v
}

pub fn msgget(key: i32, msgflg: i32) -> Result<i32, isize> {
    let mut tbl = MSG_TABLE.lock();

    // IPC_PRIVATE — always create a new private queue.
    if key == IPC_PRIVATE {
        let id = alloc_id();
        let q  = MsgQueue {
            perm:       IpcPerm::new(IPC_PRIVATE, 0, 0, (msgflg & 0o777) as u16),
            messages:   VecDeque::new(),
            msg_cbytes: 0,
            msg_qnum:   0,
            msg_qbytes: MSGMNB,
            msg_lspid:  0,
            msg_lrpid:  0,
            msg_stime:  0,
            msg_rtime:  0,
            msg_ctime:  0,
        };
        tbl.insert(id, Arc::new(Mutex::new(q)));
        return Ok(id);
    }

    // Look for an existing queue with matching key.
    if let Some((&id, _)) = tbl.iter().find(|(_, q)| q.lock().perm.key == key) {
        if msgflg & IPC_CREAT != 0 && msgflg & IPC_EXCL != 0 {
            return Err(-17); // EEXIST
        }
        return Ok(id);
    }

    if msgflg & IPC_CREAT == 0 { return Err(-2); } // ENOENT

    let id = alloc_id();
    let q  = MsgQueue {
        perm:       IpcPerm::new(key, 0, 0, (msgflg & 0o777) as u16),
        messages:   VecDeque::new(),
        msg_cbytes: 0,
        msg_qnum:   0,
        msg_qbytes: MSGMNB,
        msg_lspid:  0,
        msg_lrpid:  0,
        msg_stime:  0,
        msg_rtime:  0,
        msg_ctime:  0,
    };
    tbl.insert(id, Arc::new(Mutex::new(q)));
    Ok(id)
}

pub fn msgsnd(msqid: i32, mtype: i64, data: Vec<u8>, msgflg: i32) -> Result<(), isize> {
    if mtype <= 0 { return Err(-22); } // EINVAL — mtype must be positive
    if data.len() > MSGMAX { return Err(-90); } // EMSGSIZE

    loop {
        let arc = {
            let tbl = MSG_TABLE.lock();
            tbl.get(&msqid).cloned().ok_or(-43isize)? // EIDRM
        };
        let mut q = arc.lock();

        if !check_perm(&q.perm, 0, 0, 0o2) { return Err(-13); } // EACCES

        let needed = data.len();
        if q.msg_cbytes + needed > q.msg_qbytes {
            if msgflg & IPC_NOWAIT != 0 { return Err(-11); } // EAGAIN
            drop(q);
            core::hint::spin_loop(); continue;
        }
        q.msg_cbytes += needed;
        q.msg_qnum   += 1;
        q.msg_lspid   = crate::proc::scheduler::current_pid() as u32;
        q.messages.push_back(Message { mtype, data });
        return Ok(());
    }
}

pub fn msgrcv(
    msqid:   i32,
    msgsz:   usize,
    msgtyp:  i64,
    msgflg:  i32,
) -> Result<(i64, Vec<u8>), isize> {
    loop {
        let arc = {
            let tbl = MSG_TABLE.lock();
            tbl.get(&msqid).cloned().ok_or(-43isize)?
        };
        let mut q = arc.lock();

        if !check_perm(&q.perm, 0, 0, 0o4) { return Err(-13); } // EACCES

        // Find the target message index.
        let idx = if msgtyp == 0 {
            if q.messages.is_empty() { None } else { Some(0) }
        } else if msgtyp > 0 {
            q.messages.iter().position(|m| m.mtype == msgtyp)
        } else {
            let abs_typ = (-msgtyp) as i64;
            q.messages.iter().enumerate()
                .filter(|(_, m)| m.mtype <= abs_typ)
                .min_by_key(|(_, m)| m.mtype)
                .map(|(i, _)| i)
        };

        if let Some(i) = idx {
            let msg = q.messages.remove(i).unwrap();
            if msg.data.len() > msgsz {
                // MSG_NOERROR not implemented — return EMSGSIZE.
                q.messages.insert(i, msg).ok();
                return Err(-90);
            }
            q.msg_cbytes = q.msg_cbytes.saturating_sub(msg.data.len());
            q.msg_qnum   = q.msg_qnum.saturating_sub(1);
            q.msg_lrpid  = crate::proc::scheduler::current_pid() as u32;
            return Ok((msg.mtype, msg.data));
        }

        if msgflg & IPC_NOWAIT != 0 { return Err(-11); } // ENOMSG
        drop(q);
        core::hint::spin_loop();
    }
}

/// `IPC_RMID`: remove the queue.  Other commands are stubs.
pub fn msgctl(msqid: i32, cmd: i32) -> Result<i32, isize> {
    match cmd {
        c if c == IPC_RMID => {
            MSG_TABLE.lock().remove(&msqid).ok_or(-43isize)?;
            Ok(0)
        }
        c if c == IPC_STAT => Ok(0), // caller must copy msqid_ds themselves
        c if c == IPC_SET  => Ok(0),
        _ => Err(-22),
    }
}
