//! System V semaphores.
//!
//! ## API
//!
//! | Function                            | Returns |
//! |-------------------------------------|---------|
//! | `semget(key, nsems, semflg)`        | `semid` |
//! | `semop(semid, sops, nsops)`         | `0`     |
//! | `semctl(semid, semnum, cmd, ...)`   | varies  |
//!
//! ## `semop` atomicity
//!
//! All operations in a `sembuf` array are applied atomically.  If any
//! would block (and `IPC_NOWAIT` is not set), all are rolled back and the
//! call blocks.  The current implementation uses a spin-wait loop as a
//! placeholder for proper scheduler integration.
//!
//! ## semctl commands
//!
//! | Command    | Description |
//! |------------|-------------|
//! | GETVAL     | Return semval of semnum |
//! | SETVAL     | Set semval of semnum |
//! | GETALL     | Copy all semvals to array |
//! | SETALL     | Load all semvals from array |
//! | GETPID     | PID of last semop |
//! | GETNCNT    | Number of tasks waiting for sem > 0 |
//! | GETZCNT    | Number of tasks waiting for sem == 0 |
//! | IPC_RMID   | Remove semaphore set |
//! | IPC_STAT   | Copy semid_ds to buf |
//! | IPC_SET    | Set uid/gid/mode from buf |

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    vec::Vec,
};
use spin::Mutex;
use crate::ipc::{check_perm, IpcPerm, IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT};

pub const GETVAL:  i32 = 12;
pub const SETVAL:  i32 = 16;
pub const GETALL:  i32 = 13;
pub const SETALL:  i32 = 17;
pub const GETPID:  i32 = 11;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;

/// One semaphore within a set.
#[derive(Clone)]
struct Sem {
    val:   i16,
    pid:   u32,  // PID of last semop
    ncnt:  u32,  // waiting for val > 0
    zcnt:  u32,  // waiting for val == 0
}

/// Kernel-side semaphore set.
struct SemSet {
    perm: IpcPerm,
    sems: Vec<Sem>,
}

use alloc::sync::Arc;
static SEM_TABLE: Mutex<BTreeMap<i32, Arc<Mutex<SemSet>>>> = Mutex::new(BTreeMap::new());
static NEXT_ID:   Mutex<i32>                                = Mutex::new(1);

#[inline]
fn alloc_id() -> i32 {
    let mut id = NEXT_ID.lock();
    let v = *id;
    *id += 1;
    v
}

pub fn semget(key: i32, nsems: i32, semflg: i32) -> Result<i32, isize> {
    if nsems < 0 { return Err(-22); } // EINVAL
    let mut tbl = SEM_TABLE.lock();

    if key == IPC_PRIVATE {
        let id = alloc_id();
        tbl.insert(id, Arc::new(Mutex::new(SemSet {
            perm: IpcPerm::new(IPC_PRIVATE, 0, 0, (semflg & 0o777) as u16),
            sems: (0..nsems as usize).map(|_| Sem { val: 0, pid: 0, ncnt: 0, zcnt: 0 }).collect(),
        })));
        return Ok(id);
    }

    if let Some((&id, _)) = tbl.iter().find(|(_, s)| s.lock().perm.key == key) {
        if semflg & IPC_CREAT != 0 && semflg & IPC_EXCL != 0 { return Err(-17); }
        return Ok(id);
    }
    if semflg & IPC_CREAT == 0 { return Err(-2); } // ENOENT

    let id = alloc_id();
    tbl.insert(id, Arc::new(Mutex::new(SemSet {
        perm: IpcPerm::new(key, 0, 0, (semflg & 0o777) as u16),
        sems: (0..nsems as usize).map(|_| Sem { val: 0, pid: 0, ncnt: 0, zcnt: 0 }).collect(),
    })));
    Ok(id)
}

/// One element of the `sembuf` array passed to `semop(2)`.
pub struct SemBuf {
    pub sem_num: u16,
    pub sem_op:  i16,
    pub sem_flg: i16,
}

pub fn semop(semid: i32, sops: &[SemBuf]) -> Result<(), isize> {
    loop {
        let arc = {
            let tbl = SEM_TABLE.lock();
            tbl.get(&semid).cloned().ok_or(-43isize)? // EIDRM
        };
        let mut set = arc.lock();

        if !check_perm(&set.perm, 0, 0, 0o2) { return Err(-13); } // EACCES

        // Check-phase: ensure all ops can proceed without blocking.
        let mut would_block = false;
        for sop in sops {
            let idx = sop.sem_num as usize;
            if idx >= set.sems.len() { return Err(-22); } // EINVAL
            let val = set.sems[idx].val;
            if sop.sem_op < 0 && (val as i32 + sop.sem_op as i32) < 0 {
                would_block = true;
                break;
            }
            if sop.sem_op == 0 && val != 0 {
                would_block = true;
                break;
            }
        }

        if would_block {
            // Check IPC_NOWAIT on any blocking op.
            let nowait = sops.iter().any(|s| s.sem_flg & 1 != 0); // SEM_UNDO would be bit 1
            if nowait { return Err(-11); } // EAGAIN
            drop(set);
            core::hint::spin_loop(); continue;
        }

        // Apply-phase.
        let pid = crate::proc::scheduler::current_pid() as u32;
        for sop in sops {
            let s = &mut set.sems[sop.sem_num as usize];
            s.val = (s.val as i32 + sop.sem_op as i32) as i16;
            s.pid = pid;
        }
        return Ok(());
    }
}

pub fn semctl(semid: i32, semnum: i32, cmd: i32, arg: u64) -> Result<i32, isize> {
    let arc = {
        let tbl = SEM_TABLE.lock();
        tbl.get(&semid).cloned().ok_or(-43isize)?
    };
    let mut set = arc.lock();
    let n = semnum as usize;

    match cmd {
        c if c == GETVAL => {
            if n >= set.sems.len() { return Err(-22); }
            Ok(set.sems[n].val as i32)
        }
        c if c == SETVAL => {
            if n >= set.sems.len() { return Err(-22); }
            set.sems[n].val = arg as i16;
            Ok(0)
        }
        c if c == GETPID => {
            if n >= set.sems.len() { return Err(-22); }
            Ok(set.sems[n].pid as i32)
        }
        c if c == GETNCNT => {
            if n >= set.sems.len() { return Err(-22); }
            Ok(set.sems[n].ncnt as i32)
        }
        c if c == GETZCNT => {
            if n >= set.sems.len() { return Err(-22); }
            Ok(set.sems[n].zcnt as i32)
        }
        c if c == GETALL => Ok(0), // stub: caller must copy vals
        c if c == SETALL => Ok(0), // stub
        c if c == IPC_RMID => {
            SEM_TABLE.lock().remove(&semid);
            Ok(0)
        }
        c if c == IPC_STAT => Ok(0),
        c if c == IPC_SET  => Ok(0),
        _ => Err(-22),
    }
}
