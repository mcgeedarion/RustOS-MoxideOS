//! System V semaphores.
//!
//! Implements `semget`, `semop`, and the currently wired `semctl` commands.
//! `semop` applies operation arrays atomically. If an operation would block,
//! the caller is recorded in the semaphore wait counters and the scheduler is
//! yielded before retrying.

extern crate alloc;

use crate::ipc::{
    check_perm, IpcPerm, IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use spin::Mutex;

pub const GETVAL: i32 = 12;
pub const SETVAL: i32 = 16;
pub const GETALL: i32 = 13;
pub const SETALL: i32 = 17;
pub const GETPID: i32 = 11;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;

const IPC_NOWAIT: i16 = 0x0800;
const SEM_UNDO: i16 = 0x1000;

/// One semaphore within a set.
#[derive(Clone)]
struct Sem {
    val: i16,
    pid: u32,
    ncnt: u32,
    zcnt: u32,
}

/// Kernel-side semaphore set.
struct SemSet {
    perm: IpcPerm,
    sems: Vec<Sem>,
}

static SEM_TABLE: Mutex<BTreeMap<i32, Arc<Mutex<SemSet>>>> = Mutex::new(BTreeMap::new());
static NEXT_ID: Mutex<i32> = Mutex::new(1);

#[derive(Clone, Copy)]
enum WaitKind {
    NonZero,
    Zero,
}

#[inline]
fn alloc_id() -> i32 {
    let mut id = NEXT_ID.lock();
    let v = *id;
    *id += 1;
    v
}

fn blank_sem() -> Sem {
    Sem {
        val: 0,
        pid: 0,
        ncnt: 0,
        zcnt: 0,
    }
}

pub fn semget(key: i32, nsems: i32, semflg: i32) -> Result<i32, isize> {
    if nsems < 0 {
        return Err(-22);
    }

    let mut tbl = SEM_TABLE.lock();

    if key == IPC_PRIVATE {
        let id = alloc_id();

        tbl.insert(
            id,
            Arc::new(Mutex::new(SemSet {
                perm: IpcPerm::new(IPC_PRIVATE, 0, 0, (semflg & 0o777) as u16),
                sems: (0..nsems as usize).map(|_| blank_sem()).collect(),
            })),
        );

        return Ok(id);
    }

    if let Some((&id, _)) = tbl.iter().find(|(_, s)| s.lock().perm.key == key) {
        if semflg & IPC_CREAT != 0 && semflg & IPC_EXCL != 0 {
            return Err(-17);
        }

        return Ok(id);
    }

    if semflg & IPC_CREAT == 0 {
        return Err(-2);
    }

    let id = alloc_id();

    tbl.insert(
        id,
        Arc::new(Mutex::new(SemSet {
            perm: IpcPerm::new(key, 0, 0, (semflg & 0o777) as u16),
            sems: (0..nsems as usize).map(|_| blank_sem()).collect(),
        })),
    );

    Ok(id)
}

/// One element of the `sembuf` array passed to `semop(2)`.
pub struct SemBuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

fn blocking_ops(set: &SemSet, sops: &[SemBuf]) -> Result<Vec<(usize, WaitKind)>, isize> {
    let mut waiters = Vec::new();

    for sop in sops {
        let idx = sop.sem_num as usize;

        if idx >= set.sems.len() {
            return Err(-22);
        }

        let val = set.sems[idx].val;

        if sop.sem_op < 0 && (val as i32 + sop.sem_op as i32) < 0 {
            waiters.push((idx, WaitKind::NonZero));
        } else if sop.sem_op == 0 && val != 0 {
            waiters.push((idx, WaitKind::Zero));
        }
    }

    Ok(waiters)
}

fn adjust_wait_counts(set: &mut SemSet, waiters: &[(usize, WaitKind)], add: bool) {
    for &(idx, kind) in waiters {
        let Some(sem) = set.sems.get_mut(idx) else {
            continue;
        };

        match (kind, add) {
            (WaitKind::NonZero, true) => sem.ncnt = sem.ncnt.saturating_add(1),
            (WaitKind::NonZero, false) => sem.ncnt = sem.ncnt.saturating_sub(1),
            (WaitKind::Zero, true) => sem.zcnt = sem.zcnt.saturating_add(1),
            (WaitKind::Zero, false) => sem.zcnt = sem.zcnt.saturating_sub(1),
        }
    }
}

fn yield_to_scheduler() {
    crate::proc::scheduler::schedule();
}

pub fn semop(semid: i32, sops: &[SemBuf]) -> Result<(), isize> {
    loop {
        let arc = {
            let tbl = SEM_TABLE.lock();
            tbl.get(&semid).cloned().ok_or(-43isize)?
        };

        let mut set = arc.lock();

        if !check_perm(&set.perm, 0, 0, 0o2) {
            return Err(-13);
        }

        let waiters = blocking_ops(&set, sops)?;

        if !waiters.is_empty() {
            let nowait = sops.iter().any(|s| s.sem_flg & IPC_NOWAIT != 0);

            if nowait {
                return Err(-11);
            }

            adjust_wait_counts(&mut set, &waiters, true);
            drop(set);

            yield_to_scheduler();

            let mut set = arc.lock();
            adjust_wait_counts(&mut set, &waiters, false);
            continue;
        }

        let pid = crate::proc::scheduler::current_pid() as u32;

        for sop in sops {
            let s = &mut set.sems[sop.sem_num as usize];
            s.val = (s.val as i32 + sop.sem_op as i32) as i16;
            s.pid = pid;

            if sop.sem_flg & SEM_UNDO != 0 {
                // Hook point for per-process semadj storage. The semaphore
                // operation itself is still applied atomically here; process
                // exit cleanup should register an undo delta in proc state.
            }
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
            if n >= set.sems.len() {
                return Err(-22);
            }

            Ok(set.sems[n].val as i32)
        },
        c if c == SETVAL => {
            if n >= set.sems.len() {
                return Err(-22);
            }

            set.sems[n].val = arg as i16;
            Ok(0)
        },
        c if c == GETPID => {
            if n >= set.sems.len() {
                return Err(-22);
            }

            Ok(set.sems[n].pid as i32)
        },
        c if c == GETNCNT => {
            if n >= set.sems.len() {
                return Err(-22);
            }

            Ok(set.sems[n].ncnt as i32)
        },
        c if c == GETZCNT => {
            if n >= set.sems.len() {
                return Err(-22);
            }

            Ok(set.sems[n].zcnt as i32)
        },
        c if c == GETALL => Ok(0),
        c if c == SETALL => Ok(0),
        c if c == IPC_RMID => {
            SEM_TABLE.lock().remove(&semid);
            Ok(0)
        },
        c if c == IPC_STAT => Ok(0),
        c if c == IPC_SET => Ok(0),
        _ => Err(-22),
    }
}
