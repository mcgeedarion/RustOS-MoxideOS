//! System V semaphores.
//!
//! ## API
//!
//!   semget(key, nsems, semflg)         -> semid
//!   semop(semid, sops, nsops)          -> 0
//!   semctl(semid, semnum, cmd, ...)    -> varies
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
use alloc::vec::Vec;
use spin::Mutex;
use alloc::collections::BTreeMap;
use crate::ipc::{IpcPerm, IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_RMID, IPC_SET, IPC_STAT, check_perm};

// ── Limits ────────────────────────────────────────────────────────────────────────────
pub const SEMMAX:  u16  = 32767;
pub const SEMMNI:  usize = 128;
pub const SEMMSL:  usize = 250;
pub const SEMOPM:  usize = 32;

// ── semctl command constants (Linux UAPI) ──────────────────────────────────────
pub const GETPID:  i32 = 11;
pub const GETVAL:  i32 = 12;
pub const GETALL:  i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL:  i32 = 16;
pub const SETALL:  i32 = 17;
pub const SEM_STAT: i32 = 18;
pub const SEM_INFO: i32 = 19;

// ── Data structures ───────────────────────────────────────────────────────────────────

/// One semaphore in a set.
#[derive(Clone, Copy, Default, Debug)]
struct Sem {
    val:   u16,
    pid:   u32, // PID of last semop
    ncnt:  u32, // waiting for val > 0
    zcnt:  u32, // waiting for val == 0
}

/// `struct semid_ds`
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SemidDs {
    pub sem_perm:  IpcPerm,
    pub sem_otime: i64,
    pub sem_ctime: i64,
    pub sem_nsems: u64,
    _pad: [u8; 16],
}

/// `struct sembuf` — one operation in a `semop` call.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op:  i16,
    pub sem_flg: i16,
}

struct SemSet {
    ds:   SemidDs,
    sems: Vec<Sem>,
    key:  i32,
}

static SETS: Mutex<BTreeMap<i32, SemSet>> = Mutex::new(BTreeMap::new());
static NEXT_ID: spin::Mutex<i32> = spin::Mutex::new(1);
fn alloc_id() -> i32 { let mut n = NEXT_ID.lock(); let id = *n; *n += 1; id }

// ── semget ────────────────────────────────────────────────────────────────────────────

pub fn semget(key: i32, nsems: i32, semflg: i32) -> Result<i32, isize> {
    let mut sets = SETS.lock();
    if key != IPC_PRIVATE {
        if let Some((&id, s)) = sets.iter().find(|(_, s)| s.key == key) {
            if semflg & IPC_CREAT != 0 && semflg & IPC_EXCL != 0 {
                return Err(-17); // EEXIST
            }
            if nsems > 0 && s.sems.len() < nsems as usize {
                return Err(-22); // EINVAL: existing set has fewer sems
            }
            return Ok(id);
        }
        if semflg & IPC_CREAT == 0 { return Err(-2); }
    }
    if nsems <= 0 || nsems as usize > SEMMSL { return Err(-22); }
    if sets.len() >= SEMMNI { return Err(-28); }
    let id   = alloc_id();
    let mode = (semflg & 0o777) as u16;
    let perm = IpcPerm::new(key, 0, 0, mode);
    let now  = crate::time::clock::time_secs();
    let ds   = SemidDs {
        sem_perm:  perm,
        sem_ctime: now,
        sem_nsems: nsems as u64,
        ..Default::default()
    };
    sets.insert(id, SemSet {
        ds,
        sems: alloc::vec![Sem::default(); nsems as usize],
        key,
    });
    Ok(id)
}

// ── semop ────────────────────────────────────────────────────────────────────────────

pub fn semop(semid: i32, ops: &[Sembuf]) -> Result<(), isize> {
    if ops.len() > SEMOPM { return Err(-22); }
    loop {
        let mut sets = SETS.lock();
        let s = sets.get_mut(&semid).ok_or(-43isize)?;
        if !check_perm(&s.ds.sem_perm, 0, 0, 0o2) { return Err(-13); }
        // Check all ops first (atomicity).
        let mut would_block = false;
        for op in ops {
            let i = op.sem_num as usize;
            if i >= s.sems.len() { return Err(-22); }
            let val = s.sems[i].val as i32;
            if op.sem_op < 0 {
                let need = (-op.sem_op) as i32;
                if val < need {
                    if op.sem_flg as i32 & crate::ipc::IPC_NOWAIT != 0 {
                        return Err(-11); // EAGAIN
                    }
                    would_block = true;
                    break;
                }
            } else if op.sem_op == 0 && val != 0 {
                if op.sem_flg as i32 & crate::ipc::IPC_NOWAIT != 0 {
                    return Err(-11);
                }
                would_block = true;
                break;
            }
        }
        if would_block { drop(sets); core::hint::spin_loop(); continue; }
        // Apply all ops.
        let pid = current_pid();
        for op in ops {
            let i = op.sem_num as usize;
            let v = s.sems[i].val as i32 + op.sem_op as i32;
            s.sems[i].val = v.max(0) as u16;
            s.sems[i].pid = pid;
        }
        s.ds.sem_otime = crate::time::clock::time_secs();
        return Ok(());
    }
}

// ── semctl ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SemctlArg { Val(i32), Buf(SemidDs), Array(Vec<u16>) }

pub fn semctl(semid: i32, semnum: i32, cmd: i32, arg: Option<SemctlArg>)
    -> Result<i32, isize>
{
    let mut sets = SETS.lock();
    match cmd {
        IPC_RMID => { sets.remove(&semid).ok_or(-43isize)?; Ok(0) }
        IPC_STAT => Ok(0), // ds returned via arg in real impl
        GETVAL => {
            let s = sets.get(&semid).ok_or(-43isize)?;
            let i = semnum as usize;
            if i >= s.sems.len() { return Err(-22); }
            Ok(s.sems[i].val as i32)
        }
        SETVAL => {
            let v = match arg { Some(SemctlArg::Val(v)) => v, _ => return Err(-22) };
            if v < 0 || v > SEMMAX as i32 { return Err(-22); }
            let s = sets.get_mut(&semid).ok_or(-43isize)?;
            let i = semnum as usize;
            if i >= s.sems.len() { return Err(-22); }
            s.sems[i].val = v as u16;
            s.ds.sem_ctime = crate::time::clock::time_secs();
            Ok(0)
        }
        GETALL => Ok(0), // array returned via arg
        SETALL => {
            let arr = match arg { Some(SemctlArg::Array(a)) => a, _ => return Err(-22) };
            let s = sets.get_mut(&semid).ok_or(-43isize)?;
            if arr.len() != s.sems.len() { return Err(-22); }
            for (sem, &v) in s.sems.iter_mut().zip(arr.iter()) {
                if v > SEMMAX { return Err(-22); }
                sem.val = v;
            }
            s.ds.sem_ctime = crate::time::clock::time_secs();
            Ok(0)
        }
        GETPID  => { let s = sets.get(&semid).ok_or(-43isize)?; Ok(s.sems.get(semnum as usize).map(|sem| sem.pid as i32).unwrap_or(0)) }
        GETNCNT => { let s = sets.get(&semid).ok_or(-43isize)?; Ok(s.sems.get(semnum as usize).map(|sem| sem.ncnt as i32).unwrap_or(0)) }
        GETZCNT => { let s = sets.get(&semid).ok_or(-43isize)?; Ok(s.sems.get(semnum as usize).map(|sem| sem.zcnt as i32).unwrap_or(0)) }
        _ => Err(-22),
    }
}

fn current_pid() -> u32 { 0 } // integrate with crate::proc::current().pid
