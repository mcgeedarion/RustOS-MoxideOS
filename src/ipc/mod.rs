//! IPC subsystem.
//!
//! | Module        | Facility                                                      |
//! |---------------|---------------------------------------------------------------|
//! | `key`         | `ftok`, IPC key ↔ ID mapping, `IPC_PRIVATE`                  |
//! | `msg`         | System V message queues (`msgget`/`msgsnd`/`msgrcv`/`msgctl`)|
//! | `sem`         | System V semaphores (`semget`/`semop`/`semctl`)               |
//! | `shm`         | System V shared memory (`shmget`/`shmat`/`shmdt`/`shmctl`)   |
//! | `mq`          | POSIX message queues (`mq_open`/`send`/`receive`/`notify`)    |
//! | `pipe_scheme` | Scheme-backed anonymous pipes; `create_pipe()` returns two   |
//! |               | `FdEntry::Scheme` descriptors backed by a shared `PipeScheme`.|
//!
//! ## Permissions
//!
//! All SysV objects store an `IpcPerm` with `uid/gid/cuid/cgid/mode`.
//! `check_perm(perm, uid, gid, access_bits)` enforces rwx on owner/group/other.
//! Capability checks (`CAP_IPC_OWNER`) are integration stubs.

extern crate alloc;

pub mod key;
pub mod mq;
pub mod msg;
pub mod pipe_scheme;
pub mod sem;
pub mod shm;

// ── Common IPC permission structure ───────────────────────────────────────────

/// `struct ipc_perm` — matches Linux x86_64 UAPI layout.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct IpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u16,
    pub seq: u16,
    _pad: [u8; 4],
}

impl IpcPerm {
    #[inline]
    pub fn new(key: i32, uid: u32, gid: u32, mode: u16) -> Self {
        IpcPerm {
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode,
            seq: 0,
            _pad: [0; 4],
        }
    }
}

/// Returns `true` if `uid`/`gid` has the `need` permission bits on `perm`.
/// `need`: 0o4 = read, 0o2 = write.
#[inline]
pub fn check_perm(perm: &IpcPerm, uid: u32, gid: u32, need: u16) -> bool {
    if uid == 0 {
        return true;
    } // root bypass
    let shift = if uid == perm.uid {
        6
    } else if gid == perm.gid {
        3
    } else {
        0
    };
    (perm.mode >> shift) & need == need
}

// ── Common IPC flags / commands ───────────────────────────────────────────────

pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: i32 = 0o001000;
pub const IPC_EXCL: i32 = 0o002000;
pub const IPC_NOWAIT: i32 = 0o004000;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;
