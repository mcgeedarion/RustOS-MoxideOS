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

// ====================================================================
// Userspace driver IPC entry points.
//
// Hybrid-kernel service servers use endpoints with two independent queues:
// kernel -> server requests/IRQ notifications, and server -> kernel replies.
// This keeps `IpcProxyScheme` synchronous while still letting userspace
// drivers block in `sys_ipc_recv()` for work.
// ====================================================================

use alloc::{collections::BTreeMap, collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use scheme_api::IpcEndpoint;
use spin::Mutex;

const IPC_MAX_MESSAGE: usize = 64 * 1024;
const IPC_MAX_QUEUE_DEPTH: usize = 128;

#[derive(Debug)]
struct EndpointState {
    owner_pid: usize,
    to_server: VecDeque<Vec<u8>>,
    to_kernel: VecDeque<Vec<u8>>,
}

static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(1);
static ENDPOINTS: Mutex<BTreeMap<u64, EndpointState>> = Mutex::new(BTreeMap::new());

fn valid_message_len(len: usize) -> bool {
    len <= IPC_MAX_MESSAGE
}

/// Create an IPC endpoint owned by the current process.
pub fn endpoint_create_for_current() -> IpcEndpoint {
    let id = NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed);
    ENDPOINTS.lock().insert(
        id,
        EndpointState {
            owner_pid: crate::proc::scheduler::current_pid() as usize,
            to_server: VecDeque::new(),
            to_kernel: VecDeque::new(),
        },
    );
    IpcEndpoint(id)
}

/// Return true if an endpoint exists.
pub fn endpoint_exists(endpoint: IpcEndpoint) -> bool {
    ENDPOINTS.lock().contains_key(&endpoint.0)
}

/// Return true if the current process owns an endpoint.
pub fn endpoint_owned_by_current(endpoint: IpcEndpoint) -> bool {
    let pid = crate::proc::scheduler::current_pid() as usize;
    ENDPOINTS
        .lock()
        .get(&endpoint.0)
        .map(|ep| ep.owner_pid == pid)
        .unwrap_or(false)
}

/// Remove all endpoints owned by `pid`.
pub fn endpoint_cleanup_pid(pid: usize) {
    ENDPOINTS.lock().retain(|_, ep| ep.owner_pid != pid);
}

/// Send bytes from the kernel to a userspace driver/service.
pub fn endpoint_send(endpoint: IpcEndpoint, bytes: &[u8]) -> Result<(), ()> {
    if !valid_message_len(bytes.len()) {
        return Err(());
    }
    let mut endpoints = ENDPOINTS.lock();
    let ep = endpoints.get_mut(&endpoint.0).ok_or(())?;
    if ep.to_server.len() >= IPC_MAX_QUEUE_DEPTH {
        return Err(());
    }
    ep.to_server.push_back(bytes.to_vec());
    Ok(())
}

/// Receive bytes sent from a userspace driver/service back to the kernel.
pub fn endpoint_recv(endpoint: IpcEndpoint) -> Result<Vec<u8>, ()> {
    ENDPOINTS
        .lock()
        .get_mut(&endpoint.0)
        .and_then(|ep| ep.to_kernel.pop_front())
        .ok_or(())
}

/// Queue an IRQ notification or control message for the userspace endpoint.
pub fn endpoint_notify_server(endpoint: IpcEndpoint, bytes: &[u8]) -> Result<(), ()> {
    endpoint_send(endpoint, bytes)
}

/// Userspace-facing endpoint creation syscall.
pub fn sys_ipc_endpoint_create() -> isize {
    endpoint_create_for_current().0 as isize
}

/// Userspace-facing receive syscall: pop kernel->server work into `buf`.
pub fn sys_ipc_recv(endpoint: u64, buf_va: usize, buf_len: usize) -> isize {
    if buf_len == 0 || !crate::uaccess::validate_user_ptr(buf_va, buf_len) {
        return -14; // EFAULT
    }
    let endpoint = IpcEndpoint(endpoint);
    if !endpoint_owned_by_current(endpoint) {
        return -1; // EPERM
    }

    let msg = match ENDPOINTS
        .lock()
        .get_mut(&endpoint.0)
        .and_then(|ep| ep.to_server.pop_front())
    {
        Some(msg) => msg,
        None => return -11, // EAGAIN; scheduler integration can block later.
    };

    let n = msg.len().min(buf_len);
    if crate::uaccess::copy_to_user(buf_va, msg.as_ptr(), n).is_err() {
        return -14;
    }
    n as isize
}

/// Userspace-facing send syscall: push a server->kernel reply.
pub fn sys_ipc_send(endpoint: u64, buf_va: usize, buf_len: usize) -> isize {
    if !valid_message_len(buf_len) || !crate::uaccess::validate_user_ptr(buf_va, buf_len) {
        return -14; // EFAULT / oversized user message
    }
    let endpoint = IpcEndpoint(endpoint);
    if !endpoint_owned_by_current(endpoint) {
        return -1; // EPERM
    }

    let mut msg = alloc::vec![0u8; buf_len];
    if crate::uaccess::copy_from_user(msg.as_mut_ptr(), buf_va, buf_len).is_err() {
        return -14;
    }

    let mut endpoints = ENDPOINTS.lock();
    let ep = match endpoints.get_mut(&endpoint.0) {
        Some(ep) => ep,
        None => return -111, // ECONNREFUSED
    };
    if ep.to_kernel.len() >= IPC_MAX_QUEUE_DEPTH {
        return -11; // EAGAIN
    }
    ep.to_kernel.push_back(msg);
    buf_len as isize
}

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

pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: i32 = 0o001000;
pub const IPC_EXCL: i32 = 0o002000;
pub const IPC_NOWAIT: i32 = 0o004000;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;
