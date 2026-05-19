//! x86-64 Linux syscall dispatch table for rustos.
//!
//! ## Architecture
//!
//! Syscall dispatch is split into three layers:
//!
//!   1. `dispatch_with_rip` (this file) — seccomp pre-check + router calls only.
//!      This function must stay thin.  No match arms live here.
//!
//!   2. `routers.rs` — five subsystem routers, each owning one logical group:
//!        dispatch_filesystem  fs I/O, stat, sockets, io_uring, pipes, epoll …
//!        dispatch_process     fork/exec/wait, signals, uid/gid, futex, prctl …
//!        dispatch_memory      mmap, mprotect, munmap, brk, madvise, pkey_* …
//!        dispatch_ipc         SysV shm/sem/msg, POSIX mq
//!        dispatch_time        clock_*, timers, getitimer, times
//!
//!   3. Implementation modules — the actual syscall logic lives in the
//!      subsystem modules (fs::*, proc::*, mm::*, ipc::*, …).
//!
//! ## Adding a new syscall
//!   1. Add the NR constant to `nr.rs`.
//!   2. Add a match arm in the correct router in `routers.rs`.
//!   3. Done — no changes to `dispatch_with_rip` required.
//!
//! ## Recently wired
//!   NR 425  io_uring_setup(entries, params)    => io_uring::syscall::sys_io_uring_setup
//!   NR 426  io_uring_enter(fd, …)              => io_uring::syscall::sys_io_uring_enter
//!   NR 427  io_uring_register(fd, op, arg, n)  => io_uring::syscall::sys_io_uring_register
//!   NR 41-55 socket syscalls (all 15)
//!   NR 288   accept4
//!   NR 318  getrandom(buf, count, flags)     => stubs::sys_getrandom_impl
//!   NR 334  close_range(first, last, flags)  => fs::close_range::sys_close_range
//!   NR 332  statx                            => posix_full::sys_statx_impl
//!   NR 326  copy_file_range                  => posix_full::sys_copy_file_range_impl
//!   NR 435  clone3                           => proc::clone::sys_clone3
//!   NR 437  openat2                          => openat2_mincore::sys_openat2_impl

#![allow(unused_variables, unused_imports)]
extern crate alloc;
use crate::fs::vfs;
use crate::fs::fcntl;
use alloc::string::String;
use alloc::vec::Vec;
use crate::ipc::{msg, sem, shm, mq};

// ── Named constant sub-modules ───────────────────────────────────────────────
pub mod nr;
pub mod errno;
pub mod signal_nr;
pub mod dispatcher_context;
pub mod routers;

use nr::{SYS_EXIT, SYS_EXIT_GROUP};
use errno::{efault, einval, enosys, emsgsize};
use signal_nr::SIGSYS;
use dispatcher_context::SyscallContext;

include!("p0_gaps.rs");
include!("openat2_mincore.rs");
include!("stubs.rs");
include!("posix_full.rs");

// Re-export helpers needed by posix_full.rs
pub(crate) use self::sys_readv_impl as sys_readv_impl;
pub(crate) use self::sys_pwrite64_impl as sys_pwrite64_impl;

/// Resolve a dirfd + path_va pair the same way stubs.rs does.
pub(crate) fn stubs_at_path(dirfd: i32, path_va: usize) -> Option<String> {
    const AT_FDCWD: i32 = -100;
    let path = crate::proc::exec::read_cstr_safe(path_va)?;
    if dirfd == AT_FDCWD || path.starts_with('/') {
        Some(path)
    } else {
        let dir = crate::fs::vfs::fd_to_path(dirfd as usize)
            .unwrap_or_else(|| String::from("/"));
        Some(alloc::format!("{}/{}", dir.trim_end_matches('/'), path))
    }
}

const EPOLL_CLOEXEC: u32 = 0x0008_0000;

#[inline(always)]
fn arg_u32(v: usize) -> Option<u32> {
    if v > u32::MAX as usize { None } else { Some(v as u32) }
}

/// Convert a raw syscall argument to `i32`, accepting sign-extended negatives.
#[inline(always)]
fn arg_i32(v: usize) -> Option<i32> {
    let hi = v >> 32;
    if hi == 0 || hi == 0xFFFF_FFFF {
        Some(v as i32)
    } else {
        None
    }
}

// ── Small inline helpers ─────────────────────────────────────────────────────

pub(crate) fn sys_epoll_create1(flags: u32) -> isize {
    let fd = crate::fs::poll::sys_epoll_create(0);
    if fd >= 0 && flags & EPOLL_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fd as usize, true);
    }
    fd
}

// ── NR 118 / 119: getresgid / getresgid32 ────────────────────────────────────
// Deduplicated into a single helper; both NRs route here.
#[inline]
pub(crate) fn copy_gid_to_user(a: usize, b: usize, c: usize) -> isize {
    let pid  = crate::proc::scheduler::current_pid();
    let gid  = crate::proc::scheduler::with_proc(pid, |p| p.cred.gid).unwrap_or(0);
    let bytes = gid.to_le_bytes();
    if a != 0 { let _ = crate::uaccess::copy_to_user(a, &bytes); }
    if b != 0 { let _ = crate::uaccess::copy_to_user(b, &bytes); }
    if c != 0 { let _ = crate::uaccess::copy_to_user(c, &bytes); }
    0
}

// ── NR 165: getresuid ────────────────────────────────────────────────────────
// Mirrors copy_gid_to_user; extracted from the inline arm in dispatch_process.
#[inline]
pub(crate) fn copy_uid_to_user(a: usize, b: usize, c: usize) -> isize {
    let pid  = crate::proc::scheduler::current_pid();
    let uid  = crate::proc::scheduler::with_proc(pid, |p| p.uid).unwrap_or(0);
    let bytes = uid.to_le_bytes();
    if a != 0 { let _ = crate::uaccess::copy_to_user(a, &bytes); }
    if b != 0 { let _ = crate::uaccess::copy_to_user(b, &bytes); }
    if c != 0 { let _ = crate::uaccess::copy_to_user(c, &bytes); }
    0
}

// ── IPC user-copy helpers ────────────────────────────────────────────────────

fn copy_msgbuf_from_user(msgp_va: usize, msgsz: usize) -> Option<(i64, Vec<u8>)> {
    if msgp_va == 0 || msgsz > msg::MSGMAX { return None; }
    let total = 8 + msgsz;
    let mut buf = alloc::vec![0u8; total];
    crate::uaccess::copy_from_user(&mut buf, msgp_va).ok()?;
    let mtype = i64::from_ne_bytes(buf[0..8].try_into().ok()?);
    let data  = buf[8..].to_vec();
    Some((mtype, data))
}

fn copy_msgbuf_to_user(msgp_va: usize, mtype: i64, data: &[u8]) -> bool {
    if msgp_va == 0 { return false; }
    let mut buf = alloc::vec![0u8; 8 + data.len()];
    buf[0..8].copy_from_slice(&mtype.to_ne_bytes());
    buf[8..].copy_from_slice(data);
    crate::uaccess::copy_to_user(msgp_va, &buf).is_ok()
}

fn copy_sembuf_from_user(sops_va: usize, nsops: usize) -> Option<Vec<sem::Sembuf>> {
    if sops_va == 0 || nsops == 0 || nsops > sem::SEMOPM { return None; }
    const SEMBUF_SIZE: usize = 8;
    let mut raw = alloc::vec![0u8; nsops * SEMBUF_SIZE];
    crate::uaccess::copy_from_user(&mut raw, sops_va).ok()?;
    let mut ops = Vec::with_capacity(nsops);
    for i in 0..nsops {
        let off = i * SEMBUF_SIZE;
        let num = u16::from_ne_bytes(raw[off..off+2].try_into().ok()?);
        let op  = i16::from_ne_bytes(raw[off+2..off+4].try_into().ok()?);
        let flg = i16::from_ne_bytes(raw[off+4..off+6].try_into().ok()?);
        ops.push(sem::Sembuf { sem_num: num, sem_op: op, sem_flg: flg });
    }
    Some(ops)
}

// ── Safe IPC struct parsers ───────────────────────────────────────────────────

fn parse_shmid_ds(buf: &[u8]) -> Option<shm::ShmidDs> {
    use core::mem::size_of;
    if buf.len() < size_of::<shm::ShmidDs>() { return None; }
    Some(shm::ShmidDs {
        shm_perm:   parse_ipc64_perm(&buf[0..48])?,
        shm_segsz:  usize::from_ne_bytes(buf[48..56].try_into().ok()?),
        shm_atime:  i64::from_ne_bytes(buf[56..64].try_into().ok()?),
        shm_dtime:  i64::from_ne_bytes(buf[64..72].try_into().ok()?),
        shm_ctime:  i64::from_ne_bytes(buf[72..80].try_into().ok()?),
        shm_cpid:   i32::from_ne_bytes(buf[80..84].try_into().ok()?),
        shm_lpid:   i32::from_ne_bytes(buf[84..88].try_into().ok()?),
        shm_nattch: u64::from_ne_bytes(buf[88..96].try_into().ok()?),
    })
}

fn serialize_shmid_ds(ds: &shm::ShmidDs) -> [u8; 96] {
    let mut buf = [0u8; 96];
    serialize_ipc64_perm(&ds.shm_perm, &mut buf[0..48]);
    buf[48..56].copy_from_slice(&ds.shm_segsz.to_ne_bytes());
    buf[56..64].copy_from_slice(&ds.shm_atime.to_ne_bytes());
    buf[64..72].copy_from_slice(&ds.shm_dtime.to_ne_bytes());
    buf[72..80].copy_from_slice(&ds.shm_ctime.to_ne_bytes());
    buf[80..84].copy_from_slice(&ds.shm_cpid.to_ne_bytes());
    buf[84..88].copy_from_slice(&ds.shm_lpid.to_ne_bytes());
    buf[88..96].copy_from_slice(&ds.shm_nattch.to_ne_bytes());
    buf
}

fn parse_msqid_ds(buf: &[u8]) -> Option<msg::MsqidDs> {
    use core::mem::size_of;
    if buf.len() < size_of::<msg::MsqidDs>() { return None; }
    Some(msg::MsqidDs {
        msg_perm:   parse_ipc64_perm(&buf[0..48])?,
        msg_stime:  i64::from_ne_bytes(buf[48..56].try_into().ok()?),
        msg_rtime:  i64::from_ne_bytes(buf[56..64].try_into().ok()?),
        msg_ctime:  i64::from_ne_bytes(buf[64..72].try_into().ok()?),
        msg_cbytes: u64::from_ne_bytes(buf[72..80].try_into().ok()?),
        msg_qnum:   u64::from_ne_bytes(buf[80..88].try_into().ok()?),
        msg_qbytes: u64::from_ne_bytes(buf[88..96].try_into().ok()?),
        msg_lspid:  i32::from_ne_bytes(buf[96..100].try_into().ok()?),
        msg_lrpid:  i32::from_ne_bytes(buf[100..104].try_into().ok()?),
    })
}

fn serialize_msqid_ds(ds: &msg::MsqidDs) -> [u8; 104] {
    let mut buf = [0u8; 104];
    serialize_ipc64_perm(&ds.msg_perm, &mut buf[0..48]);
    buf[48..56].copy_from_slice(&ds.msg_stime.to_ne_bytes());
    buf[56..64].copy_from_slice(&ds.msg_rtime.to_ne_bytes());
    buf[64..72].copy_from_slice(&ds.msg_ctime.to_ne_bytes());
    buf[72..80].copy_from_slice(&ds.msg_cbytes.to_ne_bytes());
    buf[80..88].copy_from_slice(&ds.msg_qnum.to_ne_bytes());
    buf[88..96].copy_from_slice(&ds.msg_qbytes.to_ne_bytes());
    buf[96..100].copy_from_slice(&ds.msg_lspid.to_ne_bytes());
    buf[100..104].copy_from_slice(&ds.msg_lrpid.to_ne_bytes());
    buf
}

fn parse_ipc64_perm(buf: &[u8]) -> Option<crate::ipc::Ipc64Perm> {
    if buf.len() < 48 { return None; }
    Some(crate::ipc::Ipc64Perm {
        key:  i32::from_ne_bytes(buf[0..4].try_into().ok()?),
        uid:  u32::from_ne_bytes(buf[4..8].try_into().ok()?),
        gid:  u32::from_ne_bytes(buf[8..12].try_into().ok()?),
        cuid: u32::from_ne_bytes(buf[12..16].try_into().ok()?),
        cgid: u32::from_ne_bytes(buf[16..20].try_into().ok()?),
        mode: u16::from_ne_bytes(buf[20..22].try_into().ok()?),
        seq:  u16::from_ne_bytes(buf[22..24].try_into().ok()?),
    })
}

fn serialize_ipc64_perm(p: &crate::ipc::Ipc64Perm, buf: &mut [u8]) {
    buf[0..4].copy_from_slice(&p.key.to_ne_bytes());
    buf[4..8].copy_from_slice(&p.uid.to_ne_bytes());
    buf[8..12].copy_from_slice(&p.gid.to_ne_bytes());
    buf[12..16].copy_from_slice(&p.cuid.to_ne_bytes());
    buf[16..20].copy_from_slice(&p.cgid.to_ne_bytes());
    buf[20..22].copy_from_slice(&p.mode.to_ne_bytes());
    buf[22..24].copy_from_slice(&p.seq.to_ne_bytes());
}

fn copy_mq_attr_from_user(va: usize) -> Option<mq::MqAttr> {
    if va == 0 { return None; }
    const SZ: usize = core::mem::size_of::<mq::MqAttr>();
    let mut buf = [0u8; SZ];
    crate::uaccess::copy_from_user(&mut buf, va).ok()?;
    Some(mq::MqAttr {
        mq_flags:   i64::from_ne_bytes(buf[0..8].try_into().ok()?),
        mq_maxmsg:  i64::from_ne_bytes(buf[8..16].try_into().ok()?),
        mq_msgsize: i64::from_ne_bytes(buf[16..24].try_into().ok()?),
        mq_curmsgs: i64::from_ne_bytes(buf[24..32].try_into().ok()?),
        _pad: [0u8; 16],
    })
}

fn copy_mq_attr_to_user(va: usize, attr: &mq::MqAttr) -> bool {
    if va == 0 { return true; }
    const SZ: usize = core::mem::size_of::<mq::MqAttr>();
    let mut buf = [0u8; SZ];
    buf[0..8].copy_from_slice(&attr.mq_flags.to_ne_bytes());
    buf[8..16].copy_from_slice(&attr.mq_maxmsg.to_ne_bytes());
    buf[16..24].copy_from_slice(&attr.mq_msgsize.to_ne_bytes());
    buf[24..32].copy_from_slice(&attr.mq_curmsgs.to_ne_bytes());
    crate::uaccess::copy_to_user(va, &buf).is_ok()
}

// ── Entry points ─────────────────────────────────────────────────────────────

pub fn dispatch(nr: usize, a: usize, b: usize, c: usize,
                d: usize, e: usize, f: usize) -> isize {
    dispatch_with_rip(nr, a, b, c, d, e, f, 0)
}

/// Inner dispatch — called by arch entry points that plumb the saved RIP.
/// `dispatch()` is the legacy shim (passes 0 for RIP).
///
/// Structure:
///   1. seccomp pre-check  — may kill, trap, or override the return code
///   2. subsystem routers  — each returns `Some(retval)` or `None`
///   3. catch-all          — returns ENOSYS for any unrecognised NR
///
/// All actual syscall logic lives in the five routers in `routers.rs`.
/// Adding a match arm here is a bug; add it to the appropriate router.
pub fn dispatch_with_rip(nr: usize, a: usize, b: usize, c: usize,
                         d: usize, e: usize, f: usize,
                         saved_rip: u64) -> isize {

    // ── seccomp pre-check ─────────────────────────────────────────────────
    let is_exit = nr == SYS_EXIT || nr == SYS_EXIT_GROUP;
    match crate::security::seccomp::seccomp_check(nr, &[a, b, c, d, e, f], saved_rip) {
        crate::security::seccomp::SeccompVerdict::Allow  => {}
        crate::security::seccomp::SeccompVerdict::Errno(code) => {
            if !is_exit { return -(code as isize); }
        }
        crate::security::seccomp::SeccompVerdict::Trap  => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, SIGSYS);
            if !is_exit { return -1; }
        }
        crate::security::seccomp::SeccompVerdict::Kill  => {
            crate::proc::exit::sys_exit(-1);
            return -1;
        }
    }

    // ── subsystem routers ─────────────────────────────────────────────────
    // Tried in call-frequency order (fs > proc > memory > ipc > time).
    // Each returns Some(retval) when it owns the nr.
    let ctx = SyscallContext::new(nr, [a, b, c, d, e, f], saved_rip);
    if let Some(ret) = routers::dispatch_filesystem(&ctx) { return ret; }
    if let Some(ret) = routers::dispatch_process(&ctx)    { return ret; }
    if let Some(ret) = routers::dispatch_memory(&ctx)     { return ret; }
    if let Some(ret) = routers::dispatch_ipc(&ctx)        { return ret; }
    if let Some(ret) = routers::dispatch_time(&ctx)       { return ret; }

    // ── unrecognised syscall ──────────────────────────────────────────────
    enosys()
}

// ═══════════════════════════════════════════════════════════════════════════
// IPC dispatch helpers — thin named wrappers so routers.rs stays readable.
// Each function contains exactly the logic that was previously an inline
// match arm in dispatch_with_rip.
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) fn shmctl_dispatch(shmid: i32, cmd: i32, buf_va: usize) -> isize {
    if cmd == crate::ipc::IPC_SET {
        const SZ: usize = core::mem::size_of::<shm::ShmidDs>();
        let mut buf = [0u8; SZ];
        if crate::uaccess::copy_from_user(&mut buf, buf_va).is_err() { return efault(); }
        match parse_shmid_ds(&buf) {
            Some(ds) => match shm::shmctl_set(shmid, ds) { Ok(()) => 0, Err(e) => e },
            None     => efault(),
        }
    } else {
        match shm::shmctl(shmid, cmd) {
            Ok(ds) => {
                if buf_va != 0 {
                    let _ = crate::uaccess::copy_to_user(buf_va, &serialize_shmid_ds(&ds));
                }
                0
            }
            Err(e) => e,
        }
    }
}

pub(crate) fn semop_dispatch(semid: i32, sops_va: usize, nsops: usize) -> isize {
    match copy_sembuf_from_user(sops_va, nsops) {
        Some(ops) => match sem::semop(semid, &ops) { Ok(()) => 0, Err(e) => e },
        None      => efault(),
    }
}

pub(crate) fn semctl_dispatch(semid: i32, semnum: i32, cmd: i32, arg_va: usize) -> isize {
    let arg = match cmd {
        sem::SETVAL | sem::SETALL => Some(sem::SemctlArg::Val(arg_va as i32)),
        _ => None,
    };
    match sem::semctl(semid, semnum, cmd, arg) { Ok(v) => v as isize, Err(e) => e }
}

pub(crate) fn msgsnd_dispatch(msqid: i32, msgp_va: usize, msgsz: usize, msgflg: i32) -> isize {
    match copy_msgbuf_from_user(msgp_va, msgsz) {
        Some((mtype, data)) =>
            match msg::msgsnd(msqid, mtype, data, msgflg) { Ok(()) => 0, Err(e) => e },
        None => efault(),
    }
}

pub(crate) fn msgrcv_dispatch(msqid: i32, msgp_va: usize, msgsz: usize,
                               msgtyp: i64, msgflg: i32) -> isize {
    match msg::msgrcv(msqid, msgsz, msgtyp, msgflg) {
        Ok((mtype, data)) => {
            if !copy_msgbuf_to_user(msgp_va, mtype, &data) { return efault(); }
            data.len() as isize
        }
        Err(e) => e,
    }
}

pub(crate) fn msgctl_dispatch(msqid: i32, cmd: i32, buf_va: usize) -> isize {
    if cmd == crate::ipc::IPC_SET {
        const SZ: usize = core::mem::size_of::<msg::MsqidDs>();
        let mut buf = [0u8; SZ];
        if crate::uaccess::copy_from_user(&mut buf, buf_va).is_err() { return efault(); }
        match parse_msqid_ds(&buf) {
            Some(ds) => match msg::msgctl_set(msqid, ds) { Ok(()) => 0, Err(e) => e },
            None     => efault(),
        }
    } else {
        match msg::msgctl(msqid, cmd) {
            Ok(ds) => {
                if buf_va != 0 {
                    let _ = crate::uaccess::copy_to_user(buf_va, &serialize_msqid_ds(&ds));
                }
                0
            }
            Err(e) => e,
        }
    }
}

pub(crate) fn mq_open_dispatch(name_va: usize, oflag: i32, mode: u32, attr_va: usize) -> isize {
    match crate::proc::exec::read_cstr_safe(name_va) {
        Some(name) => {
            let attr = if attr_va != 0 { copy_mq_attr_from_user(attr_va) } else { None };
            match mq::mq_open(&name, oflag, mode, attr) { Ok(mqd) => mqd as isize, Err(e) => e }
        }
        None => efault(),
    }
}

pub(crate) fn mq_unlink_dispatch(name_va: usize) -> isize {
    match crate::proc::exec::read_cstr_safe(name_va) {
        Some(name) => match mq::mq_unlink(&name) { Ok(()) => 0, Err(e) => e },
        None       => efault(),
    }
}

pub(crate) fn mq_timedsend_dispatch(mqd: u64, msg_va: usize, msglen: usize, prio: u32) -> isize {
    if msglen > mq::MQ_MSGSIZE { return emsgsize(); }
    let mut buf = alloc::vec![0u8; msglen];
    if crate::uaccess::copy_from_user(&mut buf, msg_va).is_err() { return efault(); }
    match mq::mq_send(mqd, buf, prio) { Ok(()) => 0, Err(e) => e }
}

pub(crate) fn mq_timedreceive_dispatch(mqd: u64, buf_va: usize, buflen: usize,
                                        prio_va: usize) -> isize {
    match mq::mq_receive(mqd, buflen) {
        Ok((data, prio)) => {
            if crate::uaccess::copy_to_user(buf_va, &data).is_err() { return efault(); }
            if prio_va != 0 {
                let _ = crate::uaccess::copy_to_user(prio_va, &prio.to_ne_bytes());
            }
            data.len() as isize
        }
        Err(e) => e,
    }
}

pub(crate) fn mq_notify_dispatch(mqd: u64, sigev_va: usize) -> isize {
    if sigev_va == 0 {
        match mq::mq_notify(mqd, 0, 0) { Ok(()) => 0, Err(e) => e }
    } else {
        let mut sigev = [0u8; 32];
        if crate::uaccess::copy_from_user(&mut sigev, sigev_va).is_err() { return efault(); }
        let signo = u32::from_ne_bytes(sigev[4..8].try_into().unwrap_or([0; 4]));
        let pid   = crate::proc::scheduler::current_pid() as u32;
        match mq::mq_notify(mqd, signo, pid) { Ok(()) => 0, Err(e) => e }
    }
}

pub(crate) fn mq_getsetattr_dispatch(mqd: u64, new_va: usize, old_va: usize) -> isize {
    if new_va != 0 {
        match copy_mq_attr_from_user(new_va) {
            Some(new) => match mq::mq_setattr(mqd, new) {
                Ok(old) => {
                    if old_va != 0 && !copy_mq_attr_to_user(old_va, &old) { return efault(); }
                    0
                }
                Err(e) => e,
            },
            None => efault(),
        }
    } else {
        match mq::mq_getattr(mqd) {
            Ok(attr) => {
                if old_va != 0 && !copy_mq_attr_to_user(old_va, &attr) { return efault(); }
                0
            }
            Err(e) => e,
        }
    }
}

// ── Side-table cleanup (called from do_exit) ──────────────────────────────────

pub fn altstack_clear_pid(pid: usize) {
    crate::proc::signal::altstack_clear_pid(pid);
}

pub fn proc_name_clear(pid: usize) {
    crate::syscall::proc_name_clear(pid);
}
