//! x86-64 Linux syscall dispatch table for rustos.
//!
//! ## Recently wired
//!   NR 425  io_uring_setup(entries, params)    => io_uring::syscall::sys_io_uring_setup
//!   NR 426  io_uring_enter(fd, …)              => io_uring::syscall::sys_io_uring_enter
//!   NR 427  io_uring_register(fd, op, arg, n)  => io_uring::syscall::sys_io_uring_register
//!   NR 41-55 socket syscalls (all 15)
//!   NR 288   accept4 (was wrongly aliased to timerfd_gettime64)
//!   NR 318  getrandom(buf, count, flags)     => stubs::sys_getrandom_impl
//!   NR 334  close_range(first, last, flags)  => fs::close_range::sys_close_range
//!   NR 332  statx                            => posix_full::sys_statx_impl
//!   NR 326  copy_file_range                  => posix_full::sys_copy_file_range_impl
//!   NR 327  preadv2 / NR 328 pwritev2        => posix_full
//!   NR 222-226 POSIX timer_*                 => posix_full
//!   NR 285  fallocate                        => posix_full
//!   NR 322  execveat                         => posix_full
//!   NR 307  sendmmsg / NR 299 recvmmsg       => posix_full
//!   NR 283  timerfd_create                   => fs::timerfd::sys_timerfd_create
//!   NR 286  timerfd_settime                  => fs::timerfd::sys_timerfd_settime
//!   NR 287  timerfd_gettime                  => fs::timerfd::sys_timerfd_gettime
//!   NR 93   lchown                           => p0_gaps::sys_lchown_impl
//!   NR 27   mincore                          => openat2_mincore::sys_mincore
//!   NR 437  openat2                          => openat2_mincore::sys_openat2_impl
//!
//! ## Push 5 — newly dispatched
//!   NR 73   flock(fd, op)                    => fs::vfs_extras::sys_flock
//!   NR 100  times(buf)                       => stubs::sys_times_impl  (was missing arm)
//!   NR 139  getpriority(which, who)          => inline (returns 0)
//!   NR 140  setpriority(which, who, prio)    => inline (returns 0)
//!   NR 155  getpgid(pid)                     => inline (returns current pid)
//!   NR 156  setpgid(pid, pgid)               => inline (returns 0)
//!   NR 221  posix_fadvise(fd,off,len,advice) => fs::vfs_extras::sys_posix_fadvise
//!   NR 260  fchownat(dirfd,path,uid,gid,fl)  => inline stub (ownership not enforced)
//!   NR 268  fchmodat(dirfd,path,mode,flags)  => inline stub (permissions not enforced)
//!
//! ## Push 6 — newly dispatched
//!   NR 284  eventfd(initval)                 => fs::eventfd::sys_eventfd
//!           (NR 290 eventfd2 was already wired; NR 284 was the missing slot)
//!
//! ## NR 15  rt_sigreturn
//!   Intercepted BEFORE dispatch() at the arch entry point:
//!     x86_64: rust_syscall_handler in arch/x86_64/syscall.rs
//!     riscv64: handle_exception(code=8) in arch/riscv64/trap.rs
//!   The dispatch() arm for NR 15 below is therefore unreachable in normal
//!   operation and exists only as a safe fallback.
//!
//! ## Socket NRs (NR 41-55, 288)
//!   41  socket       42  connect     43  accept      44  sendto
//!   45  recvfrom     46  sendmsg     47  recvmsg     48  shutdown
//!   49  bind         50  listen      51  getsockname 52  getpeername
//!   53  socketpair   54  setsockopt  55  getsockopt
//!   288 accept4
//!
//! ## IPC (wired)
//!   NR 29   shmget   NR 30  shmat    NR 31  shmctl
//!   NR 64   semget   NR 65  semop    NR 66  semctl   NR 67  shmdt
//!   NR 68   msgget   NR 69  msgsnd   NR 70  msgrcv   NR 71  msgctl
//!   NR 240  mq_open  NR 241 mq_unlink NR 242 mq_timedsend NR 243 mq_timedreceive
//!   NR 244  mq_notify NR 245 mq_getsetattr
//!
//! ## Already implemented (audit notes)
//!   NR 9    mmap — MAP_FIXED_NOREPLACE (0x100000) handled in mm::mmap::sys_mmap
//!   NR 89   readlink  — routes /proc/* through procfs::procfs_readlink
//!   NR 267  readlinkat — same routing as NR 89
//!
//! ## Signal NRs
//!   NR 127  rt_sigpending   NR 128  rt_sigtimedwait   NR 130  rt_sigsuspend
//!
//! ## NPTL threading NRs
//!   NR 200  tkill   NR 202  futex   NR 234  tgkill
//!   NR 273  set_robust_list   NR 274  get_robust_list
//!
//! ## seccomp / namespace NRs
//!   NR 272  unshare  NR 308  setns  NR 317  seccomp
//!
//! ## inotify / fanotify NRs
//!   NR 253/254/255/292  NR 300/301

#![allow(unused_variables, unused_imports)]
extern crate alloc;
use crate::fs::fcntl;
use crate::fs::vfs;
use crate::ipc::{mq, msg, sem, shm};
use alloc::string::String;
use alloc::vec::Vec;

include!("p0_gaps.rs");
include!("openat2_mincore.rs");
include!("stubs.rs");
include!("posix_full.rs");

// Re-export helpers needed by posix_full.rs
pub(crate) use self::sys_pwrite64_impl;
pub(crate) use self::sys_readv_impl;

/// Resolve a dirfd + path_va pair the same way stubs.rs does,
/// exported so posix_full.rs can call it without duplicating logic.
pub(crate) fn stubs_at_path(dirfd: i32, path_va: usize) -> Option<String> {
    const AT_FDCWD: i32 = -100;
    let path = crate::proc::exec::read_cstr_safe(path_va)?;
    if dirfd == AT_FDCWD || path.starts_with('/') {
        Some(path)
    } else {
        let dir = crate::fs::vfs::fd_to_path(dirfd as usize).unwrap_or_else(|| String::from("/"));
        Some(alloc::format!("{}/{}", dir.trim_end_matches('/'), path))
    }
}

const EPOLL_CLOEXEC: u32 = 0x0008_0000;

#[inline(always)]
fn arg_u32(v: usize) -> Option<u32> {
    if v > u32::MAX as usize {
        None
    } else {
        Some(v as u32)
    }
}

/// Convert a raw syscall argument to `i32`.
///
/// Syscall arguments arrive as `usize` (64-bit register values).  A
/// user-space caller that passes a negative `i32` (e.g. `AT_FDCWD = -100`)
/// will sign-extend it to a full 64-bit value
/// (`0xFFFF_FFFF_FFFF_FF9C`).  We accept that by reinterpreting the
/// low 32 bits — but only if the high 32 bits are all-zeros (positive
/// small integer) or all-ones (sign-extended negative).  Any other
/// pattern means the value genuinely doesn't fit in an `i32`.
#[inline(always)]
fn arg_i32(v: usize) -> Option<i32> {
    let hi = v >> 32;
    // Valid patterns: 0x0000_0000 (positive) or 0xFFFF_FFFF (sign-extended negative).
    if hi == 0 || hi == 0xFFFF_FFFF {
        Some(v as i32)
    } else {
        None
    }
}

fn sys_epoll_create1(flags: u32) -> isize {
    let fd = crate::fs::poll::sys_epoll_create(0);
    if fd >= 0 && flags & EPOLL_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fd as usize, true);
    }
    fd
}

// ── IPC helpers ────────────────────────────────────────────────────────────────────
fn copy_msgbuf_from_user(msgp_va: usize, msgsz: usize) -> Option<(i64, Vec<u8>)> {
    if msgp_va == 0 || msgsz > msg::MSGMAX {
        return None;
    }
    let total = 8 + msgsz;
    let mut buf = alloc::vec![0u8; total];
    crate::uaccess::copy_from_user(&mut buf, msgp_va).ok()?;
    let mtype = i64::from_ne_bytes(buf[0..8].try_into().ok()?);
    let data = buf[8..].to_vec();
    Some((mtype, data))
}

fn copy_msgbuf_to_user(msgp_va: usize, mtype: i64, data: &[u8]) -> bool {
    if msgp_va == 0 {
        return false;
    }
    let mut buf = alloc::vec![0u8; 8 + data.len()];
    buf[0..8].copy_from_slice(&mtype.to_ne_bytes());
    buf[8..].copy_from_slice(data);
    crate::uaccess::copy_to_user(msgp_va, &buf).is_ok()
}

fn copy_sembuf_from_user(sops_va: usize, nsops: usize) -> Option<Vec<sem::Sembuf>> {
    if sops_va == 0 || nsops == 0 || nsops > sem::SEMOPM {
        return None;
    }
    const SEMBUF_SIZE: usize = 8;
    let mut raw = alloc::vec![0u8; nsops * SEMBUF_SIZE];
    crate::uaccess::copy_from_user(&mut raw, sops_va).ok()?;
    let mut ops = Vec::with_capacity(nsops);
    for i in 0..nsops {
        let off = i * SEMBUF_SIZE;
        let num = u16::from_ne_bytes(raw[off..off + 2].try_into().ok()?);
        let op = i16::from_ne_bytes(raw[off + 2..off + 4].try_into().ok()?);
        let flg = i16::from_ne_bytes(raw[off + 4..off + 6].try_into().ok()?);
        ops.push(sem::Sembuf {
            sem_num: num,
            sem_op: op,
            sem_flg: flg,
        });
    }
    Some(ops)
}

// ── Safe field-by-field IPC struct parsers ──────────────────────────────────────────────
//
// P0 fix: these replace the previous `unsafe { core::mem::transmute(buf) }`
// calls on the IPC_SET paths for shmctl and msgctl.  Parsing each field
// explicitly from the raw byte buffer:
//   (a) avoids UB if ShmidDs/MsqidDs ever gain enum discriminants or
//       references;
//   (b) allows us to validate individual fields before they reach the
//       IPC subsystem;
//   (c) makes the code self-documenting about the wire layout.
//
// The struct layouts below match the x86-64 Linux ABI definitions from
// <linux/shm.h> and <linux/msg.h>.  Field offsets were verified against
// the kernel headers.

/// Parse a `ShmidDs` from a raw byte buffer read from user space.
/// Returns `None` if the buffer is too small (should never happen given
/// the size_of check at the call site, but defensive is correct here).
fn parse_shmid_ds(buf: &[u8]) -> Option<shm::ShmidDs> {
    use core::mem::size_of;
    if buf.len() < size_of::<shm::ShmidDs>() {
        return None;
    }
    Some(shm::ShmidDs {
        shm_perm: parse_ipc64_perm(&buf[0..48])?,
        shm_segsz: usize::from_ne_bytes(buf[48..56].try_into().ok()?),
        shm_atime: i64::from_ne_bytes(buf[56..64].try_into().ok()?),
        shm_dtime: i64::from_ne_bytes(buf[64..72].try_into().ok()?),
        shm_ctime: i64::from_ne_bytes(buf[72..80].try_into().ok()?),
        shm_cpid: i32::from_ne_bytes(buf[80..84].try_into().ok()?),
        shm_lpid: i32::from_ne_bytes(buf[84..88].try_into().ok()?),
        shm_nattch: u64::from_ne_bytes(buf[88..96].try_into().ok()?),
    })
}

/// Serialize a `ShmidDs` to a raw byte buffer for copy_to_user.
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

/// Parse a `MsqidDs` from a raw byte buffer read from user space.
fn parse_msqid_ds(buf: &[u8]) -> Option<msg::MsqidDs> {
    use core::mem::size_of;
    if buf.len() < size_of::<msg::MsqidDs>() {
        return None;
    }
    Some(msg::MsqidDs {
        msg_perm: parse_ipc64_perm(&buf[0..48])?,
        msg_stime: i64::from_ne_bytes(buf[48..56].try_into().ok()?),
        msg_rtime: i64::from_ne_bytes(buf[56..64].try_into().ok()?),
        msg_ctime: i64::from_ne_bytes(buf[64..72].try_into().ok()?),
        msg_cbytes: u64::from_ne_bytes(buf[72..80].try_into().ok()?),
        msg_qnum: u64::from_ne_bytes(buf[80..88].try_into().ok()?),
        msg_qbytes: u64::from_ne_bytes(buf[88..96].try_into().ok()?),
        msg_lspid: i32::from_ne_bytes(buf[96..100].try_into().ok()?),
        msg_lrpid: i32::from_ne_bytes(buf[100..104].try_into().ok()?),
    })
}

/// Serialize a `MsqidDs` to a raw byte buffer for copy_to_user.
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

/// Parse an `ipc64_perm` from a 48-byte slice.
fn parse_ipc64_perm(buf: &[u8]) -> Option<crate::ipc::Ipc64Perm> {
    if buf.len() < 48 {
        return None;
    }
    Some(crate::ipc::Ipc64Perm {
        key: i32::from_ne_bytes(buf[0..4].try_into().ok()?),
        uid: u32::from_ne_bytes(buf[4..8].try_into().ok()?),
        gid: u32::from_ne_bytes(buf[8..12].try_into().ok()?),
        cuid: u32::from_ne_bytes(buf[12..16].try_into().ok()?),
        cgid: u32::from_ne_bytes(buf[16..20].try_into().ok()?),
        mode: u16::from_ne_bytes(buf[20..22].try_into().ok()?),
        seq: u16::from_ne_bytes(buf[22..24].try_into().ok()?),
    })
}

/// Serialize an `ipc64_perm` into a 48-byte slice.
fn serialize_ipc64_perm(p: &crate::ipc::Ipc64Perm, buf: &mut [u8]) {
    buf[0..4].copy_from_slice(&p.key.to_ne_bytes());
    buf[4..8].copy_from_slice(&p.uid.to_ne_bytes());
    buf[8..12].copy_from_slice(&p.gid.to_ne_bytes());
    buf[12..16].copy_from_slice(&p.cuid.to_ne_bytes());
    buf[16..20].copy_from_slice(&p.cgid.to_ne_bytes());
    buf[20..22].copy_from_slice(&p.mode.to_ne_bytes());
    buf[22..24].copy_from_slice(&p.seq.to_ne_bytes());
    // bytes 24..48 are padding; already zeroed by the caller
}

// ── Safe mq_attr user-copy helpers ──────────────────────────────────────────────────────────
fn copy_mq_attr_from_user(va: usize) -> Option<mq::MqAttr> {
    if va == 0 {
        return None;
    }
    const SZ: usize = core::mem::size_of::<mq::MqAttr>();
    let mut buf = [0u8; SZ];
    crate::uaccess::copy_from_user(&mut buf, va).ok()?;
    let mq_flags = i64::from_ne_bytes(buf[0..8].try_into().ok()?);
    let mq_maxmsg = i64::from_ne_bytes(buf[8..16].try_into().ok()?);
    let mq_msgsize = i64::from_ne_bytes(buf[16..24].try_into().ok()?);
    let mq_curmsgs = i64::from_ne_bytes(buf[24..32].try_into().ok()?);
    Some(mq::MqAttr {
        mq_flags,
        mq_maxmsg,
        mq_msgsize,
        mq_curmsgs,
        _pad: [0u8; 16],
    })
}

fn copy_mq_attr_to_user(va: usize, attr: &mq::MqAttr) -> bool {
    if va == 0 {
        return true;
    }
    const SZ: usize = core::mem::size_of::<mq::MqAttr>();
    let mut buf = [0u8; SZ];
    buf[0..8].copy_from_slice(&attr.mq_flags.to_ne_bytes());
    buf[8..16].copy_from_slice(&attr.mq_maxmsg.to_ne_bytes());
    buf[16..24].copy_from_slice(&attr.mq_msgsize.to_ne_bytes());
    buf[24..32].copy_from_slice(&attr.mq_curmsgs.to_ne_bytes());
    crate::uaccess::copy_to_user(va, &buf).is_ok()
}

pub fn dispatch(nr: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    dispatch_with_rip(nr, a, b, c, d, e, f, 0)
}

/// Inner dispatch that accepts the saved instruction pointer from the
/// syscall entry stub.  Called by arch entry points that plumb RIP;
/// `dispatch()` is the legacy shim that passes 0 for RIP.
pub fn dispatch_with_rip(
    nr: usize,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    saved_rip: u64,
) -> isize {
    // ── seccomp pre-check ────────────────────────────────────────────────────────
    match crate::security::seccomp::seccomp_check(nr, &[a, b, c, d, e, f], saved_rip) {
        crate::security::seccomp::SeccompVerdict::Allow => {}
        crate::security::seccomp::SeccompVerdict::Errno(e) => {
            if nr != 60 && nr != 231 {
                return -(e as isize);
            }
        }
        crate::security::seccomp::SeccompVerdict::Trap => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, 31 /* SIGSYS */);
            if nr != 60 && nr != 231 {
                return -1;
            }
        }
        crate::security::seccomp::SeccompVerdict::Kill => {
            crate::proc::exit::sys_exit(-1);
            return -1;
        }
    }

    match nr {
        // ── filesystem I/O ───────────────────────────────────────────────────────────────────────────────
        0 => crate::fs::io_syscalls::sys_read(a, b, c),
        1 => crate::fs::io_syscalls::sys_write(a, b, c),
        2 => crate::fs::io_syscalls::sys_open(a, b as u32, c as u32),
        3 => crate::fs::io_syscalls::sys_close(a),
        17 => crate::fs::io_syscalls::sys_pread64(a, b, c, d as i64),
        18 => sys_pwrite64_impl(a, b, c, d as i64),
        19 => sys_readv_impl(a, b, c),
        20 => crate::fs::io_syscalls::sys_writev(a, b, c),
        22 => crate::fs::pipe::sys_pipe(a),
        27 => sys_mincore(a, b, c),
        32 => crate::fs::vfs::dup(a),
        33 => crate::fs::fcntl::sys_dup2(a, b),
        40 => sys_sendfile_impl(a, b, c, d),
        73 => crate::fs::vfs_extras::sys_flock(a, b as i32),
        72 => crate::fs::fcntl::sys_fcntl(a, b as i32, c),
        74 => sys_fsync_impl(a),
        75 => sys_fdatasync_impl(a),
        76 => sys_truncate_impl(a, b as i64),
        77 => sys_ftruncate_impl(a, b as i64),
        78 => crate::fs::getdents::sys_getdents(a, b, c),
        16 => crate::fs::ioctl::sys_ioctl(a, b, c),
        81 => sys_fchdir_impl(a),
        84 => sys_rmdir_impl(a),
        85 => sys_creat_impl(a, b as u32),
        86 => sys_link_impl(a, b),
        88 => sys_symlink_impl(a, b),
        89 => sys_readlink_impl(a, b, c),
        132 => sys_utime_impl(a, b),
        162 => sys_sync_impl(),
        217 => crate::fs::getdents::sys_getdents64(a, b, c),
        220 => crate::fs::getdents::sys_getdents64(a, b, c),
        221 => crate::fs::vfs_extras::sys_posix_fadvise(a, b as i64, c as i64, d as i32),
        235 => sys_utimes_impl(a, b),
        257 => sys_openat_impl(a as i32, b, c as i32, d as u32),
        258 => sys_mkdirat_impl(a as i32, b, c as u32),
        259 => sys_mknodat_impl(a as i32, b, c as u32, d as u64),
        260 => 0,
        261 => sys_futimesat_impl(a as i32, b, c),
        262 => sys_newfstatat_impl(a as i32, b, c, d as u32),
        263 => sys_unlinkat_impl(a as i32, b, c as u32),
        264 => sys_renameat_impl(a as i32, b, c as i32, d),
        265 => sys_linkat_impl(a as i32, b, c as i32, d, e as i32),
        266 => sys_symlinkat_impl(a, b as i32, c),
        267 => sys_readlinkat_impl(a as i32, b, c, d),
        268 => 0,
        280 => sys_utimensat_impl(a as i32, b, c, d as i32),
        285 => sys_fallocate_impl(a, b as i32, c as i64, d as i64),
        // NR 284  eventfd(initval)
        // Was returning ENOSYS. NR 290 (eventfd2) was already wired;
        // this is the legacy single-argument form.
        284 => crate::fs::eventfd::sys_eventfd(a as u32),
        290 => crate::fs::eventfd::sys_eventfd2(a as u32, b as u32),
        293 => crate::fs::pipe::sys_pipe2(a, b as u32),
        294 => crate::fs::fcntl::sys_dup3(a, b, c as i32),
        306 => sys_syncfs_impl(a),
        319 => sys_memfd_create_impl(a, b as u32),
        322 => sys_execveat_impl(a as i32, b, c, d, e as i32),
        326 => sys_copy_file_range_impl(a, b, c, d, e, f as u32),
        327 => sys_preadv2_impl(a, b, c, d, e, f as i32),
        328 => sys_pwritev2_impl(a, b, c, d, e, f as i32),
        332 => sys_statx_impl(a as i32, b, c as u32, d as u32, e),
        437 => sys_openat2_impl(a as i32, b, c, d),
        334 => match (arg_u32(a), arg_u32(b), arg_u32(c)) {
            (Some(first), Some(last), Some(flags)) => {
                crate::fs::close_range::sys_close_range(first, last, flags)
            }
            _ => -22,
        },
        // ── io_uring ───────────────────────────────────────────────────────────────────────────────
        425 => crate::io_uring::syscall::sys_io_uring_setup(a as u32, b),
        426 => crate::io_uring::syscall::sys_io_uring_enter(a, b as u32, c as u32, d as u32, e, f),
        427 => crate::io_uring::syscall::sys_io_uring_register(a, b as u32, c, d as u32),
        // ── socket syscalls (NR 41-55, 288) ────────────────────────────────────────────
        41 => crate::net::socket::sys_socket(a as i32, b as i32, c as i32),
        42 => crate::net::socket::sys_connect(a, b, c as u32),
        43 => crate::net::socket::sys_accept(a, b, c),
        44 => crate::net::socket::sys_sendto(a, b, c, d as i32, e, f as u32),
        45 => crate::net::socket::sys_recvfrom(a, b, c, d as i32, e, f),
        46 => crate::net::socket::sys_sendmsg(a, b, c as i32),
        47 => crate::net::socket::sys_recvmsg(a, b, c as i32),
        48 => crate::net::socket::sys_shutdown(a, b as i32),
        49 => crate::net::socket::sys_bind(a, b, c as u32),
        50 => crate::net::socket::sys_listen(a, b as i32),
        51 => crate::net::socket::sys_getsockname(a, b, c),
        52 => crate::net::socket::sys_getpeername(a, b, c),
        53 => crate::net::socket::sys_socketpair(a as i32, b as i32, c as i32, d),
        54 => crate::net::socket::sys_setsockopt(a, b as i32, c as i32, d, e as u32),
        55 => crate::net::socket::sys_getsockopt(a, b as i32, c as i32, d, e),
        288 => {
            let fd = crate::net::socket::sys_accept(a, b, c);
            if fd >= 0 {
                if d & 0x800 != 0 {
                    let mut t = crate::net::socket::TCP_SOCKETS.lock();
                    if let Some(Some(s)) = t.get_mut(fd as usize) {
                        s.nonblocking = true;
                    }
                }
                if d & 0x80000 != 0 {
                    crate::fs::fcntl::set_cloexec(fd as usize, true);
                }
            }
            fd
        }
        // ── timerfd ───────────────────────────────────────────────────────────────────────────────────
        283 => crate::fs::timerfd::sys_timerfd_create(a as u32, b as u32),
        286 => crate::fs::timerfd::sys_timerfd_settime(a, b as i32, c, d),
        287 => crate::fs::timerfd::sys_timerfd_gettime(a, b),
        // ── inotify ─────────────────────────────────────────────────────────────────────────
        253 => crate::fs::inotify::sys_inotify_init1(0),
        254 => crate::fs::inotify::sys_inotify_add_watch(a, b, c as u32),
        255 => crate::fs::inotify::sys_inotify_rm_watch(a, b as i32),
        292 => crate::fs::inotify::sys_inotify_init1(a as u32),
        // ── fanotify ─────────────────────────────────────────────────────────────────────────
        300 => crate::fs::fanotify::sys_fanotify_init(a as u32, b as u32),
        301 => crate::fs::fanotify::sys_fanotify_mark(a, b as u32, c as u64, d as i32, e),
        // ── seccomp + namespaces ───────────────────────────────────────────────────────────
        272 => crate::proc::namespace::sys_unshare(a),
        308 => crate::proc::namespace::sys_setns(a, b as u32),
        317 => crate::security::seccomp::sys_seccomp(a as u32, b as u32, c),
        // ── I/O multiplexing ────────────────────────────────────────────────────────────────
        7 => crate::fs::poll::sys_poll(a, b, c as i32),
        23 => crate::fs::poll::sys_select(a, b, c, d, e),
        168 => crate::fs::poll::sys_poll(a, b, c as i32),
        213 => crate::fs::poll::sys_epoll_create(a as i32),
        232 => crate::fs::poll::sys_epoll_wait(a, b, c as i32, d as i32),
        233 => crate::fs::poll::sys_epoll_ctl(a, b as i32, c as i32, d),
        270 => crate::fs::poll::sys_pselect6(a, b, c, d, e, f),
        271 => crate::fs::poll::sys_ppoll(a, b, c, d, e),
        281 => crate::fs::poll::sys_epoll_pwait(a, b, c as i32, d as i32, e, f),
        291 => sys_epoll_create1(a as u32),
        // ── stat / path ops ───────────────────────────────────────────────────────────────────────────
        4 => crate::fs::stat_syscalls::sys_stat(a, b),
        5 => crate::fs::stat_syscalls::sys_fstat(a, b),
        6 => crate::fs::stat_syscalls::sys_lstat(a, b),
        8 => crate::fs::stat_syscalls::sys_lseek(a, b as i64, c as i32),
        21 => crate::fs::stat_syscalls::sys_access(a, b as u32),
        79 => crate::fs::stat_syscalls::sys_getcwd(a, b),
        80 => crate::fs::stat_syscalls::sys_chdir(a),
        82 => crate::fs::stat_syscalls::sys_rename(a, b),
        83 => crate::fs::stat_syscalls::sys_mkdir(a, b as u32),
        87 => crate::fs::stat_syscalls::sys_unlink(a),
        95 => sys_umask_impl(a as u32),
        133 => sys_mknod_impl(a, b as u32, c as u64),
        135 => sys_personality_impl(a as u32),
        136 => sys_ustat_impl(a as u64, b),
        137 => sys_statfs_impl(a, b),
        138 => sys_fstatfs_impl(a, b),
        163 => sys_acct_impl(a),
        164 => sys_settimeofday_impl(a, b),
        166 => sys_umount2_impl(a, b as i32),
        167 => sys_swapon_impl(a, b as i32),
        216 => sys_remap_file_pages_impl(),
        269 => crate::fs::stat_syscalls::sys_faccessat(a as i32, b, c as u32),
        // ── memory ──────────────────────────────────────────────────────────────────────────────────
        9 => crate::mm::mmap::sys_mmap(a, b, c as u32, d as u32, e, f),
        10 => crate::mm::mmap::sys_mprotect(a, b, c as u32),
        11 => crate::mm::mmap::sys_munmap(a, b),
        12 => crate::mm::mmap::sys_brk(a),
        25 => sys_mremap_impl(a, b, c, d, e),
        28 => sys_madvise_impl(a, b, c as i32),
        149 => sys_mlock_impl(a, b),
        150 => sys_munlock_impl(a, b),
        325 => sys_mlock2_impl(a, b, c as u32),
        329 => sys_pkey_mprotect_impl(a, b, c as u32, d as i32),
        330 => sys_pkey_alloc_impl(a as u32, b as u64),
        331 => sys_pkey_free_impl(a as i32),
        // ── System V IPC: shared memory ──────────────────────────────────────────────────
        29 => match shm::shmget(a as i32, b, c as i32) {
            Ok(id) => id as isize,
            Err(e) => e,
        },
        30 => match shm::shmat(a as i32, b, c as i32) {
            Ok(va) => va as isize,
            Err(e) => e,
        },
        31 => {
            let cmd = b as i32;
            if cmd == crate::ipc::IPC_SET {
                const SZ: usize = core::mem::size_of::<shm::ShmidDs>();
                let mut buf = [0u8; SZ];
                if crate::uaccess::copy_from_user(&mut buf, c).is_err() {
                    return -14;
                }
                let new_ds = match parse_shmid_ds(&buf) {
                    Some(ds) => ds,
                    None => return -14,
                };
                match shm::shmctl_set(a as i32, new_ds) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            } else {
                match shm::shmctl(a as i32, cmd) {
                    Ok(ds) => {
                        if c != 0 {
                            let bytes = serialize_shmid_ds(&ds);
                            let _ = crate::uaccess::copy_to_user(c, &bytes);
                        }
                        0
                    }
                    Err(e) => e,
                }
            }
        }
        // ── System V IPC: semaphores ──────────────────────────────────────────────────
        64 => match sem::semget(a as i32, b as i32, c as i32) {
            Ok(id) => id as isize,
            Err(e) => e,
        },
        65 => {
            let ops = match copy_sembuf_from_user(b, c) {
                Some(v) => v,
                None => return -14,
            };
            match sem::semop(a as i32, &ops) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        66 => {
            let cmd = c as i32;
            let arg = match cmd {
                sem::SETVAL => Some(sem::SemctlArg::Val(d as i32)),
                sem::SETALL => Some(sem::SemctlArg::Val(d as i32)),
                _ => None,
            };
            match sem::semctl(a as i32, b as i32, cmd, arg) {
                Ok(v) => v as isize,
                Err(e) => e,
            }
        }
        67 => match shm::shmdt(a) {
            Ok(()) => 0,
            Err(e) => e,
        },
        // ── System V IPC: message queues ──────────────────────────────────────────────
        68 => match msg::msgget(a as i32, b as i32) {
            Ok(id) => id as isize,
            Err(e) => e,
        },
        69 => {
            let (mtype, data) = match copy_msgbuf_from_user(b, c) {
                Some(v) => v,
                None => return -14,
            };
            match msg::msgsnd(a as i32, mtype, data, d as i32) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        70 => match msg::msgrcv(a as i32, c, d as i64, e as i32) {
            Ok((mtype, data)) => {
                if !copy_msgbuf_to_user(b, mtype, &data) {
                    return -14;
                }
                data.len() as isize
            }
            Err(e) => e,
        },
        71 => {
            let cmd = b as i32;
            if cmd == crate::ipc::IPC_SET {
                const SZ: usize = core::mem::size_of::<msg::MsqidDs>();
                let mut buf = [0u8; SZ];
                if crate::uaccess::copy_from_user(&mut buf, c).is_err() {
                    return -14;
                }
                let new_ds = match parse_msqid_ds(&buf) {
                    Some(ds) => ds,
                    None => return -14,
                };
                match msg::msgctl_set(a as i32, new_ds) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            } else {
                match msg::msgctl(a as i32, cmd) {
                    Ok(ds) => {
                        if c != 0 {
                            let bytes = serialize_msqid_ds(&ds);
                            let _ = crate::uaccess::copy_to_user(c, &bytes);
                        }
                        0
                    }
                    Err(e) => e,
                }
            }
        }
        // ── POSIX message queues ────────────────────────────────────────────────────────────
        240 => {
            let name = match crate::proc::exec::read_cstr_safe(a) {
                Some(s) => s,
                None => return -14,
            };
            let oflag = b as i32;
            let mode = c as u32;
            let attr = if d != 0 {
                copy_mq_attr_from_user(d)
            } else {
                None
            };
            match mq::mq_open(&name, oflag, mode, attr) {
                Ok(mqd) => mqd as isize,
                Err(e) => e,
            }
        }
        241 => {
            let name = match crate::proc::exec::read_cstr_safe(a) {
                Some(s) => s,
                None => return -14,
            };
            match mq::mq_unlink(&name) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        242 => {
            let msglen = c;
            if msglen > mq::MQ_MSGSIZE {
                return -90;
            }
            let mut buf = alloc::vec![0u8; msglen];
            if crate::uaccess::copy_from_user(&mut buf, b).is_err() {
                return -14;
            }
            match mq::mq_send(a as u64, buf, d as u32) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        243 => {
            let buflen = c;
            match mq::mq_receive(a as u64, buflen) {
                Ok((data, prio)) => {
                    if crate::uaccess::copy_to_user(b, &data).is_err() {
                        return -14;
                    }
                    if d != 0 {
                        let _ = crate::uaccess::copy_to_user(d, &prio.to_ne_bytes());
                    }
                    data.len() as isize
                }
                Err(e) => e,
            }
        }
        244 => {
            if b == 0 {
                match mq::mq_notify(a as u64, 0, 0) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            } else {
                let mut sigev = [0u8; 32];
                if crate::uaccess::copy_from_user(&mut sigev, b).is_err() {
                    return -14;
                }
                let signo = u32::from_ne_bytes(sigev[4..8].try_into().unwrap_or([0; 4]));
                let pid = crate::proc::scheduler::current_pid() as u32;
                match mq::mq_notify(a as u64, signo, pid) {
                    Ok(()) => 0,
                    Err(e) => e,
                }
            }
        }
        245 => {
            if b != 0 {
                let new = match copy_mq_attr_from_user(b) {
                    Some(a) => a,
                    None => return -14,
                };
                match mq::mq_setattr(a as u64, new) {
                    Ok(old) => {
                        if c != 0 && !copy_mq_attr_to_user(c, &old) {
                            return -14;
                        }
                        0
                    }
                    Err(e) => e,
                }
            } else {
                match mq::mq_getattr(a as u64) {
                    Ok(attr) => {
                        if c != 0 && !copy_mq_attr_to_user(c, &attr) {
                            return -14;
                        }
                        0
                    }
                    Err(e) => e,
                }
            }
        }
        // ── process / signals ─────────────────────────────────────────────────────────────────────────
        13 => match arg_u32(a) {
            Some(sig) if sig >= 1 && sig <= 64 => {
                crate::proc::signal::sys_rt_sigaction(sig, b, c, d)
            }
            _ => -22,
        },
        14 => match arg_u32(a) {
            Some(how) if how <= 2 => crate::proc::signal::sys_rt_sigprocmask(how, b, c, d),
            _ => -22,
        },
        15 => -38,
        24 => sys_sched_yield_impl(),
        34 => sys_pause_impl(),
        35 => crate::proc::nanosleep::sys_nanosleep(a, b),
        37 => sys_alarm_impl(a as u32),
        39 => crate::proc::scheduler::current_pid() as isize,
        56 => sys_clone_impl(a, b, c, d, e),
        57 => crate::proc::fork_syscall::sys_fork(),
        58 => sys_vfork_impl(),
        59 => crate::proc::exec::sys_execve(a, b, c),
        60 => crate::proc::exit::sys_exit(a as i32),
        61 => crate::proc::wait::sys_waitpid(a as isize, b, c as u32),
        62 => match arg_u32(b) {
            Some(sig) if sig <= 64 => sys_kill_impl(a as isize, sig),
            _ => -22,
        },
        63 => sys_uname_impl(a),
        100 => sys_times_impl(a),
        98 => sys_getrusage_impl(a as i32, b),
        99 => sys_sysinfo_impl(a),
        109 => {
            let pid = crate::proc::scheduler::current_pid();
            let uid = crate::proc::scheduler::with_proc(pid, |p| p.cred.uid).unwrap_or(0);
            let bytes = uid.to_le_bytes();
            if a != 0 {
                let _ = crate::uaccess::copy_to_user(a, &bytes);
            }
            if b != 0 {
                let _ = crate::uaccess::copy_to_user(b, &bytes);
            }
            if c != 0 {
                let _ = crate::uaccess::copy_to_user(c, &bytes);
            }
            0
        }
        110 => crate::proc::scheduler::current_ppid() as isize,
        111 => sys_getpgrp_impl(),
        112 => sys_setsid_impl(),
        113 => match (arg_u32(a), arg_u32(b)) {
            (Some(pid), Some(pgid)) => {
                let _ = (pid, pgid);
                0
            }
            _ => -22,
        },
        114 => crate::proc::scheduler::current_pid() as isize,
        121 => crate::proc::scheduler::current_pid() as isize,
        122 => sys_setreuid_impl(a as u32, b as u32),
        123 => sys_setregid_impl(a as u32, b as u32),
        124 => sys_getgroups_impl(a as i32, b),
        125 => sys_setgroups_impl(a as i32, b),
        126 => sys_setresuid_impl(a as u32, b as u32, c as u32),
        129 => sys_rt_sigqueueinfo_impl(a as i32, b, c),
        127 => crate::proc::signal::sys_rt_sigpending(a, b),
        128 => crate::proc::signal::sys_rt_sigtimedwait(a, b, c, d),
        130 => crate::proc::signal::sys_rt_sigsuspend(a, b),
        131 => sys_sigaltstack_impl(a, b),
        139 => 0,
        140 => 0,
        147 => sys_getsid_impl(a as u32),
        155 => crate::proc::scheduler::current_pid() as isize,
        156 => 0,
        158 => crate::arch::x86_64::syscall::sys_arch_prctl(a as i32, b),
        169 => sys_reboot_impl(a as u32, b as u32, c as u32, d),
        170 => sys_sethostname_impl(a, b),
        171 => sys_setdomainname_impl(a, b),
        172 => sys_iopl_impl(a as i32),
        173 => sys_ioperm_impl(a, b, c as i32),
        175 => sys_init_module_impl(a, b, c),
        176 => sys_delete_module_impl(a, b as u32),
        183 => sys_getcpu_impl(a, b, c),
        184 => sys_process_vm_readv_impl(a, b, c, d, e, f),
        185 => sys_prctl_impl(a as i32, b, c, d, e),
        186 => crate::proc::thread::sys_gettid(),
        // ── NPTL threading ──────────────────────────────────────────────────────────────────────
        200 => match arg_u32(b) {
            Some(sig) if sig <= 64 => crate::proc::thread::sys_tkill(a, sig),
            _ => -22,
        },
        202 => crate::proc::futex::sys_futex(a, b as u32, c as u32, d, e, f as u32),
        218 => crate::arch::x86_64::syscall::sys_set_tid_address(a),
        222 => sys_timer_create_impl(a as u32, b, c),
        223 => sys_timer_settime_impl(a as u32, b as i32, c, d),
        224 => sys_timer_gettime_impl(a as u32, b),
        225 => sys_timer_getoverrun_impl(a as u32),
        226 => sys_timer_delete_impl(a as u32),
        227 => sys_clock_settime_impl(a as u32, b),
        229 => sys_clock_getres_impl(a as u32, b),
        234 => match arg_u32(c) {
            Some(sig) if sig <= 64 => crate::proc::thread::sys_tgkill(a, b, sig),
            _ => -22,
        },
        273 => crate::proc::futex::sys_set_robust_list(a, b),
        274 => crate::proc::futex::sys_get_robust_list(a, b, c),
        // ── time ─────────────────────────────────────────────────────────────────────────────────
        36 => sys_getitimer_impl(a as i32, b),
        38 => sys_setitimer_impl(a as i32, b, c),
        96 => sys_gettimeofday_impl(a, b),
        97 => sys_getrlimit_impl(a as u32, b),
        160 => sys_setrlimit_impl(a as u32, b),
        201 => sys_time_impl(a),
        203 => sys_sched_setaffinity_impl(a, b, c),
        204 => sys_sched_getaffinity_impl(a, b, c),
        228 => match arg_u32(a) {
            Some(clk) => crate::proc::nanosleep::sys_clock_gettime(clk, b),
            None => -22,
        },
        230 => match arg_u32(a) {
            Some(clk) => sys_clock_getres_impl(clk, b),
            None => -22,
        },
        231 => crate::proc::exit::sys_exit_group(a as i32),
        247 => match (arg_i32(a), arg_i32(b), arg_u32(d)) {
            (Some(idtype), Some(id), Some(opts)) => sys_waitid_impl(idtype, id, c, opts),
            _ => -22,
        },
        // ── uid / gid ────────────────────────────────────────────────────────────────────────────
        102 | 104 | 107 | 108 => 0,
        105 | 106 => 0,
        118 => {
            let pid = crate::proc::scheduler::current_pid();
            let gid = crate::proc::scheduler::with_proc(pid, |p| p.cred.gid).unwrap_or(0);
            let bytes = gid.to_le_bytes();
            if a != 0 {
                let _ = crate::uaccess::copy_to_user(a, &bytes);
            }
            if b != 0 {
                let _ = crate::uaccess::copy_to_user(b, &bytes);
            }
            if c != 0 {
                let _ = crate::uaccess::copy_to_user(c, &bytes);
            }
            0
        }
        119 => {
            let pid = crate::proc::scheduler::current_pid();
            let gid = crate::proc::scheduler::with_proc(pid, |p| p.cred.gid).unwrap_or(0);
            let bytes = gid.to_le_bytes();
            if a != 0 {
                let _ = crate::uaccess::copy_to_user(a, &bytes);
            }
            if b != 0 {
                let _ = crate::uaccess::copy_to_user(b, &bytes);
            }
            if c != 0 {
                let _ = crate::uaccess::copy_to_user(c, &bytes);
            }
            0
        }
        117 | 120 => 0,
        // ── scheduler attrs ────────────────────────────────────────────────────────────────
        309 => sys_getcpu_impl(a, b, c),
        310 => sys_process_vm_writev_impl(a, b, c, d, e, f),
        315 => sys_sched_getattr_impl(a, b as u32, c as u32, d as u32),
        316 => sys_sched_setattr_impl(a, b, c as u32),
        // ── random ───────────────────────────────────────────────────────────────────────────────
        318 => match arg_u32(c) {
            Some(flags) => sys_getrandom_impl(a, b, flags),
            None => -22,
        },
        // ── sendmmsg / recvmmsg ──────────────────────────────────────────────────────────────
        299 => sys_recvmmsg_impl(a, b, c as u32, d as u32, e),
        307 => sys_sendmmsg_impl(a, b, c as u32, d as u32),
        // ── pidfd ───────────────────────────────────────────────────────────────────────────────
        302 => sys_prlimit64_impl(a, b as u32, c, d),
        320 => sys_kexec_file_load_impl(),
        321 => sys_bpf_impl(),
        323 => sys_userfaultfd_impl(),
        424 => crate::fs::pidfd::sys_pidfd_send_signal(a, b as u32, c, d as u32),
        434 => crate::fs::pidfd::sys_pidfd_open(a, b as u32),
        435 => crate::proc::clone::sys_clone3(a, b),
        438 => crate::fs::pidfd::sys_pidfd_getfd(a, b, c as u32),
        // ── permission / attribute stubs ──────────────────────────────────────────────────
        90 => sys_chmod_impl(a, b as u32),
        91 => sys_fchmod_impl(a, b as u32),
        92 => sys_chown_impl(a, b as u32, c as u32),
        93 => sys_lchown_impl(a, b as u32, c as u32),
        94 => sys_fchown_impl(a, b as u32, c as u32),
        101 => sys_ptrace_impl(a as i32, b as i32, c, d),
        103 => sys_syslog_impl(a as i32, b, c as i32),
        165 => sys_mount_impl(a, b, c, d as u64, e),
        _ => -38, // ENOSYS
    }
}

// ── Syscall-side side-table cleanup (called from do_exit) ─────────────────────────────────────────────────────────

pub fn altstack_clear_pid(pid: usize) {
    crate::proc::signal::altstack_clear_pid(pid);
}

pub fn proc_name_clear(pid: usize) {
    crate::syscall::proc_name_clear(pid);
}
