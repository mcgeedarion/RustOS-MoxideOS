//! Syscall stubs — thin wrappers and minor implementations that do not
//! warrant their own module.

extern crate alloc;
use alloc::string::String;

use crate::fs::path::resolve_path;
use crate::proc::scheduler;

pub(super) const AT_FDCWD_STUBS: i32 = -100;

// ─── path resolution helper ──────────────────────────────────────────────────

pub(super) fn resolve_at_path_for_stubs(dirfd: i32, path_va: usize) -> Result<String, isize> {
    crate::fs::at_path::resolve_at(dirfd, path_va)
}

// copy helpers used by ptrace
fn copy_to_user(dst_va: usize, src: &[u8]) -> Result<(), ()> {
    crate::mm::uaccess::copy_to_user(dst_va, src)
}
fn copy_from_user(dst: &mut [u8], src_va: usize) -> Result<(), ()> {
    crate::mm::uaccess::copy_from_user(dst, src_va)
}

// ─── getcwd ──────────────────────────────────────────────────────────────────

/// NR 79  getcwd(buf_va, size)
pub(super) fn sys_getcwd_impl(buf_va: usize, size: usize) -> isize {
    let pid = scheduler::current_pid();
    let cwd = match scheduler::with_proc(pid, |p| p.cwd.clone()) {
        Some(s) => s,
        None    => return -22,
    };
    let bytes = cwd.as_bytes();
    if bytes.len() + 1 > size { return -34; } // ERANGE
    if copy_to_user(buf_va, bytes).is_err() { return -14; }
    if copy_to_user(buf_va + bytes.len(), &[0u8]).is_err() { return -14; }
    buf_va as isize
}

// ─── chdir / fchdir ──────────────────────────────────────────────────────────

/// NR 80  chdir(path_va)
pub(super) fn sys_chdir_impl(path_va: usize) -> isize {
    crate::fs::io_syscalls::sys_chdir(path_va)
}

/// NR 81  fchdir(fd)
pub(super) fn sys_fchdir_impl(fd: usize) -> isize {
    crate::fs::io_syscalls::sys_fchdir(fd)
}

// ─── rename / renameat ───────────────────────────────────────────────────────

/// NR 82  rename(old_va, new_va) — delegates to renameat with AT_FDCWD.
pub(super) fn sys_rename_impl(old_va: usize, new_va: usize) -> isize {
    sys_renameat_impl(AT_FDCWD_STUBS, old_va, AT_FDCWD_STUBS, new_va)
}

/// NR 264  renameat(old_dirfd, old_va, new_dirfd, new_va)
pub(super) fn sys_renameat_impl(
    old_dirfd: i32, old_va: usize, new_dirfd: i32, new_va: usize,
) -> isize {
    let old = match resolve_at_path_for_stubs(old_dirfd, old_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    let new = match resolve_at_path_for_stubs(new_dirfd, new_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::rename(&old, &new)
}

/// NR 316  renameat2(old_dirfd, old_va, new_dirfd, new_va, flags)
pub(super) fn sys_renameat2_impl(
    old_dirfd: i32, old_va: usize, new_dirfd: i32, new_va: usize, flags: u32,
) -> isize {
    if flags != 0 {
        // RENAME_NOREPLACE / RENAME_EXCHANGE / RENAME_WHITEOUT not yet
        return -38; // ENOSYS
    }
    sys_renameat_impl(old_dirfd, old_va, new_dirfd, new_va)
}

// ─── mkdir / mkdirat ─────────────────────────────────────────────────────────

/// NR 83  mkdir(path_va, mode)
pub(super) fn sys_mkdir_impl(path_va: usize, mode: u32) -> isize {
    sys_mkdirat_impl(AT_FDCWD_STUBS, path_va, mode)
}

pub(super) fn sys_mkdirat_impl(dirfd: i32, path_va: usize, mode: u32) -> isize {
    crate::fs::io_syscalls::sys_mkdirat(dirfd, path_va, mode)
}

/// NR 259  mknodat(dirfd, path_va, mode, dev)
///
/// Supported node types:
///   S_IFIFO  (0o010000) — create a named pipe via the VFS pipe layer.
///   S_IFSOCK (0o014000) — create a UNIX-domain socket node (AF_UNIX bind path).
///   S_IFCHR / S_IFBLK   — pass through to vfs_ops::mknod; returns EPERM if
///                          the driver table has no entry for (major, minor).
///   S_IFREG  with dev=0 — semantically equivalent to creat(2).
///   S_IFDIR  and other  — EINVAL per POSIX.
pub(super) fn sys_mknodat_impl(dirfd: i32, path_va: usize, mode: u32, dev: u64) -> isize {
    const S_IFMT:   u32 = 0o170000;
    const S_IFREG:  u32 = 0o100000;
    const S_IFCHR:  u32 = 0o020000;
    const S_IFBLK:  u32 = 0o060000;
    const S_IFIFO:  u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;

    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };

    match mode & S_IFMT {
        S_IFIFO => {
            // Named pipe: place a FIFO inode in the VFS so open(O_RDONLY) can
            // rendezvous with a future open(O_WRONLY) on the same path.
            crate::fs::pipe::create_named_pipe(&path, mode & !S_IFMT)
        }
        S_IFSOCK => {
            // Socket node: used by AF_UNIX bind(2).  The kernel socket itself
            // is not created here; we only anchor the path token in the VFS.
            crate::fs::vfs_ops::create_socket_node(&path, mode & !S_IFMT)
        }
        S_IFREG if dev == 0 => {
            // mknod(path, S_IFREG, 0) == creat(path, mode) per POSIX.
            crate::fs::vfs_ops::create_regular(&path, mode & !S_IFMT)
        }
        S_IFCHR | S_IFBLK => {
            // Device node: decode the dev_t encoding used by Linux x86-64:
            //   major = bits[19:8]  (12 bits)
            //   minor = bits[7:0] | bits[31:20]  (20 bits)
            let major = ((dev >> 8) & 0xfff) as u32;
            let minor = ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32;
            crate::fs::vfs_ops::mknod(&path, mode, major, minor)
        }
        _ => -22, // EINVAL — S_IFDIR or reserved type bits
    }
}

/// NR 133  mknod(path_va, mode, dev) — delegates to mknodat with AT_FDCWD.
pub(super) fn sys_mknod_impl(path_va: usize, mode: u32, dev: u64) -> isize {
    sys_mknodat_impl(AT_FDCWD_STUBS, path_va, mode, dev)
}

pub(super) fn sys_newfstatat_impl(dirfd: i32, path_va: usize, stat_va: usize, flags: u32) -> isize {
    crate::fs::stat_syscalls::sys_newfstatat(dirfd, path_va, stat_va, flags)
}

pub(super) fn sys_unlinkat_impl(dirfd: i32, path_va: usize, flags: u32) -> isize {
    const AT_REMOVEDIR: u32 = 0x200;
    if flags & !AT_REMOVEDIR != 0 { return -22; }
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    if flags & AT_REMOVEDIR != 0 {
        crate::fs::vfs_ops::rmdir(&path)
    } else {
        crate::fs::vfs_ops::unlink(&path)
    }
}

pub(super) fn sys_rmdir_impl(path_va: usize) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::rmdir(&path)
}

pub(super) fn sys_unlink_impl(path_va: usize) -> isize {
    sys_unlinkat_impl(AT_FDCWD_STUBS, path_va, 0)
}

// ─── symlink / readlink ───────────────────────────────────────────────────────

pub(super) fn sys_symlinkat_impl(target_va: usize, new_dirfd: i32, linkpath_va: usize) -> isize {
    let target = match crate::mm::uaccess::read_user_str(target_va, 4096) {
        Ok(s)  => s,
        Err(_) => return -14,
    };
    let link = match resolve_at_path_for_stubs(new_dirfd, linkpath_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::symlink(&target, &link)
}

pub(super) fn sys_symlink_impl(target_va: usize, linkpath_va: usize) -> isize {
    sys_symlinkat_impl(target_va, AT_FDCWD_STUBS, linkpath_va)
}

pub(super) fn sys_readlinkat_impl(
    dirfd: i32, path_va: usize, buf_va: usize, bufsz: usize,
) -> isize {
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    let target = match crate::fs::vfs_ops::readlink(&path) {
        Ok(s)  => s,
        Err(e) => return e,
    };
    let bytes = target.as_bytes();
    let n = bytes.len().min(bufsz);
    if copy_to_user(buf_va, &bytes[..n]).is_err() { return -14; }
    n as isize
}

pub(super) fn sys_readlink_impl(path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    sys_readlinkat_impl(AT_FDCWD_STUBS, path_va, buf_va, bufsz)
}

// ─── link / linkat ───────────────────────────────────────────────────────────

pub(super) fn sys_linkat_impl(
    old_dirfd: i32, old_va: usize, new_dirfd: i32, new_va: usize, _flags: i32,
) -> isize {
    let old = match resolve_at_path_for_stubs(old_dirfd, old_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    let new = match resolve_at_path_for_stubs(new_dirfd, new_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::link(&old, &new)
}

pub(super) fn sys_link_impl(old_va: usize, new_va: usize) -> isize {
    sys_linkat_impl(AT_FDCWD_STUBS, old_va, AT_FDCWD_STUBS, new_va, 0)
}

// ─── chmod / chown ───────────────────────────────────────────────────────────

pub(super) fn sys_chmod_impl(path_va: usize, mode: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::chmod(&path, mode & 0o7777)
}

pub(super) fn sys_chown_impl(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::chown(&path, uid, gid)
}

pub(super) fn sys_lchown_impl(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::lchown(&path, uid, gid)
}

// ─── umask ───────────────────────────────────────────────────────────────────

pub(super) fn sys_umask_impl(mask: u32) -> isize {
    let pid = scheduler::current_pid();
    let old = scheduler::with_proc(pid, |p| p.umask).unwrap_or(0o022);
    scheduler::with_proc_mut(pid, |p, _| p.umask = mask & 0o777).unwrap_or(());
    old as isize
}

// ─── access / faccessat ──────────────────────────────────────────────────────

pub(super) fn sys_faccessat_impl(dirfd: i32, path_va: usize, mode: i32, _flags: i32) -> isize {
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::access(&path, mode)
}

pub(super) fn sys_access_impl(path_va: usize, mode: i32) -> isize {
    sys_faccessat_impl(AT_FDCWD_STUBS, path_va, mode, 0)
}

// ─── truncate ────────────────────────────────────────────────────────────────

pub(super) fn sys_truncate_impl(path_va: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::truncate_path(&path, length as u64)
}

// ─── statfs / fstatfs ────────────────────────────────────────────────────────

pub(super) fn sys_statfs_impl(path_va: usize, buf_va: usize) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::stat_syscalls::sys_statfs_path(&path, buf_va)
}

pub(super) fn sys_fstatfs_impl(fd: usize, buf_va: usize) -> isize {
    crate::fs::stat_syscalls::sys_fstatfs(fd, buf_va)
}

// ─── getdents64 ──────────────────────────────────────────────────────────────

pub(super) fn sys_getdents64_impl(fd: usize, buf_va: usize, count: usize) -> isize {
    crate::fs::io_syscalls::sys_getdents64(fd, buf_va, count)
}

// ─── fchownat / fchown ───────────────────────────────────────────────────────

/// NR 260  fchownat(dirfd, path_va, uid, gid, flags)
///
/// AT_EMPTY_PATH (0x1000) + empty path: operate on dirfd inode directly.
/// AT_SYMLINK_NOFOLLOW (0x100): lchown semantics — stop at final symlink.
/// uid/gid == u32::MAX is the POSIX "don't change" sentinel; passed through
/// to the VFS which handles it.
pub(super) fn sys_fchownat_impl(
    dirfd: i32, path_va: usize, uid: u32, gid: u32, flags: i32,
) -> isize {
    const AT_EMPTY_PATH:       i32 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

    if flags & AT_EMPTY_PATH != 0 && path_va == 0 {
        let pid = crate::proc::scheduler::current_pid();
        match crate::fs::process_fd::proc_fd_path(pid, dirfd as usize) {
            Some(p) => return crate::fs::vfs_ops::chown(&p, uid, gid),
            None    => return -9, // EBADF
        }
    }

    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };

    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        crate::fs::vfs_ops::lchown(&path, uid, gid)
    } else {
        crate::fs::vfs_ops::chown(&path, uid, gid)
    }
}

/// NR 94  fchown(fd, uid, gid) — operate on an open file descriptor.
pub(super) fn sys_fchown_impl(fd: usize, uid: u32, gid: u32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match crate::fs::process_fd::proc_fd_path(pid, fd) {
        Some(p) => crate::fs::vfs_ops::chown(&p, uid, gid),
        None    => -9, // EBADF
    }
}

// ─── fchmodat / fchmod ───────────────────────────────────────────────────────

/// NR 268  fchmodat(dirfd, path_va, mode, flags)
///
/// AT_SYMLINK_NOFOLLOW is not supported for chmod on Linux (returns ENOTSUP).
/// Only flags == 0 is accepted.
pub(super) fn sys_fchmodat_impl(dirfd: i32, path_va: usize, mode: u32, flags: i32) -> isize {
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        return -95; // ENOTSUP — mirrors Linux fchmodat(2) + NOFOLLOW behaviour
    }
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p)  => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::chmod(&path, mode & 0o7777)
}

/// NR 91  fchmod(fd, mode) — operate on an open file descriptor.
pub(super) fn sys_fchmod_impl(fd: usize, mode: u32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match crate::fs::process_fd::proc_fd_path(pid, fd) {
        Some(p) => crate::fs::vfs_ops::chmod(&p, mode & 0o7777),
        None    => -9, // EBADF
    }
}

// ─── remap_file_pages ────────────────────────────────────────────────────────

/// NR 216  remap_file_pages — deprecated since Linux 3.16, non-linear file
/// mappings removed in Linux 4.0.  Return ENOSYS so callers fall back to
/// standard mmap(2).
pub(super) fn sys_remap_file_pages_impl() -> isize { -38 }

// ─── kexec_file_load / bpf / userfaultfd ─────────────────────────────────────

/// NR 320  kexec_file_load — booting a second kernel image is not applicable
/// to RustOS.  ENOSYS causes kexec-tools to abort gracefully.
pub(super) fn sys_kexec_file_load_impl() -> isize { -38 }

/// NR 321  bpf(cmd, attr, size) — BPF subsystem not implemented.
///
/// ENOSYS is intentional: it causes glibc/libseccomp to skip BPF-based
/// seccomp and fall back to classic mode.  EPERM would be misread as
/// "kernel has BPF but caller lacks CAP_BPF".
pub(super) fn sys_bpf_impl() -> isize { -38 }

/// NR 323  userfaultfd(flags) — user-space page-fault handling not implemented.
///
/// ENOSYS causes liburing / Go runtime to detect absence and skip the UFFD
/// code path.  EPERM would cause confusion as the runtime would think the
/// feature exists but is permission-denied.
pub(super) fn sys_userfaultfd_impl() -> isize { -38 }

// ─── ptrace ──────────────────────────────────────────────────────────────────

/// NR 101  ptrace(request, pid, addr, data)
///
/// Full implementation covering:
///   PTRACE_TRACEME, PTRACE_ATTACH, PTRACE_DETACH, PTRACE_CONT,
///   PTRACE_SINGLESTEP, PTRACE_SYSCALL, PTRACE_KILL,
///   PTRACE_PEEKTEXT/DATA/USER, PTRACE_POKETEXT/DATA/USER,
///   PTRACE_GETREGS, PTRACE_SETREGS,
///   PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG, PTRACE_GETSIGINFO.
///
/// Cross-process memory access uses Paging::virt_to_phys_cr3, the same
/// mechanism as process_vm_readv/writev.  Register access uses
/// proc::ptrace::{build_user_regs_pub, apply_user_regs_pub} which operate
/// on the saved kernel stack frame.
pub(super) fn sys_ptrace_impl(request: i32, pid: i32, addr: usize, data: usize) -> isize {
    use crate::arch::api::Paging;
    use crate::mm::pmm::PAGE_SIZE;
    use crate::proc::ptrace::{
        PtraceState,
        PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_PEEKUSER,
        PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSER,
        PTRACE_CONT, PTRACE_KILL, PTRACE_SINGLESTEP,
        PTRACE_GETREGS, PTRACE_SETREGS,
        PTRACE_ATTACH, PTRACE_DETACH, PTRACE_SYSCALL,
        PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG,
        PTRACE_O_MASK, UREG_COUNT, FRAME_SZ,
        build_user_regs_pub, apply_user_regs_pub,
    };
    const PTRACE_GETSIGINFO: i32 = 0x4202;
    const USER_REGS_BYTES: usize = UREG_COUNT * 8;

    let caller = crate::proc::scheduler::current_pid();

    match request {
        // ── PTRACE_TRACEME ───────────────────────────────────────────────────
        PTRACE_TRACEME => {
            let ppid = crate::proc::scheduler::current_ppid();
            crate::proc::scheduler::with_proc_mut(caller, |p, _| {
                p.ptrace_state = PtraceState::Tracee {
                    tracer: ppid, options: 0, in_syscall_stop: false,
                };
            }).unwrap_or(());
            0
        }

        // ── PTRACE_ATTACH ────────────────────────────────────────────────────
        PTRACE_ATTACH => {
            let target = pid as usize;
            if crate::proc::scheduler::with_proc(target, |_| ()).is_none() {
                return -3; // ESRCH
            }
            crate::proc::scheduler::with_proc_mut(target, |p, _| {
                p.ptrace_state = PtraceState::Tracee {
                    tracer: caller, options: 0, in_syscall_stop: false,
                };
            }).unwrap_or(());
            crate::proc::signal::send_signal(target, 19 /* SIGSTOP */);
            0
        }

        // ── PTRACE_DETACH ────────────────────────────────────────────────────
        PTRACE_DETACH => {
            let target = pid as usize;
            crate::proc::scheduler::with_proc_mut(target, |p, _| {
                p.ptrace_state = PtraceState::None;
            }).unwrap_or(());
            if data != 0 {
                crate::proc::signal::send_signal(target, data as i32);
            }
            crate::proc::scheduler::wake(target);
            0
        }

        // ── PTRACE_CONT / PTRACE_SYSCALL ─────────────────────────────────────
        PTRACE_CONT | PTRACE_SYSCALL => {
            let target = pid as usize;
            crate::proc::scheduler::with_proc_mut(target, |p, _| {
                let (tracer, options) = match p.ptrace_state {
                    PtraceState::Stopped { tracer, options, .. } => (tracer, options),
                    PtraceState::Tracee  { tracer, options, .. } => (tracer, options),
                    PtraceState::None => return,
                };
                let in_syscall = request == PTRACE_SYSCALL;
                p.ptrace_state = PtraceState::Tracee {
                    tracer, options, in_syscall_stop: in_syscall,
                };
                // Clear TF (trap flag) on resume unless we need single-step.
                #[cfg(target_arch = "x86_64")]
                if let Some(kstack) = p.kstack_top {
                    let f = unsafe {
                        core::slice::from_raw_parts_mut(
                            (kstack - FRAME_SZ) as *mut usize, 17)
                    };
                    f[14] &= !(1usize << 8); // F_R11 = EFLAGS on SYSRET path
                }
            }).unwrap_or(());
            if data != 0 { crate::proc::signal::send_signal(pid as usize, data as i32); }
            crate::proc::scheduler::wake(pid as usize);
            0
        }

        // ── PTRACE_SINGLESTEP ────────────────────────────────────────────────
        PTRACE_SINGLESTEP => {
            let target = pid as usize;
            crate::proc::scheduler::with_proc_mut(target, |p, _| {
                #[cfg(target_arch = "x86_64")]
                if let Some(kstack) = p.kstack_top {
                    let f = unsafe {
                        core::slice::from_raw_parts_mut(
                            (kstack - FRAME_SZ) as *mut usize, 17)
                    };
                    f[14] |= 1usize << 8; // set TF in EFLAGS
                }
                let (tracer, options) = match p.ptrace_state {
                    PtraceState::Stopped { tracer, options, .. } => (tracer, options),
                    PtraceState::Tracee  { tracer, options, .. } => (tracer, options),
                    PtraceState::None => return,
                };
                p.ptrace_state = PtraceState::Tracee {
                    tracer, options, in_syscall_stop: false,
                };
            }).unwrap_or(());
            if data != 0 { crate::proc::signal::send_signal(pid as usize, data as i32); }
            crate::proc::scheduler::wake(pid as usize);
            0
        }

        // ── PTRACE_KILL ──────────────────────────────────────────────────────
        PTRACE_KILL => {
            crate::proc::signal::send_signal(pid as usize, 9 /* SIGKILL */);
            0
        }

        // ── PTRACE_PEEKTEXT / PTRACE_PEEKDATA ────────────────────────────────
        // Both read one machine word from the tracee's virtual address space.
        // The word is returned as the syscall result; *data is also written for
        // old-ABI compat.
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            if addr & (core::mem::size_of::<usize>() - 1) != 0 { return -22; }
            let remote_cr3 = match crate::proc::scheduler::with_proc(pid as usize, |p| p.cr3) {
                Some(cr3) => cr3,
                None      => return -3, // ESRCH
            };
            let pa = match Paging::virt_to_phys_cr3(remote_cr3, addr) {
                Some(pa) => pa,
                None     => return -14, // EFAULT
            };
            let word: usize = unsafe {
                core::ptr::read((pa + (addr & (PAGE_SIZE - 1))) as *const usize)
            };
            if data != 0 {
                if copy_to_user(data, &word.to_le_bytes()).is_err() { return -14; }
            }
            word as isize
        }

        // ── PTRACE_POKETEXT / PTRACE_POKEDATA ────────────────────────────────
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            if addr & (core::mem::size_of::<usize>() - 1) != 0 { return -22; }
            let remote_cr3 = match crate::proc::scheduler::with_proc(pid as usize, |p| p.cr3) {
                Some(cr3) => cr3,
                None      => return -3,
            };
            let pa = match Paging::virt_to_phys_cr3(remote_cr3, addr) {
                Some(pa) => pa,
                None     => return -14,
            };
            unsafe {
                core::ptr::write(
                    (pa + (addr & (PAGE_SIZE - 1))) as *mut usize, data)
            };
            0
        }

        // ── PTRACE_PEEKUSER ──────────────────────────────────────────────────
        // Read one 8-byte slot from the tracee's user_regs_struct by byte offset.
        PTRACE_PEEKUSER => {
            if addr & 7 != 0 || addr + 8 > USER_REGS_BYTES { return -22; }
            let slot = addr / 8;
            let val = crate::proc::scheduler::with_proc(pid as usize, |p| {
                p.kstack_top.map(|ks| {
                    let regs = build_user_regs_pub(ks, p.fs_base);
                    if slot < UREG_COUNT { regs[slot] } else { 0 }
                }).unwrap_or(0)
            }).unwrap_or(0);
            if data != 0 {
                if copy_to_user(data, &val.to_le_bytes()).is_err() { return -14; }
            }
            val as isize
        }

        // ── PTRACE_POKEUSER ──────────────────────────────────────────────────
        PTRACE_POKEUSER => {
            if addr & 7 != 0 || addr + 8 > USER_REGS_BYTES { return -22; }
            let slot = addr / 8;
            crate::proc::scheduler::with_proc_mut(pid as usize, |p, _| {
                if let Some(ks) = p.kstack_top {
                    let mut regs = build_user_regs_pub(ks, p.fs_base);
                    if slot < UREG_COUNT {
                        regs[slot] = data as u64;
                        apply_user_regs_pub(ks, &regs);
                    }
                }
            }).unwrap_or(());
            0
        }

        // ── PTRACE_GETREGS ───────────────────────────────────────────────────
        PTRACE_GETREGS => {
            let regs_opt = crate::proc::scheduler::with_proc(pid as usize, |p| {
                p.kstack_top.map(|ks| build_user_regs_pub(ks, p.fs_base))
            });
            match regs_opt {
                Some(Some(regs)) => {
                    let bytes: [u8; UREG_COUNT * 8] = unsafe {
                        core::mem::transmute(regs)
                    };
                    if copy_to_user(data, &bytes).is_err() { return -14; }
                    0
                }
                _ => -3, // ESRCH
            }
        }

        // ── PTRACE_SETREGS ───────────────────────────────────────────────────
        PTRACE_SETREGS => {
            let mut bytes = [0u8; UREG_COUNT * 8];
            if copy_from_user(&mut bytes, data).is_err() { return -14; }
            let regs: [u64; UREG_COUNT] = unsafe { core::mem::transmute(bytes) };
            crate::proc::scheduler::with_proc_mut(pid as usize, |p, _| {
                if let Some(ks) = p.kstack_top {
                    apply_user_regs_pub(ks, &regs);
                }
            }).unwrap_or(());
            0
        }

        // ── PTRACE_SETOPTIONS ────────────────────────────────────────────────
        PTRACE_SETOPTIONS => {
            let opts = (data as u64) & PTRACE_O_MASK;
            crate::proc::scheduler::with_proc_mut(pid as usize, |p, _| {
                if let PtraceState::Tracee { ref mut options, .. } = p.ptrace_state {
                    *options = opts;
                }
            }).unwrap_or(());
            0
        }

        // ── PTRACE_GETEVENTMSG ───────────────────────────────────────────────
        PTRACE_GETEVENTMSG => {
            let msg = crate::proc::scheduler::with_proc(pid as usize, |p| {
                p.ptrace_event_msg
            }).unwrap_or(0);
            if copy_to_user(data, &msg.to_le_bytes()).is_err() { return -14; }
            0
        }

        // ── PTRACE_GETSIGINFO ────────────────────────────────────────────────
        PTRACE_GETSIGINFO => {
            let si = crate::proc::signal::get_pending_siginfo(pid as usize);
            if copy_to_user(data, &si).is_err() { return -14; }
            0
        }

        _ => -22, // EINVAL — unrecognized ptrace request
    }
}
