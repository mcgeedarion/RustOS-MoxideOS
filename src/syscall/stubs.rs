//! Stub implementations for syscalls that have no full implementation yet,
//! plus AT-variant helpers used by multiple syscall files.
//!
//! Functions here are `pub(super)` and called directly from `mod.rs`.

extern crate alloc;
use alloc::string::String;

use crate::proc::scheduler;

// ── AT_FDCWD sentinel used in this file ──────────────────────────────────────
const AT_FDCWD_STUBS: i32 = -100;

// ── resolve_at_path_for_stubs ─────────────────────────────────────────────────
/// Resolve a (dirfd, path_va) pair into an absolute path string.
/// Returns Err(errno) on failure.
pub(super) fn resolve_at_path_for_stubs(dirfd: i32, path_va: usize) -> Result<String, isize> {
    crate::fs::path::resolve_at(dirfd, path_va).map_err(|e| e as isize)
}

// ── copy_to_user / copy_from_user helpers ─────────────────────────────────────
/// Copy bytes from kernel to a user-space virtual address.
/// Returns Err(()) on fault.
pub(super) fn copy_to_user(dst_va: usize, src: &[u8]) -> Result<(), ()> {
    crate::mm::user_copy::copy_to_user(dst_va, src)
}

/// Copy bytes from a user-space virtual address into a kernel slice.
/// Returns Err(()) on fault.
pub(super) fn copy_from_user(dst: &mut [u8], src_va: usize) -> Result<(), ()> {
    crate::mm::user_copy::copy_from_user(dst, src_va)
}

// ── getdents64 ────────────────────────────────────────────────────────────────

pub(super) fn sys_getdents64_impl(fd: usize, buf_va: usize, count: usize) -> isize {
    crate::fs::io_syscalls::sys_getdents64(fd, buf_va, count)
}

// ── mmap / munmap / mprotect / madvise / msync / mlock* ─────────────────────

pub(super) fn sys_mmap_impl(
    addr: usize, len: usize, prot: i32, flags: i32, fd: i32, off: i64,
) -> isize {
    crate::mm::mmap::sys_mmap(addr, len, prot, flags, fd, off)
}

pub(super) fn sys_munmap_impl(addr: usize, len: usize) -> isize {
    crate::mm::mmap::sys_munmap(addr, len)
}

pub(super) fn sys_mprotect_impl(addr: usize, len: usize, prot: i32) -> isize {
    crate::mm::mmap::sys_mprotect(addr, len, prot)
}

pub(super) fn sys_madvise_impl(_addr: usize, _len: usize, _advice: i32) -> isize { 0 }
pub(super) fn sys_msync_impl(_addr: usize, _len: usize, _flags: i32) -> isize { 0 }
pub(super) fn sys_mlock_impl(_addr: usize, _len: usize) -> isize { 0 }
pub(super) fn sys_munlock_impl(_addr: usize, _len: usize) -> isize { 0 }
pub(super) fn sys_mlockall_impl(_flags: i32) -> isize { 0 }
pub(super) fn sys_munlockall_impl() -> isize { 0 }

// ── mremap ────────────────────────────────────────────────────────────────────

pub(super) fn sys_mremap_impl(
    old_addr: usize, old_len: usize, new_len: usize, flags: i32, new_addr: usize,
) -> isize {
    crate::mm::mmap::sys_mremap(old_addr, old_len, new_len, flags, new_addr)
}

// ── brk ───────────────────────────────────────────────────────────────────────

pub(super) fn sys_brk_impl(addr: usize) -> isize {
    crate::mm::brk::sys_brk(addr)
}

// ── access / faccessat ────────────────────────────────────────────────────────

pub(super) fn sys_access_impl(path_va: usize, mode: u32) -> isize {
    sys_faccessat_impl(AT_FDCWD_STUBS, path_va, mode, 0)
}

pub(super) fn sys_faccessat_impl(dirfd: i32, path_va: usize, mode: u32, _flags: i32) -> isize {
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::access(&path, mode)
}

// ── chdir / fchdir / getcwd ───────────────────────────────────────────────────

pub(super) fn sys_chdir_impl(path_va: usize) -> isize {
    crate::fs::cwd::sys_chdir(path_va)
}

pub(super) fn sys_fchdir_impl(fd: usize) -> isize {
    crate::fs::cwd::sys_fchdir(fd)
}

pub(super) fn sys_getcwd_impl(buf_va: usize, size: usize) -> isize {
    crate::fs::cwd::sys_getcwd(buf_va, size)
}

// ── rename / renameat / renameat2 ─────────────────────────────────────────────

pub(super) fn sys_rename_impl(old_va: usize, new_va: usize) -> isize {
    sys_renameat2_impl(AT_FDCWD_STUBS, old_va, AT_FDCWD_STUBS, new_va, 0)
}

pub(super) fn sys_renameat_impl(
    old_dir: i32, old_va: usize, new_dir: i32, new_va: usize,
) -> isize {
    sys_renameat2_impl(old_dir, old_va, new_dir, new_va, 0)
}

pub(super) fn sys_renameat2_impl(
    old_dir: i32, old_va: usize, new_dir: i32, new_va: usize, flags: u32,
) -> isize {
    let old = match resolve_at_path_for_stubs(old_dir, old_va) {
        Ok(p) => p, Err(e) => return e,
    };
    let new = match resolve_at_path_for_stubs(new_dir, new_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::rename(&old, &new, flags)
}

// ── mkdir / mkdirat ───────────────────────────────────────────────────────────

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
        Ok(p) => p, Err(e) => return e,
    };
    if flags & AT_REMOVEDIR != 0 {
        crate::fs::vfs_ops::rmdir(&path)
    } else {
        crate::fs::vfs_ops::unlink(&path)
    }
}

pub(super) fn sys_unlink_impl(path_va: usize) -> isize {
    sys_unlinkat_impl(AT_FDCWD_STUBS, path_va, 0)
}

pub(super) fn sys_rmdir_impl(path_va: usize) -> isize {
    sys_unlinkat_impl(AT_FDCWD_STUBS, path_va, 0x200)
}

// ── symlink / symlinkat / readlink / readlinkat ───────────────────────────────

pub(super) fn sys_symlinkat_impl(target_va: usize, new_dir: i32, link_va: usize) -> isize {
    let target = match crate::mm::user_copy::read_user_cstr(target_va, 4096) {
        Ok(s) => s, Err(_) => return -14,
    };
    let link = match resolve_at_path_for_stubs(new_dir, link_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::symlink(&target, &link)
}

pub(super) fn sys_symlink_impl(target_va: usize, link_va: usize) -> isize {
    sys_symlinkat_impl(target_va, AT_FDCWD_STUBS, link_va)
}

pub(super) fn sys_readlinkat_impl(
    dirfd: i32, path_va: usize, buf_va: usize, bufsz: usize,
) -> isize {
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::readlink(&path, buf_va, bufsz)
}

pub(super) fn sys_readlink_impl(path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    sys_readlinkat_impl(AT_FDCWD_STUBS, path_va, buf_va, bufsz)
}

// ── link / linkat ─────────────────────────────────────────────────────────────

pub(super) fn sys_linkat_impl(
    old_dir: i32, old_va: usize, new_dir: i32, new_va: usize, flags: i32,
) -> isize {
    let old = match resolve_at_path_for_stubs(old_dir, old_va) {
        Ok(p) => p, Err(e) => return e,
    };
    let new = match resolve_at_path_for_stubs(new_dir, new_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::link(&old, &new, flags)
}

pub(super) fn sys_link_impl(old_va: usize, new_va: usize) -> isize {
    sys_linkat_impl(AT_FDCWD_STUBS, old_va, AT_FDCWD_STUBS, new_va, 0)
}

// ── chmod / chown (scalar path forms) ────────────────────────────────────────

pub(super) fn sys_chmod_impl(path_va: usize, mode: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::chmod(&path, mode & 0o7777)
}

pub(super) fn sys_chown_impl(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::chown(&path, uid, gid)
}

pub(super) fn sys_lchown_impl(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::lchown(&path, uid, gid)
}

// ── truncate ─────────────────────────────────────────────────────────────────

pub(super) fn sys_truncate_impl(path_va: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::vfs_ops::truncate_by_path(&path, length as u64)
}

// ── statfs / fstatfs ──────────────────────────────────────────────────────────

pub(super) fn sys_statfs_impl(path_va: usize, buf_va: usize) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::stat_syscalls::sys_statfs_path(&path, buf_va)
}

pub(super) fn sys_fstatfs_impl(fd: usize, buf_va: usize) -> isize {
    crate::fs::stat_syscalls::sys_fstatfs(fd, buf_va)
}

// ── utimensat / futimesat / utimes / utime ────────────────────────────────────

pub(super) fn sys_utimensat_impl(
    dirfd: i32, path_va: usize, times_va: usize, flags: i32,
) -> isize {
    crate::fs::stat_syscalls::sys_utimensat(dirfd, path_va, times_va, flags)
}

pub(super) fn sys_futimesat_impl(dirfd: i32, path_va: usize, tv_va: usize) -> isize {
    crate::fs::stat_syscalls::sys_futimesat(dirfd, path_va, tv_va)
}

pub(super) fn sys_utimes_impl(path_va: usize, tv_va: usize) -> isize {
    sys_futimesat_impl(AT_FDCWD_STUBS, path_va, tv_va)
}

pub(super) fn sys_utime_impl(path_va: usize, buf_va: usize) -> isize {
    crate::fs::stat_syscalls::sys_utime(path_va, buf_va)
}

// ── chroot ────────────────────────────────────────────────────────────────────

pub(super) fn sys_chroot_impl(path_va: usize) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p, Err(e) => return e,
    };
    crate::fs::cwd::sys_chroot(&path)
}

// ── mount / umount2 ───────────────────────────────────────────────────────────

pub(super) fn sys_mount_impl(
    src_va: usize, dst_va: usize, fs_va: usize, flags: usize, data_va: usize,
) -> isize {
    crate::fs::mount::sys_mount(src_va, dst_va, fs_va, flags, data_va)
}

pub(super) fn sys_umount2_impl(target_va: usize, flags: i32) -> isize {
    crate::fs::mount::sys_umount2(target_va, flags)
}

// ── ioctl ─────────────────────────────────────────────────────────────────────

pub(super) fn sys_ioctl_impl(fd: usize, req: usize, arg: usize) -> isize {
    crate::fs::ioctl::sys_ioctl(fd, req, arg)
}

// ── sendfile ─────────────────────────────────────────────────────────────────

pub(super) fn sys_sendfile_impl(
    out_fd: usize, in_fd: usize, offset_va: usize, count: usize,
) -> isize {
    crate::fs::io_syscalls::sys_sendfile(out_fd, in_fd, offset_va, count)
}

// ── splice / tee / vmsplice ───────────────────────────────────────────────────

pub(super) fn sys_splice_impl(
    fd_in: usize, off_in: usize, fd_out: usize, off_out: usize,
    len: usize, flags: u32,
) -> isize {
    crate::fs::io_syscalls::sys_splice(fd_in, off_in, fd_out, off_out, len, flags)
}

pub(super) fn sys_tee_impl(
    fd_in: usize, fd_out: usize, len: usize, flags: u32,
) -> isize {
    crate::fs::io_syscalls::sys_tee(fd_in, fd_out, len, flags)
}

pub(super) fn sys_vmsplice_impl(
    fd: usize, iov_va: usize, nr_segs: usize, flags: u32,
) -> isize {
    crate::fs::io_syscalls::sys_vmsplice(fd, iov_va, nr_segs, flags)
}

// ── inotify ───────────────────────────────────────────────────────────────────

pub(super) fn sys_inotify_init_impl() -> isize {
    crate::fs::inotify::sys_inotify_init()
}

pub(super) fn sys_inotify_init1_impl(flags: i32) -> isize {
    crate::fs::inotify::sys_inotify_init1(flags)
}

pub(super) fn sys_inotify_add_watch_impl(fd: usize, path_va: usize, mask: u32) -> isize {
    crate::fs::inotify::sys_inotify_add_watch(fd, path_va, mask)
}

pub(super) fn sys_inotify_rm_watch_impl(fd: usize, wd: i32) -> isize {
    crate::fs::inotify::sys_inotify_rm_watch(fd, wd)
}

// ── fchownat / fchown ────────────────────────────────────────────────────────

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

// ── fchmodat / fchmod ────────────────────────────────────────────────────────

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

// ── remap_file_pages ────────────────────────────────────────────────────────

/// NR 216  remap_file_pages — deprecated since Linux 3.16, non-linear file
/// mappings removed in Linux 4.0.  Return ENOSYS so callers fall back to
/// standard mmap(2).
pub(super) fn sys_remap_file_pages_impl() -> isize { -38 }

// ── kexec_file_load / bpf / userfaultfd ──────────────────────────────────────

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

// ── ptrace ────────────────────────────────────────────────────────────────────

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
