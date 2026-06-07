// Syscall stubs — thin wrappers and minor implementations that do not
// warrant their own module.

use crate::fs::path::resolve_path;
use crate::proc::scheduler;

// Named errno helpers — all sourced from the shared errno module.
use crate::syscall::errno::{ebadf, enotsup, erange, esrch};

// Named signal numbers.
use crate::syscall::signal_nr::{SIGKILL, SIGSTOP};

pub(super) const AT_FDCWD_STUBS: i32 = -100;

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

/// NR 79  getcwd(buf_va, size)
pub(super) fn sys_getcwd_impl(buf_va: usize, size: usize) -> isize {
    let pid = scheduler::current_pid();
    let cwd = match scheduler::with_proc(pid, |p| p.cwd.clone()) {
        Some(s) => s,
        None => return einval(),
    };
    let bytes = cwd.as_bytes();
    if bytes.len() + 1 > size {
        return erange();
    }
    if copy_to_user(buf_va, bytes).is_err() {
        return efault();
    }
    if copy_to_user(buf_va + bytes.len(), &[0u8]).is_err() {
        return efault();
    }
    buf_va as isize
}

/// NR 80  chdir(path_va)
pub(super) fn sys_chdir_impl(path_va: usize) -> isize {
    crate::fs::io_syscalls::sys_chdir(path_va)
}

/// NR 81  fchdir(fd)
pub(super) fn sys_fchdir_impl(fd: usize) -> isize {
    crate::fs::io_syscalls::sys_fchdir(fd)
}

/// NR 82  rename(old_va, new_va) — delegates to renameat with AT_FDCWD.
pub(super) fn sys_rename_impl(old_va: usize, new_va: usize) -> isize {
    sys_renameat_impl(AT_FDCWD_STUBS, old_va, AT_FDCWD_STUBS, new_va)
}

/// NR 264  renameat(old_dirfd, old_va, new_dirfd, new_va)
pub(super) fn sys_renameat_impl(
    old_dirfd: i32,
    old_va: usize,
    new_dirfd: i32,
    new_va: usize,
) -> isize {
    let old = match resolve_at_path_for_stubs(old_dirfd, old_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new = match resolve_at_path_for_stubs(new_dirfd, new_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::rename(&old, &new)
}

/// NR 316  renameat2(old_dirfd, old_va, new_dirfd, new_va, flags)
pub(super) fn sys_renameat2_impl(
    old_dirfd: i32,
    old_va: usize,
    new_dirfd: i32,
    new_va: usize,
    flags: u32,
) -> isize {
    if flags != 0 {
        // RENAME_NOREPLACE / RENAME_EXCHANGE / RENAME_WHITEOUT not yet implemented.
        return enosys();
    }
    sys_renameat_impl(old_dirfd, old_va, new_dirfd, new_va)
}

/// NR 83  mkdir(path_va, mode)
pub(super) fn sys_mkdir_impl(path_va: usize, mode: u32) -> isize {
    sys_mkdirat_impl(AT_FDCWD_STUBS, path_va, mode)
}

pub(super) fn sys_mkdirat_impl(dirfd: i32, path_va: usize, mode: u32) -> isize {
    crate::fs::io_syscalls::sys_mkdirat(dirfd, path_va, mode)
}

/// NR 259  mknodat(dirfd, path_va, mode, dev)
pub(super) fn sys_mknodat_impl(dirfd: i32, path_va: usize, mode: u32, dev: u64) -> isize {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;

    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };

    match mode & S_IFMT {
        S_IFIFO => crate::fs::pipe::create_named_pipe(&path, mode & !S_IFMT),
        S_IFSOCK => crate::fs::vfs_ops::create_socket_node(&path, mode & !S_IFMT),
        S_IFREG if dev == 0 => crate::fs::vfs_ops::create_regular(&path, mode & !S_IFMT),
        S_IFCHR | S_IFBLK => {
            let major = ((dev >> 8) & 0xfff) as u32;
            let minor = ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32;
            crate::fs::vfs_ops::mknod(&path, mode, major, minor)
        },
        _ => einval(),
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
    if flags & !AT_REMOVEDIR != 0 {
        return einval();
    }
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p,
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
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::rmdir(&path)
}

pub(super) fn sys_unlink_impl(path_va: usize) -> isize {
    sys_unlinkat_impl(AT_FDCWD_STUBS, path_va, 0)
}

pub(super) fn sys_symlinkat_impl(target_va: usize, new_dirfd: i32, linkpath_va: usize) -> isize {
    let target = match crate::mm::uaccess::read_user_str(target_va, 4096) {
        Ok(s) => s,
        Err(_) => return efault(),
    };
    let link = match resolve_at_path_for_stubs(new_dirfd, linkpath_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::symlink(&target, &link)
}

pub(super) fn sys_symlink_impl(target_va: usize, linkpath_va: usize) -> isize {
    sys_symlinkat_impl(target_va, AT_FDCWD_STUBS, linkpath_va)
}

pub(super) fn sys_readlinkat_impl(
    dirfd: i32,
    path_va: usize,
    buf_va: usize,
    bufsz: usize,
) -> isize {
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let target = match crate::fs::vfs_ops::readlink(&path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let bytes = target.as_bytes();
    let n = bytes.len().min(bufsz);
    if copy_to_user(buf_va, &bytes[..n]).is_err() {
        return efault();
    }
    n as isize
}

pub(super) fn sys_readlink_impl(path_va: usize, buf_va: usize, bufsz: usize) -> isize {
    sys_readlinkat_impl(AT_FDCWD_STUBS, path_va, buf_va, bufsz)
}

pub(super) fn sys_linkat_impl(
    old_dirfd: i32,
    old_va: usize,
    new_dirfd: i32,
    new_va: usize,
    _flags: i32,
) -> isize {
    let old = match resolve_at_path_for_stubs(old_dirfd, old_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new = match resolve_at_path_for_stubs(new_dirfd, new_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::link(&old, &new)
}

pub(super) fn sys_link_impl(old_va: usize, new_va: usize) -> isize {
    sys_linkat_impl(AT_FDCWD_STUBS, old_va, AT_FDCWD_STUBS, new_va, 0)
}

pub(super) fn sys_chmod_impl(path_va: usize, mode: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::chmod(&path, mode & 0o7777)
}

pub(super) fn sys_chown_impl(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::chown(&path, uid, gid)
}

pub(super) fn sys_lchown_impl(path_va: usize, uid: u32, gid: u32) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::lchown(&path, uid, gid)
}

pub(super) fn sys_umask_impl(mask: u32) -> isize {
    let pid = scheduler::current_pid();
    let old = scheduler::with_proc(pid, |p| p.umask).unwrap_or(0o022);
    scheduler::with_proc_mut(pid, |p, _| p.umask = mask & 0o777).unwrap_or(());
    old as isize
}

pub(super) fn sys_faccessat_impl(dirfd: i32, path_va: usize, mode: i32, _flags: i32) -> isize {
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::access(&path, mode)
}

pub(super) fn sys_access_impl(path_va: usize, mode: i32) -> isize {
    sys_faccessat_impl(AT_FDCWD_STUBS, path_va, mode, 0)
}

pub(super) fn sys_truncate_impl(path_va: usize, length: i64) -> isize {
    if length < 0 {
        return einval();
    }
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::truncate_path(&path, length as u64)
}

pub(super) fn sys_statfs_impl(path_va: usize, buf_va: usize) -> isize {
    let path = match resolve_at_path_for_stubs(AT_FDCWD_STUBS, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::stat_syscalls::sys_statfs_path(&path, buf_va)
}

pub(super) fn sys_fstatfs_impl(fd: usize, buf_va: usize) -> isize {
    crate::fs::stat_syscalls::sys_fstatfs(fd, buf_va)
}

pub(super) fn sys_getdents64_impl(fd: usize, buf_va: usize, count: usize) -> isize {
    crate::fs::io_syscalls::sys_getdents64(fd, buf_va, count)
}

/// NR 260  fchownat(dirfd, path_va, uid, gid, flags)
pub(super) fn sys_fchownat_impl(
    dirfd: i32,
    path_va: usize,
    uid: u32,
    gid: u32,
    flags: i32,
) -> isize {
    const AT_EMPTY_PATH: i32 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

    if flags & AT_EMPTY_PATH != 0 && path_va == 0 {
        let pid = crate::proc::scheduler::current_pid();
        match crate::fs::process_fd::proc_fd_path(pid, dirfd as usize) {
            Some(p) => return crate::fs::vfs_ops::chown(&p, uid, gid),
            None => return ebadf(),
        }
    }

    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p,
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
        None => ebadf(),
    }
}

/// NR 268  fchmodat(dirfd, path_va, mode, flags)
pub(super) fn sys_fchmodat_impl(dirfd: i32, path_va: usize, mode: u32, flags: i32) -> isize {
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        return enotsup();
    }
    let path = match resolve_at_path_for_stubs(dirfd, path_va) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::fs::vfs_ops::chmod(&path, mode & 0o7777)
}

/// NR 91  fchmod(fd, mode) — operate on an open file descriptor.
pub(super) fn sys_fchmod_impl(fd: usize, mode: u32) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match crate::fs::process_fd::proc_fd_path(pid, fd) {
        Some(p) => crate::fs::vfs_ops::chmod(&p, mode & 0o7777),
        None => ebadf(),
    }
}

pub(super) fn sys_remap_file_pages_impl() -> isize {
    enosys()
}
pub(super) fn sys_kexec_file_load_impl() -> isize {
    enosys()
}
pub(super) fn sys_bpf_impl() -> isize {
    enosys()
}
pub(super) fn sys_userfaultfd_impl() -> isize {
    enosys()
}

/// Validate that `addr` is naturally aligned for a `usize` read/write.
#[inline]
fn ptrace_validate_word_addr(addr: usize) -> Result<(), isize> {
    if addr & (core::mem::size_of::<usize>() - 1) != 0 {
        Err(einval())
    } else {
        Ok(())
    }
}

/// Validate that `addr` is 8-byte-aligned and fits within the user_regs block.
#[inline]
fn ptrace_validate_ureg_slot(addr: usize, user_regs_bytes: usize) -> Result<usize, isize> {
    if addr & 7 != 0 || addr + 8 > user_regs_bytes {
        return Err(einval());
    }
    Ok(addr / 8)
}

/// Resolve the page-table physical address for `addr` in the target process's
/// address space.
#[inline]
fn ptrace_resolve_remote_pa(pid: i32, addr: usize) -> Result<usize, isize> {
    use crate::arch::api::Paging;
    use crate::mm::pmm::PAGE_SIZE;
    let cr3 = match crate::proc::scheduler::with_proc(pid as usize, |p| p.cr3) {
        Some(cr3) => cr3,
        None => return Err(esrch()),
    };
    match Paging::virt_to_phys_cr3(cr3, addr) {
        Some(pa) => Ok(pa + (addr & (PAGE_SIZE - 1))),
        None => Err(efault()),
    }
}

/// Check that the caller is permitted to trace `target_pid`.
#[inline]
fn ptrace_check_permission(caller: usize, target_pid: i32) -> Result<(), isize> {
    use crate::syscall::errno::eperm;
    if target_pid as usize == caller {
        return Err(eperm());
    }
    match crate::proc::scheduler::with_proc(target_pid as usize, |_| ()) {
        Some(_) => Ok(()),
        None => Err(esrch()),
    }
}

/// Read `N` u64 register values from userspace at `va`.
#[inline]
fn ptrace_copy_regs_from_user<const N: usize>(va: usize) -> Result<[u64; N], isize> {
    let mut bytes = [0u8; N * 8];
    if copy_from_user(&mut bytes, va).is_err() {
        return Err(efault());
    }
    let mut regs = [0u64; N];
    for i in 0..N {
        let off = i * 8;
        regs[i] = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap_or([0u8; 8]));
    }
    Ok(regs)
}

/// Write `N` u64 register values to userspace at `va`.
#[inline]
fn ptrace_copy_regs_to_user<const N: usize>(va: usize, regs: &[u64; N]) -> Result<(), isize> {
    let mut bytes = [0u8; N * 8];
    for (i, &reg) in regs.iter().enumerate() {
        let off = i * 8;
        bytes[off..off + 8].copy_from_slice(&reg.to_le_bytes());
    }
    if copy_to_user(va, &bytes).is_err() {
        return Err(efault());
    }
    Ok(())
}

/// NR 101  ptrace(request, pid, addr, data)
pub(crate) fn sys_ptrace_impl(request: i32, pid: i32, addr: usize, data: usize) -> isize {
    use crate::mm::pmm::PAGE_SIZE;
    use crate::proc::ptrace::{
        apply_user_regs_pub, build_user_regs_pub, PtraceState, FRAME_SZ, PTRACE_ATTACH,
        PTRACE_CONT, PTRACE_DETACH, PTRACE_GETEVENTMSG, PTRACE_GETREGS, PTRACE_KILL, PTRACE_O_MASK,
        PTRACE_PEEKDATA, PTRACE_PEEKTEXT, PTRACE_PEEKUSER, PTRACE_POKEDATA, PTRACE_POKETEXT,
        PTRACE_POKEUSER, PTRACE_SETOPTIONS, PTRACE_SETREGS, PTRACE_SINGLESTEP, PTRACE_SYSCALL,
        PTRACE_TRACEME, UREG_COUNT,
    };
    const PTRACE_GETSIGINFO: i32 = 0x4202;
    const USER_REGS_BYTES: usize = UREG_COUNT * 8;

    let caller = crate::proc::scheduler::current_pid();

    match request {
        PTRACE_TRACEME => {
            let ppid = crate::proc::scheduler::current_ppid();
            crate::proc::scheduler::with_proc_mut(caller, |p, _| {
                p.ptrace_state = PtraceState::Tracee {
                    tracer: ppid,
                    options: 0,
                    in_syscall_stop: false,
                };
            })
            .unwrap_or(());
            0
        },

        PTRACE_ATTACH => {
            if let Err(e) = ptrace_check_permission(caller, pid) {
                return e;
            }
            crate::proc::scheduler::with_proc_mut(pid as usize, |p, _| {
                p.ptrace_state = PtraceState::Tracee {
                    tracer: caller,
                    options: 0,
                    in_syscall_stop: false,
                };
            })
            .unwrap_or(());
            crate::proc::signal::send_signal(pid as usize, SIGSTOP);
            0
        },

        PTRACE_DETACH => {
            let target = pid as usize;
            crate::proc::scheduler::with_proc_mut(target, |p, _| {
                p.ptrace_state = PtraceState::None;
            })
            .unwrap_or(());
            if data != 0 {
                crate::proc::signal::send_signal(target, data as i32);
            }
            crate::proc::scheduler::wake(target);
            0
        },

        PTRACE_CONT | PTRACE_SYSCALL => {
            let target = pid as usize;
            crate::proc::scheduler::with_proc_mut(target, |p, _| {
                let (tracer, options) = match p.ptrace_state {
                    PtraceState::Stopped {
                        tracer, options, ..
                    } => (tracer, options),
                    PtraceState::Tracee {
                        tracer, options, ..
                    } => (tracer, options),
                    PtraceState::None => return,
                };
                let in_syscall = request == PTRACE_SYSCALL;
                p.ptrace_state = PtraceState::Tracee {
                    tracer,
                    options,
                    in_syscall_stop: in_syscall,
                };
                #[cfg(target_arch = "x86_64")]
                if let Some(kstack) = p.kstack_top {
                    let f = unsafe {
                        core::slice::from_raw_parts_mut((kstack - FRAME_SZ) as *mut usize, 17)
                    };
                    f[14] &= !(1usize << 8);
                }
            })
            .unwrap_or(());
            if data != 0 {
                crate::proc::signal::send_signal(pid as usize, data as i32);
            }
            crate::proc::scheduler::wake(pid as usize);
            0
        },

        PTRACE_SINGLESTEP => {
            let target = pid as usize;
            crate::proc::scheduler::with_proc_mut(target, |p, _| {
                #[cfg(target_arch = "x86_64")]
                if let Some(kstack) = p.kstack_top {
                    let f = unsafe {
                        core::slice::from_raw_parts_mut((kstack - FRAME_SZ) as *mut usize, 17)
                    };
                    f[14] |= 1usize << 8;
                }
                let (tracer, options) = match p.ptrace_state {
                    PtraceState::Stopped {
                        tracer, options, ..
                    } => (tracer, options),
                    PtraceState::Tracee {
                        tracer, options, ..
                    } => (tracer, options),
                    PtraceState::None => return,
                };
                p.ptrace_state = PtraceState::Tracee {
                    tracer,
                    options,
                    in_syscall_stop: false,
                };
            })
            .unwrap_or(());
            if data != 0 {
                crate::proc::signal::send_signal(pid as usize, data as i32);
            }
            crate::proc::scheduler::wake(pid as usize);
            0
        },

        PTRACE_KILL => {
            crate::proc::signal::send_signal(pid as usize, SIGKILL);
            0
        },

        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            if let Err(e) = ptrace_validate_word_addr(addr) {
                return e;
            }
            let phys = match ptrace_resolve_remote_pa(pid, addr) {
                Ok(pa) => pa,
                Err(e) => return e,
            };
            let word: usize = unsafe { core::ptr::read(phys as *const usize) };
            if data != 0 {
                if copy_to_user(data, &word.to_le_bytes()).is_err() {
                    return efault();
                }
            }
            word as isize
        },

        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            if let Err(e) = ptrace_validate_word_addr(addr) {
                return e;
            }
            let phys = match ptrace_resolve_remote_pa(pid, addr) {
                Ok(pa) => pa,
                Err(e) => return e,
            };
            unsafe { core::ptr::write(phys as *mut usize, data) };
            0
        },

        PTRACE_PEEKUSER => {
            let slot = match ptrace_validate_ureg_slot(addr, USER_REGS_BYTES) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let val = crate::proc::scheduler::with_proc(pid as usize, |p| {
                p.kstack_top
                    .map(|ks| {
                        let regs = build_user_regs_pub(ks, p.fs_base);
                        if slot < UREG_COUNT {
                            regs[slot]
                        } else {
                            0
                        }
                    })
                    .unwrap_or(0)
            })
            .unwrap_or(0);
            if data != 0 {
                if copy_to_user(data, &val.to_le_bytes()).is_err() {
                    return efault();
                }
            }
            val as isize
        },

        PTRACE_POKEUSER => {
            let slot = match ptrace_validate_ureg_slot(addr, USER_REGS_BYTES) {
                Ok(s) => s,
                Err(e) => return e,
            };
            crate::proc::scheduler::with_proc_mut(pid as usize, |p, _| {
                if let Some(ks) = p.kstack_top {
                    let mut regs = build_user_regs_pub(ks, p.fs_base);
                    if slot < UREG_COUNT {
                        regs[slot] = data as u64;
                        apply_user_regs_pub(ks, &regs);
                    }
                }
            })
            .unwrap_or(());
            0
        },

        PTRACE_GETREGS => {
            let regs_opt = crate::proc::scheduler::with_proc(pid as usize, |p| {
                p.kstack_top.map(|ks| build_user_regs_pub(ks, p.fs_base))
            });
            match regs_opt {
                Some(Some(regs)) => match ptrace_copy_regs_to_user::<UREG_COUNT>(data, &regs) {
                    Ok(()) => 0,
                    Err(e) => e,
                },
                _ => esrch(),
            }
        },

        PTRACE_SETREGS => {
            let regs = match ptrace_copy_regs_from_user::<UREG_COUNT>(data) {
                Ok(r) => r,
                Err(e) => return e,
            };
            crate::proc::scheduler::with_proc_mut(pid as usize, |p, _| {
                if let Some(ks) = p.kstack_top {
                    apply_user_regs_pub(ks, &regs);
                }
            })
            .unwrap_or(());
            0
        },

        PTRACE_SETOPTIONS => {
            let opts = (data as u64) & PTRACE_O_MASK;
            crate::proc::scheduler::with_proc_mut(pid as usize, |p, _| {
                if let PtraceState::Tracee {
                    ref mut options, ..
                } = p.ptrace_state
                {
                    *options = opts;
                }
            })
            .unwrap_or(());
            0
        },

        PTRACE_GETEVENTMSG => {
            let msg = crate::proc::scheduler::with_proc(pid as usize, |p| p.ptrace_event_msg)
                .unwrap_or(0);
            if copy_to_user(data, &msg.to_le_bytes()).is_err() {
                return efault();
            }
            0
        },

        PTRACE_GETSIGINFO => {
            let si = crate::proc::signal::get_pending_siginfo(pid as usize);
            if copy_to_user(data, &si).is_err() {
                return efault();
            }
            0
        },

        _ => einval(),
    }
}
