//! P0/P1/P2 syscall gap implementations.
//!
//! Included from mod.rs via `include!("p0_gaps.rs")` so the functions
//! share the same namespace as the rest of the syscall dispatcher.
//!
//! Adds:
//!   sys_newfstatat  — fills full struct stat from VFS stat_path()
//!   sys_stat_impl   — delegates to newfstatat(AT_FDCWD, ..., 0)
//!   sys_lstat_impl  — delegates to newfstatat(AT_FDCWD, ..., AT_SYMLINK_NOFOLLOW)
//!   sys_clock_nanosleep — delegates to sys_nanosleep
//!   P2 permission/attr stubs (chmod, chown, mlock, ptrace, mount, …)

// ── newfstatat ──────────────────────────────────────────────────────────────

pub const SYS_NEWFSTATAT: usize = 262;
pub const SYS_STAT:       usize = 4;
pub const SYS_LSTAT:      usize = 6;
pub const AT_FDCWD:       i32   = -100;

fn sys_newfstatat(dirfd: i32, path_va: usize, stat_va: usize, flags: i32) -> isize {
    if path_va == 0 && dirfd >= 0 {
        return sys_fstat(dirfd as usize, stat_va);
    }
    let mut buf = [0u8; 512];
    let n = match unsafe { crate::uaccess::strncpy_from_user(&mut buf, path_va as *const u8, 512) } {
        Ok(n) => n, Err(_) => return -14,
    };
    let path = match core::str::from_utf8(&buf[..n]) { Ok(s) => s, Err(_) => return -2 };
    let full_path = if path.starts_with('/') {
        alloc::string::String::from(path)
    } else {
        alloc::format!("/{}", path)
    };
    let _is_symlink_nofollow = flags & 0x100 != 0;
    match crate::fs::vfs::stat_path(&full_path) {
        Some((size, is_dir, ino)) => {
            let mode: u32 = if is_dir { 0o40755 } else { 0o100644 };
            fill_stat_buf(stat_va, size, mode, ino)
        }
        None => -2,
    }
}

fn fill_stat_buf(stat_va: usize, size: u64, mode: u32, ino: u64) -> isize {
    if stat_va == 0 { return -14; }
    #[repr(C)]
    struct Stat {
        st_dev: u64, st_ino: u64, st_nlink: u64,
        st_mode: u32, st_uid: u32, st_gid: u32, _pad0: u32,
        st_rdev: u64, st_size: i64, st_blksize: i64, st_blocks: i64,
        st_atim: [u64; 2], st_mtim: [u64; 2], st_ctim: [u64; 2],
        _unused: [i64; 3],
    }
    let s = Stat {
        st_dev: 2, st_ino: ino, st_nlink: 1,
        st_mode: mode, st_uid: 0, st_gid: 0, _pad0: 0,
        st_rdev: 0, st_size: size as i64,
        st_blksize: 4096, st_blocks: (size as i64 + 511) / 512,
        st_atim: [0; 2], st_mtim: [0; 2], st_ctim: [0; 2],
        _unused: [0; 3],
    };
    unsafe { core::ptr::write(stat_va as *mut Stat, s); }
    0
}

fn sys_stat_impl(path_va: usize, stat_va: usize) -> isize {
    sys_newfstatat(AT_FDCWD, path_va, stat_va, 0)
}

fn sys_lstat_impl(path_va: usize, stat_va: usize) -> isize {
    sys_newfstatat(AT_FDCWD, path_va, stat_va, 0x100)
}

// ── clock_nanosleep ────────────────────────────────────────────────────────

pub const SYS_CLOCK_NANOSLEEP: usize = 230;

fn sys_clock_nanosleep(_clockid: i32, _flags: i32, req_va: usize, rem_va: usize) -> isize {
    sys_nanosleep(req_va, rem_va)
}

// ── P2 permission / attribute stubs ────────────────────────────────────────

pub const SYS_CHMOD:             usize = 90;
pub const SYS_FCHMOD:            usize = 91;
pub const SYS_CHOWN:             usize = 92;
pub const SYS_LCHOWN:            usize = 94;
pub const SYS_FCHOWN:            usize = 93;
pub const SYS_UTIMENSAT:         usize = 280;
pub const SYS_MLOCK:             usize = 149;
pub const SYS_MUNLOCK:           usize = 150;
pub const SYS_MLOCKALL:          usize = 151;
pub const SYS_MUNLOCKALL:        usize = 152;
pub const SYS_PTRACE:            usize = 101;
pub const SYS_MOUNT:             usize = 165;
pub const SYS_UMOUNT2:           usize = 166;
pub const SYS_SYSLOG:            usize = 103;
pub const SYS_PROCESS_VM_READV:  usize = 310;
pub const SYS_PROCESS_VM_WRITEV: usize = 311;
pub const SYS_OPENAT2:           usize = 437;

fn sys_mlock_impl(_addr: usize, _len: usize) -> isize { 0 }
fn sys_munlock_impl(_addr: usize, _len: usize) -> isize { 0 }
fn sys_chmod_impl(_path: usize, _mode: u32) -> isize { 0 }
fn sys_fchmod_impl(_fd: usize, _mode: u32) -> isize { 0 }
fn sys_chown_impl(_path: usize, _uid: u32, _gid: u32) -> isize { 0 }
fn sys_lchown_impl(_path: usize, _uid: u32, _gid: u32) -> isize { 0 }
fn sys_fchown_impl(_fd: usize, _uid: u32, _gid: u32) -> isize { 0 }
fn sys_utimensat_impl(_dirfd: i32, _path: usize, _times: usize, _flags: i32) -> isize { 0 }
fn sys_ptrace_impl(_req: i32, _pid: i32, _addr: usize, _data: usize) -> isize { -1 }
fn sys_mount_impl(_src: usize, _tgt: usize, _fs: usize, _fl: u64, _data: usize) -> isize { 0 }
fn sys_syslog_impl(_typ: i32, _buf: usize, _len: i32) -> isize { 0 }
fn sys_openat2_impl(dirfd: i32, path_va: usize, how_va: usize, _size: usize) -> isize {
    let (flags, mode) = if how_va != 0 {
        unsafe { (*(how_va as *const u64), *((how_va + 8) as *const u64)) }
    } else { (0, 0o666) };
    sys_openat(dirfd, path_va, flags as i32, mode as u32)
}
