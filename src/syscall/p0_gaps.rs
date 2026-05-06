// P0/P1/P2 syscall gap implementations.
//
// Included from mod.rs via `include!("p0_gaps.rs")` so the functions
// share the same namespace as the rest of the syscall dispatcher.
//
// This file contains ONLY the permission/attribute stubs that have no
// implementation elsewhere.  All stat, time, and openat2 functions were
// promoted to mod.rs directly and must NOT be redefined here.

// ── P2 permission / attribute stubs ────────────────────────────────────────

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
