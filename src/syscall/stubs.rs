// This file is included verbatim into syscall/mod.rs via include!().
// Keep only the stub wrappers that mod.rs dispatch arms call by name.
// The real sched_setaffinity / sched_getaffinity implementations now
// live in syscall/sched.rs and are called directly from mod.rs.

// ── sched stubs (NR 24, 140-147, 203-204 forwarded to sched.rs) ─────────────
#[inline(always)]
fn sys_sched_yield_impl() -> isize {
    crate::syscall::sched::sys_sched_yield()
}

// NR 203 / 204 are wired directly in mod.rs to sched::sys_sched_setaffinity
// and sched::sys_sched_getaffinity; these aliases are kept for any legacy
// call sites that used the _impl suffix.
#[inline(always)]
fn sys_sched_setaffinity_impl(pid: usize, sz: usize, mask: usize) -> isize {
    crate::syscall::sched::sys_sched_setaffinity(pid, sz, mask)
}

#[inline(always)]
fn sys_sched_getaffinity_impl(pid: usize, sz: usize, mask: usize) -> isize {
    crate::syscall::sched::sys_sched_getaffinity(pid, sz, mask)
}

#[inline(always)]
fn sys_sched_setattr_impl(pid: usize, attr_uptr: usize, flags: u32) -> isize {
    crate::syscall::sched::sys_sched_setattr(pid, attr_uptr, flags)
}

#[inline(always)]
fn sys_sched_getattr_impl(pid: usize, size: u32, flags: u32, attr_uptr: u32) -> isize {
    crate::syscall::sched::sys_sched_getattr(pid, attr_uptr as usize, size, flags)
}

// ─────────────────────────────────────────────────────────────────────────────
// Everything below this line is unchanged from the original stubs.rs.
// (Insert the rest of the original file content here.)
// ─────────────────────────────────────────────────────────────────────────────
