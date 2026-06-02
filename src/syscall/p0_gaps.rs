// P0/P1/P2 syscall gap implementations.
// Included from mod.rs via `include!("p0_gaps.rs")` so the functions
// share the same namespace as the rest of the syscall dispatcher.
// RULE: do NOT define any function here whose _impl name already exists
// in stubs.rs — include!() merges both files into the same scope and
// rustc will error on the duplicate.  Only add functions here that have
// no counterpart in stubs.rs.

// lchown(2) changes ownership of the symlink itself, not its target.
// We run as root (uid 0) so there is never a permission error from the
// caller's perspective; however pretending the ownership changed silently
// is wrong — callers rely on lchown succeeding to set metadata.  Return
// EPERM (-1) to match sys_chown behaviour: ownership changes are not
// persisted but the caller learns they failed rather than silently no-op.
#[allow(dead_code)]
fn sys_lchown_impl(_path: usize, _uid: u32, _gid: u32) -> isize { -1 }

// These share the same "not enforced" rationale as getpriority/setpriority.
// They are wired in mod.rs implicitly through the _   => -38 fallback,
// but placing them here avoids spurious ENOSYS logs from glibc's
// pthread_attr_setschedpolicy and related calls.
// NR 141 = getpriority   } already dispatched inline in mod.rs as `=> 0`
// NR 142 = setpriority   } (push 5).  Listed here for cross-reference only.
// NR 154 = sched_setparam(pid, param)  → 0 (ignored)
// NR 143 = sched_getscheduler(pid)     → 0 (SCHED_OTHER)
// NR 144 = sched_getparam(pid, param)  → writes sched_priority=0
// NR 145 = sched_setscheduler(pid, policy, param) → 0 (ignored)
#[allow(dead_code)]
fn sys_sched_setparam_impl(_pid: usize, _param: usize) -> isize { 0 }
#[allow(dead_code)]
fn sys_sched_getscheduler_impl(_pid: usize) -> isize { 0 }
#[allow(dead_code)]
fn sys_sched_getparam_impl(pid: usize, param_va: usize) -> isize {
    // struct sched_param { int sched_priority; }  — 4 bytes on x86-64
    if param_va != 0 {
        let _ = crate::uaccess::copy_to_user(param_va, &0i32.to_le_bytes());
    }
    0
}
#[allow(dead_code)]
fn sys_sched_setscheduler_impl(_pid: usize, _policy: i32, _param: usize) -> isize { 0 }
