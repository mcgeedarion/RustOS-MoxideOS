// P0/P1/P2 syscall gap implementations.
//
// These scheduler interfaces are recognized but not implemented.  Return
// ENOTSUP instead of a fake success so userspace can detect the missing kernel
// behavior and fall back or fail explicitly.

use crate::syscall::errno::enotsup;

#[allow(dead_code)]
fn sys_sched_setparam_impl(_pid: usize, _param: usize) -> isize {
    enotsup()
}

#[allow(dead_code)]
fn sys_sched_getscheduler_impl(_pid: usize) -> isize {
    enotsup()
}

#[allow(dead_code)]
fn sys_sched_getparam_impl(_pid: usize, _param_va: usize) -> isize {
    enotsup()
}

#[allow(dead_code)]
fn sys_sched_setscheduler_impl(_pid: usize, _policy: i32, _param: usize) -> isize {
    enotsup()
}
