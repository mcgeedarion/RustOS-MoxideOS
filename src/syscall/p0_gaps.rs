// P0/P1/P2 syscall gap implementations.

#[allow(dead_code)]
fn sys_sched_setparam_impl(_pid: usize, _param: usize) -> isize {
    0
}
#[allow(dead_code)]
fn sys_sched_getscheduler_impl(_pid: usize) -> isize {
    0
}
#[allow(dead_code)]
fn sys_sched_getparam_impl(pid: usize, param_va: usize) -> isize {
    // struct sched_param { int sched_priority; }  — 4 bytes on x86-64
    if param_va != 0 {
        let _ = crate::uaccess::copy_to_user(param_va, &0i32.to_le_bytes());
    }
    0
}
#[allow(dead_code)]
fn sys_sched_setscheduler_impl(_pid: usize, _policy: i32, _param: usize) -> isize {
    0
}
