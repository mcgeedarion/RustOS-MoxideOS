//! Full POSIX syscall implementations that don't fit cleanly into a single
//! subsystem file.  These are `pub(super)` and called from `mod.rs`.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proc::scheduler;

// ── uid/gid/pid identity ─────────────────────────────────────────────────────

pub(super) fn sys_getpid_impl() -> isize {
    scheduler::current_pid() as isize
}

pub(super) fn sys_getppid_impl() -> isize {
    scheduler::current_ppid() as isize
}

pub(super) fn sys_gettid_impl() -> isize {
    scheduler::current_tid() as isize
}

pub(super) fn sys_getuid_impl()  -> isize { 0 }
pub(super) fn sys_geteuid_impl() -> isize { 0 }
pub(super) fn sys_getgid_impl()  -> isize { 0 }
pub(super) fn sys_getegid_impl() -> isize { 0 }

pub(super) fn sys_getresuid_impl(ruid_va: usize, euid_va: usize, suid_va: usize) -> isize {
    let zero = 0u32;
    let _ = crate::mm::user_copy::copy_to_user(ruid_va, &zero.to_le_bytes());
    let _ = crate::mm::user_copy::copy_to_user(euid_va, &zero.to_le_bytes());
    let _ = crate::mm::user_copy::copy_to_user(suid_va, &zero.to_le_bytes());
    0
}

pub(super) fn sys_getresgid_impl(rgid_va: usize, egid_va: usize, sgid_va: usize) -> isize {
    sys_getresuid_impl(rgid_va, egid_va, sgid_va)
}

pub(super) fn sys_setuid_impl(_uid: u32) -> isize { 0 }
pub(super) fn sys_setgid_impl(_gid: u32) -> isize { 0 }
pub(super) fn sys_setreuid_impl(_ruid: u32, _euid: u32) -> isize { 0 }
pub(super) fn sys_setregid_impl(_rgid: u32, _egid: u32) -> isize { 0 }
pub(super) fn sys_setresuid_impl(_r: u32, _e: u32, _s: u32) -> isize { 0 }
pub(super) fn sys_setresgid_impl(_r: u32, _e: u32, _s: u32) -> isize { 0 }

pub(super) fn sys_getgroups_impl(size: i32, list_va: usize) -> isize {
    if size == 0 { return 0; }
    if size < 0 { return -22; }
    // Single supplementary group: gid 0.
    if size >= 1 {
        let _ = crate::mm::user_copy::copy_to_user(list_va, &0u32.to_le_bytes());
    }
    1
}

pub(super) fn sys_setgroups_impl(_size: i32, _list_va: usize) -> isize { 0 }

// ── process groups / sessions ─────────────────────────────────────────────────

pub(super) fn sys_getpgrp_impl() -> isize {
    scheduler::current_pgrp() as isize
}

pub(super) fn sys_getpgid_impl(pid: i32) -> isize {
    let target = if pid == 0 { scheduler::current_pid() } else { pid as usize };
    scheduler::with_proc(target, |p| p.pgrp as isize).unwrap_or(-3)
}

pub(super) fn sys_setpgid_impl(pid: i32, pgid: i32) -> isize {
    let target = if pid == 0 { scheduler::current_pid() } else { pid as usize };
    let new_pgrp = if pgid == 0 { target as u32 } else { pgid as u32 };
    scheduler::with_proc_mut(target, |p, _| { p.pgrp = new_pgrp; }).unwrap_or(());
    0
}

pub(super) fn sys_getsid_impl(pid: i32) -> isize {
    let target = if pid == 0 { scheduler::current_pid() } else { pid as usize };
    scheduler::with_proc(target, |p| p.sid as isize).unwrap_or(-3)
}

pub(super) fn sys_setsid_impl() -> isize {
    let pid = scheduler::current_pid();
    scheduler::with_proc_mut(pid, |p, _| {
        p.sid  = pid as u32;
        p.pgrp = pid as u32;
    }).unwrap_or(());
    pid as isize
}

// ── resource limits ───────────────────────────────────────────────────────────

pub(super) fn sys_getrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    crate::proc::rlimit::sys_getrlimit(resource, rlim_va)
}

pub(super) fn sys_setrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    crate::proc::rlimit::sys_setrlimit(resource, rlim_va)
}

pub(super) fn sys_prlimit64_impl(
    pid: i32, resource: u32, new_va: usize, old_va: usize,
) -> isize {
    crate::proc::rlimit::sys_prlimit64(pid, resource, new_va, old_va)
}

pub(super) fn sys_getrusage_impl(who: i32, usage_va: usize) -> isize {
    crate::proc::rlimit::sys_getrusage(who, usage_va)
}

// ── uname ─────────────────────────────────────────────────────────────────────

pub(super) fn sys_uname_impl(buf_va: usize) -> isize {
    crate::proc::uname::sys_uname(buf_va)
}

// ── sysinfo ───────────────────────────────────────────────────────────────────

pub(super) fn sys_sysinfo_impl(info_va: usize) -> isize {
    crate::proc::sysinfo::sys_sysinfo(info_va)
}

// ── times ─────────────────────────────────────────────────────────────────────

pub(super) fn sys_times_impl(buf_va: usize) -> isize {
    crate::proc::times::sys_times(buf_va)
}

// ── personality ───────────────────────────────────────────────────────────────

pub(super) fn sys_personality_impl(persona: u32) -> isize {
    if persona == 0xffff_ffff { return 0; } // query — return current (PER_LINUX)
    if persona != 0 { return -22; }          // only PER_LINUX (0) accepted
    0
}

// ── prctl ─────────────────────────────────────────────────────────────────────

pub(super) fn sys_prctl_impl(opt: i32, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    crate::proc::prctl::sys_prctl(opt, a2, a3, a4, a5)
}

// ── arch_prctl ────────────────────────────────────────────────────────────────

pub(super) fn sys_arch_prctl_impl(code: i32, addr: usize) -> isize {
    crate::arch::x86_64::prctl::sys_arch_prctl(code, addr)
}

// ── set_tid_address ───────────────────────────────────────────────────────────

pub(super) fn sys_set_tid_address_impl(tidptr_va: usize) -> isize {
    let pid = scheduler::current_pid();
    scheduler::with_proc_mut(pid, |p, _| {
        p.clear_child_tid = tidptr_va;
    }).unwrap_or(());
    pid as isize
}

// ── set_robust_list / get_robust_list ─────────────────────────────────────────

pub(super) fn sys_set_robust_list_impl(head_va: usize, len: usize) -> isize {
    if len != 24 { return -22; } // sizeof(struct robust_list_head) on x86-64
    let pid = scheduler::current_pid();
    scheduler::with_proc_mut(pid, |p, _| {
        p.robust_list_head = head_va;
    }).unwrap_or(());
    0
}

pub(super) fn sys_get_robust_list_impl(tid: i32, head_pp_va: usize, len_va: usize) -> isize {
    let target = if tid == 0 { scheduler::current_pid() } else { tid as usize };
    let head = scheduler::with_proc(target, |p| p.robust_list_head).unwrap_or(0);
    let len: usize = 24;
    let _ = crate::mm::user_copy::copy_to_user(head_pp_va, &head.to_le_bytes());
    let _ = crate::mm::user_copy::copy_to_user(len_va,     &len.to_le_bytes());
    0
}

// ── futex ─────────────────────────────────────────────────────────────────────

pub(super) fn sys_futex_impl(
    uaddr: usize, op: i32, val: u32, timeout_va: usize, uaddr2: usize, val3: u32,
) -> isize {
    crate::proc::futex::sys_futex(uaddr, op, val, timeout_va, uaddr2, val3)
}

// ── clone / clone3 / fork / vfork ────────────────────────────────────────────

pub(super) fn sys_fork_impl() -> isize {
    crate::proc::fork_syscall::sys_fork()
}

pub(super) fn sys_vfork_impl() -> isize {
    crate::proc::fork_syscall::sys_vfork()
}

pub(super) fn sys_clone_impl(
    flags: usize, stack: usize, ptid_va: usize, ctid_va: usize, tls: usize,
) -> isize {
    crate::proc::fork_syscall::sys_clone(flags, stack, ptid_va, ctid_va, tls)
}

pub(super) fn sys_clone3_impl(args_va: usize, size: usize) -> isize {
    crate::proc::fork_syscall::sys_clone3(args_va, size)
}

// ── execve / execveat ─────────────────────────────────────────────────────────

pub(super) fn sys_execve_impl(path_va: usize, argv_va: usize, envp_va: usize) -> isize {
    crate::proc::exec::sys_execve(path_va, argv_va, envp_va)
}

pub(super) fn sys_execveat_impl(
    dirfd: i32, path_va: usize, argv_va: usize, envp_va: usize, flags: i32,
) -> isize {
    crate::proc::exec::sys_execveat(dirfd, path_va, argv_va, envp_va, flags)
}

// ── wait4 / waitpid / waitid ──────────────────────────────────────────────────

pub(super) fn sys_wait4_impl(
    pid: i32, wstatus_va: usize, options: i32, rusage_va: usize,
) -> isize {
    crate::proc::wait::sys_wait4(pid, wstatus_va, options, rusage_va)
}

pub(super) fn sys_waitid_impl(
    idtype: i32, id: u32, infop_va: usize, options: i32, rusage_va: usize,
) -> isize {
    crate::proc::wait::sys_waitid(idtype, id, infop_va, options, rusage_va)
}

// ── exit / exit_group ─────────────────────────────────────────────────────────

pub(super) fn sys_exit_impl(status: i32) -> isize {
    crate::proc::scheduler::exit_current(status);
    unreachable!()
}

pub(super) fn sys_exit_group_impl(status: i32) -> isize {
    crate::proc::scheduler::exit_group(status);
    unreachable!()
}

// ── kill / tgkill / tkill ─────────────────────────────────────────────────────

pub(super) fn sys_kill_impl(pid: i32, sig: i32) -> isize {
    crate::proc::signal::sys_kill(pid, sig)
}

pub(super) fn sys_tgkill_impl(tgid: i32, tid: i32, sig: i32) -> isize {
    crate::proc::signal::sys_tgkill(tgid, tid, sig)
}

pub(super) fn sys_tkill_impl(tid: i32, sig: i32) -> isize {
    crate::proc::signal::sys_tkill(tid, sig)
}

// ── rt_sigaction / rt_sigprocmask / rt_sigreturn / sigaltstack ───────────────

pub(super) fn sys_rt_sigaction_impl(
    sig: i32, act_va: usize, old_va: usize, sigset_size: usize,
) -> isize {
    crate::proc::signal::sys_rt_sigaction(sig, act_va, old_va, sigset_size)
}

pub(super) fn sys_rt_sigprocmask_impl(
    how: i32, set_va: usize, old_va: usize, sigset_size: usize,
) -> isize {
    crate::proc::signal::sys_rt_sigprocmask(how, set_va, old_va, sigset_size)
}

pub(super) fn sys_rt_sigreturn_impl() -> isize {
    crate::proc::signal::sys_rt_sigreturn()
}

pub(super) fn sys_rt_sigpending_impl(set_va: usize, sigset_size: usize) -> isize {
    crate::proc::signal::sys_rt_sigpending(set_va, sigset_size)
}

pub(super) fn sys_rt_sigsuspend_impl(mask_va: usize, sigset_size: usize) -> isize {
    crate::proc::signal::sys_rt_sigsuspend(mask_va, sigset_size)
}

pub(super) fn sys_rt_sigtimedwait_impl(
    set_va: usize, info_va: usize, ts_va: usize, sigset_size: usize,
) -> isize {
    crate::proc::signal::sys_rt_sigtimedwait(set_va, info_va, ts_va, sigset_size)
}

pub(super) fn sys_sigaltstack_impl(ss_va: usize, old_ss_va: usize) -> isize {
    crate::proc::signal::sys_sigaltstack(ss_va, old_ss_va)
}

// ── sched_* ───────────────────────────────────────────────────────────────────
// Thin wrappers; the real logic lives in syscall/sched.rs.

pub(super) fn sys_sched_yield_impl() -> isize {
    crate::proc::scheduler::yield_current();
    0
}

// ── nanosleep / clock_nanosleep ───────────────────────────────────────────────

pub(super) fn sys_nanosleep_impl(req_va: usize, rem_va: usize) -> isize {
    crate::proc::timer::sys_nanosleep(req_va, rem_va)
}

pub(super) fn sys_clock_nanosleep_impl(
    clkid: i32, flags: i32, req_va: usize, rem_va: usize,
) -> isize {
    crate::proc::timer::sys_clock_nanosleep(clkid, flags, req_va, rem_va)
}

// ── clock_gettime / clock_getres / clock_settime / gettimeofday ──────────────

pub(super) fn sys_clock_gettime_impl(clkid: i32, ts_va: usize) -> isize {
    crate::arch::api::time::sys_clock_gettime(clkid, ts_va)
}

pub(super) fn sys_clock_getres_impl(clkid: i32, ts_va: usize) -> isize {
    crate::arch::api::time::sys_clock_getres(clkid, ts_va)
}

pub(super) fn sys_clock_settime_impl(_clkid: i32, _ts_va: usize) -> isize { -1 } // EPERM

pub(super) fn sys_gettimeofday_impl(tv_va: usize, tz_va: usize) -> isize {
    crate::arch::api::time::sys_gettimeofday(tv_va, tz_va)
}

pub(super) fn sys_settimeofday_impl(_tv_va: usize, _tz_va: usize) -> isize { -1 }

// ── timer_create / timer_settime / timer_gettime / timer_delete ──────────────

pub(super) fn sys_timer_create_impl(
    clkid: i32, sigevent_va: usize, timer_id_va: usize,
) -> isize {
    crate::proc::posix_timer::sys_timer_create(clkid, sigevent_va, timer_id_va)
}

pub(super) fn sys_timer_settime_impl(
    tid: u32, flags: i32, new_va: usize, old_va: usize,
) -> isize {
    crate::proc::posix_timer::sys_timer_settime(tid, flags, new_va, old_va)
}

pub(super) fn sys_timer_gettime_impl(tid: u32, val_va: usize) -> isize {
    crate::proc::posix_timer::sys_timer_gettime(tid, val_va)
}

pub(super) fn sys_timer_getoverrun_impl(tid: u32) -> isize {
    crate::proc::posix_timer::sys_timer_getoverrun(tid)
}

pub(super) fn sys_timer_delete_impl(tid: u32) -> isize {
    crate::proc::posix_timer::sys_timer_delete(tid)
}

// ── timerfd_create / timerfd_settime / timerfd_gettime ───────────────────────

pub(super) fn sys_timerfd_create_impl(clkid: i32, flags: i32) -> isize {
    crate::proc::timerfd::sys_timerfd_create(clkid, flags)
}

pub(super) fn sys_timerfd_settime_impl(
    fd: usize, flags: i32, new_va: usize, old_va: usize,
) -> isize {
    crate::proc::timerfd::sys_timerfd_settime(fd, flags, new_va, old_va)
}

pub(super) fn sys_timerfd_gettime_impl(fd: usize, cur_va: usize) -> isize {
    crate::proc::timerfd::sys_timerfd_gettime(fd, cur_va)
}

// ── alarm ─────────────────────────────────────────────────────────────────────

pub(super) fn sys_alarm_impl(seconds: u32) -> isize {
    crate::proc::timer::sys_alarm(seconds)
}

// ── epoll ─────────────────────────────────────────────────────────────────────

pub(super) fn sys_epoll_create_impl(size: i32) -> isize {
    crate::fs::epoll::sys_epoll_create(size)
}

pub(super) fn sys_epoll_create1_impl(flags: i32) -> isize {
    crate::fs::epoll::sys_epoll_create1(flags)
}

pub(super) fn sys_epoll_ctl_impl(
    epfd: usize, op: i32, fd: usize, event_va: usize,
) -> isize {
    crate::fs::epoll::sys_epoll_ctl(epfd, op, fd, event_va)
}

pub(super) fn sys_epoll_wait_impl(
    epfd: usize, events_va: usize, max: i32, timeout_ms: i32,
) -> isize {
    crate::fs::epoll::sys_epoll_wait(epfd, events_va, max, timeout_ms)
}

pub(super) fn sys_epoll_pwait_impl(
    epfd: usize, events_va: usize, max: i32, timeout_ms: i32,
    sigmask_va: usize, sigset_size: usize,
) -> isize {
    crate::fs::epoll::sys_epoll_pwait(epfd, events_va, max, timeout_ms, sigmask_va, sigset_size)
}

// ── eventfd ───────────────────────────────────────────────────────────────────

pub(super) fn sys_eventfd_impl(initval: u32) -> isize {
    crate::fs::eventfd::sys_eventfd(initval)
}

pub(super) fn sys_eventfd2_impl(initval: u32, flags: i32) -> isize {
    crate::fs::eventfd::sys_eventfd2(initval, flags)
}

// ── signalfd ──────────────────────────────────────────────────────────────────

pub(super) fn sys_signalfd_impl(fd: i32, mask_va: usize, sigset_size: usize) -> isize {
    crate::fs::signalfd::sys_signalfd(fd, mask_va, sigset_size)
}

pub(super) fn sys_signalfd4_impl(
    fd: i32, mask_va: usize, sigset_size: usize, flags: i32,
) -> isize {
    crate::fs::signalfd::sys_signalfd4(fd, mask_va, sigset_size, flags)
}

// ── pipe ──────────────────────────────────────────────────────────────────────

pub(super) fn sys_pipe_impl(pipefd_va: usize) -> isize {
    crate::fs::pipe::sys_pipe(pipefd_va)
}

pub(super) fn sys_pipe2_impl(pipefd_va: usize, flags: i32) -> isize {
    crate::fs::pipe::sys_pipe2(pipefd_va, flags)
}

// ── dup / dup2 / dup3 ─────────────────────────────────────────────────────────

pub(super) fn sys_dup_impl(fd: usize) -> isize {
    crate::fs::io_syscalls::sys_dup(fd)
}

pub(super) fn sys_dup2_impl(old: usize, new: usize) -> isize {
    crate::fs::io_syscalls::sys_dup2(old, new)
}

pub(super) fn sys_dup3_impl(old: usize, new: usize, flags: i32) -> isize {
    crate::fs::io_syscalls::sys_dup3(old, new, flags)
}

// ── select / pselect6 / poll / ppoll ─────────────────────────────────────────

pub(super) fn sys_select_impl(
    nfds: i32, rfds_va: usize, wfds_va: usize, efds_va: usize, tv_va: usize,
) -> isize {
    crate::fs::select::sys_select(nfds, rfds_va, wfds_va, efds_va, tv_va)
}

pub(super) fn sys_pselect6_impl(
    nfds: i32, rfds_va: usize, wfds_va: usize, efds_va: usize,
    ts_va: usize, sig_va: usize,
) -> isize {
    crate::fs::select::sys_pselect6(nfds, rfds_va, wfds_va, efds_va, ts_va, sig_va)
}

pub(super) fn sys_poll_impl(fds_va: usize, nfds: usize, timeout_ms: i32) -> isize {
    crate::fs::select::sys_poll(fds_va, nfds, timeout_ms)
}

pub(super) fn sys_ppoll_impl(
    fds_va: usize, nfds: usize, ts_va: usize, sigmask_va: usize, sigset_size: usize,
) -> isize {
    crate::fs::select::sys_ppoll(fds_va, nfds, ts_va, sigmask_va, sigset_size)
}

// ── socket family ─────────────────────────────────────────────────────────────

pub(super) fn sys_socket_impl(domain: i32, ty: i32, proto: i32) -> isize {
    crate::net::socket::sys_socket(domain, ty, proto)
}

pub(super) fn sys_socketpair_impl(
    domain: i32, ty: i32, proto: i32, sv_va: usize,
) -> isize {
    crate::net::socket::sys_socketpair(domain, ty, proto, sv_va)
}

pub(super) fn sys_bind_impl(fd: usize, addr_va: usize, addrlen: u32) -> isize {
    crate::net::socket::sys_bind(fd, addr_va, addrlen)
}

pub(super) fn sys_connect_impl(fd: usize, addr_va: usize, addrlen: u32) -> isize {
    crate::net::socket::sys_connect(fd, addr_va, addrlen)
}

pub(super) fn sys_listen_impl(fd: usize, backlog: i32) -> isize {
    crate::net::socket::sys_listen(fd, backlog)
}

pub(super) fn sys_accept_impl(fd: usize, addr_va: usize, addrlen_va: usize) -> isize {
    crate::net::socket::sys_accept(fd, addr_va, addrlen_va)
}

pub(super) fn sys_accept4_impl(
    fd: usize, addr_va: usize, addrlen_va: usize, flags: i32,
) -> isize {
    crate::net::socket::sys_accept4(fd, addr_va, addrlen_va, flags)
}

pub(super) fn sys_getsockname_impl(fd: usize, addr_va: usize, len_va: usize) -> isize {
    crate::net::socket::sys_getsockname(fd, addr_va, len_va)
}

pub(super) fn sys_getpeername_impl(fd: usize, addr_va: usize, len_va: usize) -> isize {
    crate::net::socket::sys_getpeername(fd, addr_va, len_va)
}

pub(super) fn sys_sendto_impl(
    fd: usize, buf_va: usize, len: usize, flags: i32,
    addr_va: usize, addrlen: u32,
) -> isize {
    crate::net::socket::sys_sendto(fd, buf_va, len, flags, addr_va, addrlen)
}

pub(super) fn sys_recvfrom_impl(
    fd: usize, buf_va: usize, len: usize, flags: i32,
    addr_va: usize, addrlen_va: usize,
) -> isize {
    crate::net::socket::sys_recvfrom(fd, buf_va, len, flags, addr_va, addrlen_va)
}

pub(super) fn sys_sendmsg_impl(fd: usize, msg_va: usize, flags: i32) -> isize {
    crate::net::socket::sys_sendmsg(fd, msg_va, flags)
}

pub(super) fn sys_recvmsg_impl(fd: usize, msg_va: usize, flags: i32) -> isize {
    crate::net::socket::sys_recvmsg(fd, msg_va, flags)
}

pub(super) fn sys_sendmmsg_impl(
    fd: usize, mmsg_va: usize, vlen: u32, flags: i32,
) -> isize {
    crate::net::socket::sys_sendmmsg(fd, mmsg_va, vlen, flags)
}

pub(super) fn sys_recvmmsg_impl(
    fd: usize, mmsg_va: usize, vlen: u32, flags: i32, timeout_va: usize,
) -> isize {
    crate::net::socket::sys_recvmmsg(fd, mmsg_va, vlen, flags, timeout_va)
}

pub(super) fn sys_shutdown_impl(fd: usize, how: i32) -> isize {
    crate::net::socket::sys_shutdown(fd, how)
}

pub(super) fn sys_setsockopt_impl(
    fd: usize, level: i32, opt: i32, val_va: usize, optlen: u32,
) -> isize {
    crate::net::socket::sys_setsockopt(fd, level, opt, val_va, optlen)
}

pub(super) fn sys_getsockopt_impl(
    fd: usize, level: i32, opt: i32, val_va: usize, len_va: usize,
) -> isize {
    crate::net::socket::sys_getsockopt(fd, level, opt, val_va, len_va)
}

// ── mq_* ──────────────────────────────────────────────────────────────────────

pub(super) fn sys_mq_open_impl(
    name_va: usize, flags: i32, mode: u32, attr_va: usize,
) -> isize {
    crate::proc::mqueue::sys_mq_open(name_va, flags, mode, attr_va)
}

pub(super) fn sys_mq_unlink_impl(name_va: usize) -> isize {
    crate::proc::mqueue::sys_mq_unlink(name_va)
}

pub(super) fn sys_mq_send_impl(
    mqd: usize, msg_va: usize, msg_len: usize, prio: u32,
) -> isize {
    crate::proc::mqueue::sys_mq_send(mqd, msg_va, msg_len, prio)
}

pub(super) fn sys_mq_receive_impl(
    mqd: usize, msg_va: usize, msg_len: usize, prio_va: usize,
) -> isize {
    crate::proc::mqueue::sys_mq_receive(mqd, msg_va, msg_len, prio_va)
}

pub(super) fn sys_mq_timedsend_impl(
    mqd: usize, msg_va: usize, msg_len: usize, prio: u32, abs_timeout_va: usize,
) -> isize {
    crate::proc::mqueue::sys_mq_timedsend(mqd, msg_va, msg_len, prio, abs_timeout_va)
}

pub(super) fn sys_mq_timedreceive_impl(
    mqd: usize, msg_va: usize, msg_len: usize, prio_va: usize, abs_timeout_va: usize,
) -> isize {
    crate::proc::mqueue::sys_mq_timedreceive(mqd, msg_va, msg_len, prio_va, abs_timeout_va)
}

pub(super) fn sys_mq_notify_impl(mqd: usize, sigevent_va: usize) -> isize {
    crate::proc::mqueue::sys_mq_notify(mqd, sigevent_va)
}

pub(super) fn sys_mq_getsetattr_impl(
    mqd: usize, new_va: usize, old_va: usize,
) -> isize {
    crate::proc::mqueue::sys_mq_getsetattr(mqd, new_va, old_va)
}

// ── semaphore / shared memory / message queue (SysV) ─────────────────────────

pub(super) fn sys_semget_impl(key: i32, nsems: i32, flags: i32) -> isize {
    crate::proc::ipc::sys_semget(key, nsems, flags)
}
pub(super) fn sys_semop_impl(semid: i32, sops_va: usize, nsops: usize) -> isize {
    crate::proc::ipc::sys_semop(semid, sops_va, nsops)
}
pub(super) fn sys_semctl_impl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> isize {
    crate::proc::ipc::sys_semctl(semid, semnum, cmd, arg)
}
pub(super) fn sys_shmget_impl(key: i32, size: usize, flags: i32) -> isize {
    crate::proc::ipc::sys_shmget(key, size, flags)
}
pub(super) fn sys_shmat_impl(shmid: i32, shmaddr: usize, shmflg: i32) -> isize {
    crate::proc::ipc::sys_shmat(shmid, shmaddr, shmflg)
}
pub(super) fn sys_shmdt_impl(shmaddr: usize) -> isize {
    crate::proc::ipc::sys_shmdt(shmaddr)
}
pub(super) fn sys_shmctl_impl(shmid: i32, cmd: i32, buf_va: usize) -> isize {
    crate::proc::ipc::sys_shmctl(shmid, cmd, buf_va)
}
pub(super) fn sys_msgget_impl(key: i32, flags: i32) -> isize {
    crate::proc::ipc::sys_msgget(key, flags)
}
pub(super) fn sys_msgsnd_impl(msqid: i32, msgp_va: usize, msgsz: usize, flags: i32) -> isize {
    crate::proc::ipc::sys_msgsnd(msqid, msgp_va, msgsz, flags)
}
pub(super) fn sys_msgrcv_impl(
    msqid: i32, msgp_va: usize, msgsz: usize, msgtyp: i64, flags: i32,
) -> isize {
    crate::proc::ipc::sys_msgrcv(msqid, msgp_va, msgsz, msgtyp, flags)
}
pub(super) fn sys_msgctl_impl(msqid: i32, cmd: i32, buf_va: usize) -> isize {
    crate::proc::ipc::sys_msgctl(msqid, cmd, buf_va)
}

// ── process_vm_readv / process_vm_writev ─────────────────────────────────────

pub(super) fn sys_process_vm_readv_impl(
    pid: i32, lvec_va: usize, liovcnt: usize,
    rvec_va: usize, riovcnt: usize, _flags: usize,
) -> isize {
    crate::proc::vm_rw::sys_process_vm_readv(pid, lvec_va, liovcnt, rvec_va, riovcnt)
}

pub(super) fn sys_process_vm_writev_impl(
    pid: i32, lvec_va: usize, liovcnt: usize,
    rvec_va: usize, riovcnt: usize, _flags: usize,
) -> isize {
    crate::proc::vm_rw::sys_process_vm_writev(pid, lvec_va, liovcnt, rvec_va, riovcnt)
}

// ── misc privileged / hardware ────────────────────────────────────────────────

/// NR 172  iopl / NR 173 ioperm — deny.
pub(super) fn sys_iopl_impl(_level: i32) -> isize { -1 }
pub(super) fn sys_ioperm_impl(_from: usize, _num: usize, _turn_on: i32) -> isize { -1 }

/// NR 175  init_module — RustOS has no loadable kernel module subsystem.
/// ENOSYS (not EPERM) so that modprobe / insmod fail with "Function not
/// implemented" rather than "Operation not permitted", which is more accurate
/// and easier to diagnose in build/test environments.
pub(super) fn sys_init_module_impl(_mod: usize, _len: usize, _opts: usize) -> isize { -38 }

/// NR 176  delete_module — same rationale as init_module above.
pub(super) fn sys_delete_module_impl(_name: usize, _flags: u32) -> isize { -38 }

// ─── fallocate ───────────────────────────────────────────────────────────────

/// NR 285  fallocate(fd, mode, offset, len)
pub(super) fn sys_fallocate_impl(fd: usize, _mode: i32, offset: i64, len: i64) -> isize {
    if offset < 0 || len <= 0 { return -22; }
    let new_size = (offset + len) as u64;
    crate::fs::vfs::truncate(fd, new_size);
    0
}

// ─── copy_file_range ─────────────────────────────────────────────────────────

/// NR 326  copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
pub(super) fn sys_copy_file_range_impl(
    fd_in: usize, off_in_va: usize,
    fd_out: usize, off_out_va: usize,
    len: usize, _flags: u32,
) -> isize {
    crate::fs::io_syscalls::sys_copy_file_range(fd_in, off_in_va, fd_out, off_out_va, len)
}

// ─── memfd_create ────────────────────────────────────────────────────────────

/// NR 319  memfd_create(name_va, flags)
pub(super) fn sys_memfd_create_impl(name_va: usize, flags: u32) -> isize {
    crate::fs::memfd::sys_memfd_create(name_va, flags)
}

// ─── getrandom ───────────────────────────────────────────────────────────────

/// NR 318  getrandom(buf_va, buflen, flags)
pub(super) fn sys_getrandom_impl(buf_va: usize, buflen: usize, _flags: u32) -> isize {
    crate::arch::api::rng::sys_getrandom(buf_va, buflen)
}

// ─── seccomp ─────────────────────────────────────────────────────────────────

/// NR 317  seccomp(op, flags, args_va) — not implemented; return ENOSYS so
/// callers (Go, sandboxed runtimes) can detect absence and skip seccomp setup.
pub(super) fn sys_seccomp_impl(_op: u32, _flags: u32, _args_va: usize) -> isize { -38 }

// ─── kcmp ────────────────────────────────────────────────────────────────────

/// NR 312  kcmp — not applicable; return ENOSYS.
pub(super) fn sys_kcmp_impl() -> isize { -38 }

// ─── pkey_* ──────────────────────────────────────────────────────────────────

pub(super) fn sys_pkey_mprotect_impl(
    addr: usize, len: usize, prot: i32, pkey: i32,
) -> isize {
    if pkey == -1 || pkey == 0 {
        crate::mm::mmap::sys_mprotect(addr, len, prot)
    } else {
        -38 // ENOSYS — MPK not supported
    }
}

pub(super) fn sys_pkey_alloc_impl(_flags: u32, _access_rights: u32) -> isize { -38 }
pub(super) fn sys_pkey_free_impl(_pkey: i32) -> isize { -38 }

// ─── io_uring ────────────────────────────────────────────────────────────────

pub(super) fn sys_io_uring_setup_impl(entries: u32, params_va: usize) -> isize {
    crate::io_uring::syscall::sys_io_uring_setup(entries, params_va)
}

pub(super) fn sys_io_uring_enter_impl(
    fd: usize, to_submit: u32, min_complete: u32, flags: u32,
    sig_va: usize, sigset_size: usize,
) -> isize {
    crate::io_uring::syscall::sys_io_uring_enter(
        fd, to_submit, min_complete, flags, sig_va, sigset_size)
}

pub(super) fn sys_io_uring_register_impl(
    fd: usize, opcode: u32, arg_va: usize, nr_args: u32,
) -> isize {
    crate::io_uring::syscall::sys_io_uring_register(fd, opcode, arg_va, nr_args)
}

// ─── landlock ────────────────────────────────────────────────────────────────

pub(super) fn sys_landlock_create_ruleset_impl() -> isize { -38 }
pub(super) fn sys_landlock_add_rule_impl()       -> isize { -38 }
pub(super) fn sys_landlock_restrict_self_impl()  -> isize { -38 }
