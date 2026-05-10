//! Process / thread exit path.
//!
//! do_exit(pid, code) is the single canonical exit function.
//! sys_exit  [NR 60]  calls do_exit for the current thread.
//! sys_exit_group [NR 231] calls do_exit for every thread in the group.
//!
//! Exit sequence:
//!   1. robust_list_on_exit  — wake futex waiters on robust mutexes
//!   2. clear_child_tid      — zero futex word + FUTEX_WAKE (unblocks pthread_join)
//!   3. unregister_thread
//!   4. altstack_clear_pid + proc_name_clear + futex_clear_pid
//!   5. proc_fd_free         — close all open fds
//!   6. free_address_space (last thread in group only)
//!   7. free_kstack + State → Zombie + exit_code = encode_exit(code)
//!   8. wake vfork_parent
//!   9. notify_exit (wakes parent waitpid)
//!  10. schedule()   — never returns

extern crate alloc;

use crate::arch::api::Cpu;
use crate::arch::Arch;
use crate::mm::kstack::free_kstack;
use crate::mm::mmap::free_address_space;
use crate::proc::futex::{futex_wake_addr, robust_list_on_exit};
use crate::proc::process::State;
use crate::proc::{scheduler, thread, wait};
use crate::proc::wait::encode_exit;
use crate::uaccess::copy_to_user;

// ── clear_child_tid ─────────────────────────────────────────────────────────

fn clear_child_tid(pid: usize) {
    let va = scheduler::with_proc_mut(pid, |p| {
        let va = p.clear_child_tid_va;
        p.clear_child_tid_va = 0;
        va
    }).unwrap_or(0);
    if va == 0 { return; }
    let _ = copy_to_user(va, &0u32.to_ne_bytes());
    futex_wake_addr(va, 1);
}

// ── is_last_live_thread ───────────────────────────────────────────────────

fn is_last_live_thread(pid: usize, tgid: usize) -> bool {
    scheduler::with_procs_ro(|procs| {
        !procs.iter().any(|p| {
            p.pid != pid && p.tgid == tgid && p.state != State::Zombie
        })
    })
}

// ── zombify ────────────────────────────────────────────────────────────

fn zombify(pid: usize, code: i32) -> usize {
    let (kstack_top, vfork_parent) = scheduler::with_proc_mut(pid, |p| {
        let ks = p.kstack_top;
        p.kstack_top = 0;
        p.state      = State::Zombie;
        p.exit_code  = encode_exit(code);
        (ks, p.vfork_parent)
    }).unwrap_or((0, 0));

    if kstack_top != 0 { free_kstack(kstack_top); }
    vfork_parent
}

// ── do_exit ────────────────────────────────────────────────────────────

pub fn do_exit(pid: usize, code: i32) {
    let tgid = thread::tgid_of(pid);

    robust_list_on_exit(pid);
    clear_child_tid(pid);
    thread::unregister_thread(pid);

    // Clean up per-pid signal state (PENDING queue, SIGMASK, ALTSTACK).
    crate::proc::signal::altstack_clear_pid(pid);
    crate::syscall::proc_name_clear(pid);
    crate::proc::futex::futex_clear_pid(pid);

    crate::fs::process_fd::proc_fd_free(pid);

    if is_last_live_thread(pid, tgid) {
        let user_satp = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
        free_address_space(pid, user_satp);
    }

    let vfork_parent = zombify(pid, code);
    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }
    wait::notify_exit(pid);
    scheduler::schedule();

    loop { <Arch as Cpu>::halt(); }
}

// ── sys_exit [NR 60] ────────────────────────────────────────────────────────

pub fn sys_exit(status: i32) -> isize {
    do_exit(scheduler::current_pid(), status);
    0
}

// ── sys_exit_group [NR 231] ─────────────────────────────────────────────────

pub fn sys_exit_group(status: i32) -> isize {
    let pid  = scheduler::current_pid();
    let tgid = thread::tgid_of(pid);

    let siblings: alloc::vec::Vec<usize> = scheduler::with_procs_ro(|procs| {
        procs.iter()
            .filter(|p| p.pid != pid && p.tgid == tgid)
            .map(|p| p.pid)
            .collect()
    });

    for sibling in siblings {
        robust_list_on_exit(sibling);
        clear_child_tid(sibling);
        thread::unregister_thread(sibling);
        crate::proc::signal::altstack_clear_pid(sibling);
        crate::syscall::proc_name_clear(sibling);
        crate::proc::futex::futex_clear_pid(sibling);
        crate::fs::process_fd::proc_fd_free(sibling);
        let vfork_parent = zombify(sibling, status);
        if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }
        wait::notify_exit(sibling);
    }

    do_exit(pid, status);
    0
}
