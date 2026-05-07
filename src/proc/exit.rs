//! Process / thread exit path.
//!
//! do_exit(pid, code) is the single canonical exit function.
//! sys_exit  [NR 60]  calls do_exit for the current thread.
//! sys_exit_group [NR 231] calls do_exit for every thread in the group.
//!
//! Exit sequence:
//!   1. clear_child_tid  — zero futex word + FUTEX_WAKE (unblocks pthread_join)
//!   2. unregister_thread
//!   3. altstack_clear_pid + proc_name_clear + futex_clear_pid  (prevent leaks)
//!   4. free_address_space (last thread in group only)
//!   5. free_kstack + State → Zombie
//!   6. wake vfork_parent
//!   7. notify_exit (wakes parent waitpid)
//!   8. schedule()   — never returns

extern crate alloc;

use crate::arch::api::Cpu;
use crate::arch::Arch;
use crate::mm::kstack::free_kstack;
use crate::mm::mmap::free_address_space;
use crate::proc::futex::futex_wake_addr;
use crate::proc::process::State;
use crate::proc::{scheduler, thread, wait};
use crate::uaccess::copy_to_user;

// ── clear_child_tid ────────────────────────────────────────────────────────────────────────────

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

// ── is_last_live_thread ─────────────────────────────────────────────────────────────────────

fn is_last_live_thread(pid: usize, tgid: usize) -> bool {
    // Read-only scan: use with_procs_ro to avoid exposing &mut unnecessarily.
    scheduler::with_procs_ro(|procs| {
        !procs.iter().any(|p| {
            p.pid != pid && p.tgid == tgid && p.state != State::Zombie
        })
    })
}

// ── zombify ───────────────────────────────────────────────────────────────────────────────

fn zombify(pid: usize, code: i32) -> usize {
    let (kstack_top, vfork_parent) = scheduler::with_proc_mut(pid, |p| {
        let ks = p.kstack_top;
        p.kstack_top = 0;
        p.state      = State::Zombie;
        p.exit_code  = code;
        (ks, p.vfork_parent)
    }).unwrap_or((0, 0));

    if kstack_top != 0 { free_kstack(kstack_top); }
    vfork_parent
}

// ── do_exit ────────────────────────────────────────────────────────────────────────────────

pub fn do_exit(pid: usize, code: i32) {
    let tgid = thread::tgid_of(pid);

    clear_child_tid(pid);           // 1
    thread::unregister_thread(pid); // 2

    crate::syscall::altstack_clear_pid(pid);
    crate::syscall::proc_name_clear(pid);
    crate::sync::futex::futex_clear_pid(pid);

    if is_last_live_thread(pid, tgid) {
        let user_satp = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
        free_address_space(pid, user_satp);
    }

    let vfork_parent = zombify(pid, code); // 5
    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); } // 6
    wait::notify_exit(pid);  // 7
    scheduler::schedule();   // 8 — never returns

    loop { <Arch as Cpu>::halt(); }
}

// ── sys_exit [NR 60] ───────────────────────────────────────────────────────────────────────────────

pub fn sys_exit(status: i32) -> isize {
    do_exit(scheduler::current_pid(), status);
    0
}

// ── sys_exit_group [NR 231] ────────────────────────────────────────────────────────────────────────────

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
        clear_child_tid(sibling);
        thread::unregister_thread(sibling);
        crate::syscall::altstack_clear_pid(sibling);
        crate::syscall::proc_name_clear(sibling);
        crate::sync::futex::futex_clear_pid(sibling);
        // Wake the sibling's vfork parent if it is waiting.
        let vfork_parent = zombify(sibling, status);
        if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); }
        // Do NOT call notify_exit per-sibling — that would send one SIGCHLD
        // per thread to the parent, causing spurious wakeups and extra waitpid
        // calls. We send a single SIGCHLD below after all siblings are done.
    }

    // One SIGCHLD to the parent after all sibling threads are zombified.
    // notify_exit on the calling thread (do_exit below) will send the real one.
    {
        let (ppid, exit_signal) = scheduler::with_proc(
            scheduler::current_pid(), |p| (p.ppid, p.exit_signal)
        ).unwrap_or((0, 17));
        if ppid != 0 { scheduler::wake_pid(ppid); }
        let _ = exit_signal; // SIGCHLD sent by do_exit's notify_exit
    }

    do_exit(pid, status);
    0
}
