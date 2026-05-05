//! Process / thread exit path.
//!
//! do_exit(pid, code) is the single canonical exit function.
//! sys_exit  [NR 60]  calls do_exit for the current thread.
//! sys_exit_group [NR 231] calls do_exit for every thread in the group.
//!
//! Exit sequence:
//!   1. clear_child_tid  — zero futex word + FUTEX_WAKE (unblocks pthread_join)
//!   2. unregister_thread
//!   3. altstack_clear_pid + proc_name_clear  (prevent per-pid map leaks)
//!   4. free_address_space (last thread in group only)
//!   5. free_kstack + State → Zombie
//!   6. wake vfork_parent
//!   7. notify_exit (wakes parent waitpid)
//!   8. schedule()   — never returns

extern crate alloc;

use crate::proc::{scheduler, thread, wait};
use crate::proc::futex::futex_wake_addr;
use crate::uaccess::copy_to_user;
use crate::arch::api::Cpu;
use crate::arch::Arch;
use crate::mm::kstack::free_kstack;
use crate::mm::mmap::free_address_space;
use crate::proc::process::State;

// ── clear_child_tid ─────────────────────────────────────────────────────────

fn clear_child_tid(pid: usize) {
    let va = scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            let va = p.clear_child_tid_va;
            p.clear_child_tid_va = 0;
            va
        } else { 0 }
    });
    if va == 0 { return; }
    let _ = copy_to_user(va, &0u32.to_ne_bytes());
    futex_wake_addr(va, 1);
}

// ── is_last_live_thread ────────────────────────────────────────────────────
//
// Returns true if `pid` is the last non-Zombie thread in its thread group.
// When true, the caller is responsible for freeing the address space.

fn is_last_live_thread(pid: usize, tgid: usize) -> bool {
    scheduler::with_procs(|procs| {
        !procs.iter().any(|p| {
            p.pid != pid
                && p.tgid == tgid
                && p.state != State::Zombie
        })
    })
}

// ── zombify ────────────────────────────────────────────────────────────────

fn zombify(pid: usize, code: i32) -> usize {
    let kstack_top = scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.kstack_top)
    });
    if kstack_top != 0 { free_kstack(kstack_top); }

    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.state     = State::Zombie;
            p.exit_code = code;
            p.vfork_parent
        } else { 0 }
    })
}

// ── do_exit ────────────────────────────────────────────────────────────────

pub fn do_exit(pid: usize, code: i32) {
    let tgid = thread::tgid_of(pid);

    clear_child_tid(pid);           // 1
    thread::unregister_thread(pid); // 2

    // 3: Release per-pid entries in syscall-level tables. These are
    //    BTreeMaps in stubs.rs that are never cleaned up otherwise,
    //    leaking one entry per process per exit indefinitely.
    crate::syscall::altstack_clear_pid(pid);
    crate::syscall::proc_name_clear(pid);

    // 4: free the address space only when the last live thread exits.
    // Sibling CLONE_VM threads share user_satp; tearing it down while
    // they are still running would cause instant faults on their next
    // user instruction. We read user_satp before zombify() zeroes it.
    if is_last_live_thread(pid, tgid) {
        let user_satp = scheduler::with_procs(|procs| {
            procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.user_satp)
        });
        free_address_space(pid, user_satp); // unmaps pages + frees PML4
    }

    let vfork_parent = zombify(pid, code); // 5
    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); } // 6
    wait::notify_exit(pid);  // 7
    scheduler::schedule();   // 8 — never returns

    loop { <Arch as Cpu>::halt(); }
}

// ── sys_exit [NR 60] ─────────────────────────────────────────────────────

pub fn sys_exit(status: i32) -> isize {
    do_exit(scheduler::current_pid(), status);
    0
}

// ── sys_exit_group [NR 231] ─────────────────────────────────────────────

pub fn sys_exit_group(status: i32) -> isize {
    let pid  = scheduler::current_pid();
    let tgid = thread::tgid_of(pid);

    // Collect sibling pids in one lock window.
    // Read p.tgid directly — do NOT call thread::tgid_of() here, as that
    // would call with_procs re-entrantly and deadlock.
    let siblings: alloc::vec::Vec<usize> = scheduler::with_procs(|procs| {
        procs.iter()
            .filter(|p| p.pid != pid && p.tgid == tgid)
            .map(|p| p.pid)
            .collect()
    });

    // Terminate siblings (clear_child_tid + zombify; no addr space free
    // yet since the caller's address space is still live).
    for sibling in siblings {
        clear_child_tid(sibling);
        thread::unregister_thread(sibling);
        crate::syscall::altstack_clear_pid(sibling);
        crate::syscall::proc_name_clear(sibling);
        let _ = zombify(sibling, status);
        wait::notify_exit(sibling);
    }

    // do_exit on self: is_last_live_thread will now be true (all siblings
    // are Zombies), so free_address_space fires exactly once.
    do_exit(pid, status);
    0
}
