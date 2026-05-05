//! Process / thread exit path.
//!
//! do_exit(pid, code) is the single canonical exit function.
//! sys_exit  [NR 60]  calls do_exit for the current thread.
//! sys_exit_group [NR 231] calls do_exit for every thread in the group.
//!
//! Exit sequence:
//!   1. clear_child_tid  — zero futex word + FUTEX_WAKE (unblocks pthread_join)
//!   2. unregister_thread
//!   3. free_kstack + State → Zombie
//!   4. wake vfork_parent
//!   5. notify_exit (wakes parent waitpid)
//!   6. schedule()   — never returns

extern crate alloc;

use crate::proc::{scheduler, thread, wait};
use crate::proc::futex::futex_wake_addr;
use crate::uaccess::copy_to_user;
use crate::arch::api::Cpu;
use crate::arch::Arch;
use crate::mm::kstack::free_kstack;
use crate::proc::process::State;

// ── clear_child_tid ───────────────────────────────────────────────────
//
// Implements the CLONE_CHILD_CLEARTID / set_tid_address contract:
//   - Zero the tid word in user memory at clear_child_tid_va.
//   - Call futex_wake(va, 1) so any pthread_join waiter unblocks.
//
// Called at the very start of do_exit, before the PCB is zombified,
// so the user address space is still live.

fn clear_child_tid(pid: usize) {
    // Read (and consume) the VA under the scheduler lock.
    let va = scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            let va = p.clear_child_tid_va;
            p.clear_child_tid_va = 0; // consume: only fire once
            va
        } else { 0 }
    });

    if va == 0 { return; }

    // Zero the tid word.  copy_to_user validates the address.
    let _ = copy_to_user(va, &0u32.to_ne_bytes());

    // Wake any pthread_join waiting on this futex address.
    futex_wake_addr(va, 1);
}

// ── zombify ────────────────────────────────────────────────────────────

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

// ── do_exit ─────────────────────────────────────────────────────────────

pub fn do_exit(pid: usize, code: i32) {
    clear_child_tid(pid);           // 1 — zero tid word + FUTEX_WAKE
    thread::unregister_thread(pid); // 2
    let vfork_parent = zombify(pid, code); // 3
    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); } // 4
    wait::notify_exit(pid);  // 5
    scheduler::schedule();   // 6 — never returns

    loop { <Arch as Cpu>::halt(); }
}

// ── sys_exit [NR 60] ──────────────────────────────────────────────────

pub fn sys_exit(status: i32) -> isize {
    do_exit(scheduler::current_pid(), status);
    0
}

// ── sys_exit_group [NR 231] ────────────────────────────────────────────

pub fn sys_exit_group(status: i32) -> isize {
    let pid  = scheduler::current_pid();
    let tgid = thread::tgid_of(pid);

    let siblings: alloc::vec::Vec<usize> = scheduler::with_procs(|procs| {
        procs.iter()
            .filter(|p| p.pid != pid && thread::tgid_of(p.pid) == tgid)
            .map(|p| p.pid)
            .collect()
    });

    for sibling in siblings {
        clear_child_tid(sibling);
        thread::unregister_thread(sibling);
        let _ = zombify(sibling, status);
        wait::notify_exit(sibling);
    }

    do_exit(pid, status);
    0
}
