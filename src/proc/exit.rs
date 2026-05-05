//! Process / thread exit path.
//!
//! do_exit(pid, code) is the single canonical exit function.
//! sys_exit  [NR 60]  calls do_exit for the current thread.
//! sys_exit_group [NR 231] calls do_exit for every thread in the group.
//!
//! Exit sequence:
//!   1. Arch::clear_child_tid  — zero futex word, wake pthread_join
//!   2. unregister_thread      — remove from THREAD_GROUP (CLONE_VM threads)
//!   3. free_kstack             — return kernel stack pages to PMM
//!   4. State → Zombie         — allow parent waitpid to collect
//!   5. wake vfork_parent       — unblock CLONE_VFORK parent
//!   6. notify_exit             — wake parent blocked in waitpid
//!   7. schedule()              — yield; this task never runs again

extern crate alloc;

use crate::proc::{scheduler, thread, wait};
use crate::arch::Arch;
use crate::arch::api::Cpu;
use crate::mm::kstack::free_kstack;
use crate::proc::process::State;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Zombify `pid`: free its kernel stack and set its exit code in one lock window.
/// Returns the vfork_parent pid (0 if none).
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

// ── do_exit ───────────────────────────────────────────────────────────────

/// Core exit logic for one task.
/// Safe to call from any context; performs all cleanup then yields forever.
pub fn do_exit(pid: usize, code: i32) {
    Arch::clear_child_tid(pid); // 1  — zero futex word in user memory
    thread::unregister_thread(pid); // 2
    let vfork_parent = zombify(pid, code); // 3 + 4
    if vfork_parent != 0 { scheduler::wake_pid(vfork_parent); } // 5
    wait::notify_exit(pid); // 6
    scheduler::schedule();  // 7  — never returns

    // Unreachable on every arch, but the type system can't prove it;
    // spin on arch-specific halt so we don't fall off the end of a ! fn.
    loop { <Arch as Cpu>::halt(); }
}

// ── sys_exit ───────────────────────────────────────────────────────────────

/// sys_exit(status) [NR 60] — exit the calling thread.
pub fn sys_exit(status: i32) -> isize {
    do_exit(scheduler::current_pid(), status);
    0 // unreachable
}

// ── sys_exit_group ──────────────────────────────────────────────────────────

/// sys_exit_group(status) [NR 231] — exit all threads in the process group.
pub fn sys_exit_group(status: i32) -> isize {
    let pid  = scheduler::current_pid();
    let tgid = thread::tgid_of(pid);

    // Collect sibling pids (exclude self) in one lock window.
    let siblings: alloc::vec::Vec<usize> = scheduler::with_procs(|procs| {
        procs.iter()
            .filter(|p| p.pid != pid && thread::tgid_of(p.pid) == tgid)
            .map(|p| p.pid)
            .collect()
    });

    for sibling in siblings {
        Arch::clear_child_tid(sibling);
        thread::unregister_thread(sibling);
        let _ = zombify(sibling, status);
        wait::notify_exit(sibling);
    }

    do_exit(pid, status);
    0
}
