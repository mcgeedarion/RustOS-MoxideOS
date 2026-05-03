//! Process / thread exit path.
//!
//! do_exit(pid, code) is the single canonical exit function.
//! sys_exit  [NR 60]  calls do_exit for the current thread.
//! sys_exit_group [NR 231] calls do_exit for every thread in the group.
//!
//! Exit sequence:
//!   1. exit_clear_child_tid  — zero futex word, wake pthread_join
//!   2. unregister_thread     — remove from THREAD_GROUP (CLONE_VM threads)
//!   3. free_kstack           — return kernel stack pages to PMM
//!   4. State → Zombie        — allow parent waitpid to collect
//!   5. wake vfork_parent     — unblock CLONE_VFORK parent
//!   6. notify_exit           — wake parent blocked in waitpid
//!   7. schedule()            — yield; this task never runs again

extern crate alloc;

use crate::proc::{scheduler, thread, wait};
use crate::arch::x86_64::syscall::exit_clear_child_tid;
use crate::mm::kstack::free_kstack;
use crate::proc::process::State;

/// Core exit logic for one task.
/// Safe to call from any context; performs all cleanup then yields.
pub fn do_exit(pid: usize, code: i32) {
    // 1. CLONE_CHILD_CLEARTID: zero tid word + futex_wake for pthread_join
    exit_clear_child_tid(pid);

    // 2. Remove from thread group (no-op for process leaders)
    thread::unregister_thread(pid);

    // 3. Free kernel stack; retrieve kstack_top under lock
    let kstack_top = {
        let procs = scheduler::procs_lock();
        let top = procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.kstack_top);
        scheduler::procs_unlock();
        top
    };
    if kstack_top != 0 {
        free_kstack(kstack_top);
    }

    // 4. Mark zombie + set exit code
    let vfork_parent = {
        let procs = scheduler::procs_lock();
        let vfp = if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.state     = State::Zombie;
            p.exit_code = code;
            p.vfork_parent
        } else { 0 };
        scheduler::procs_unlock();
        vfp
    };

    // 5. CLONE_VFORK: unblock parent
    if vfork_parent != 0 {
        scheduler::wake_pid(vfork_parent);
    }

    // 6. Wake parent blocked in waitpid
    wait::notify_exit(pid);

    // 7. Yield — this task will not be selected again (Zombie state)
    scheduler::schedule();

    // If somehow we return (shouldn't happen), halt
    loop { unsafe { core::arch::asm!("hlt", options(nostack)); } }
}

/// sys_exit(status) [NR 60] — exit the calling thread.
pub fn sys_exit(status: i32) -> isize {
    let pid = scheduler::current_pid();
    do_exit(pid, status);
    0 // unreachable
}

/// sys_exit_group(status) [NR 231] — exit all threads in the process group.
///
/// Zombifies every sibling thread in the same tgid, then exits self.
pub fn sys_exit_group(status: i32) -> isize {
    let pid  = scheduler::current_pid();
    let tgid = thread::tgid_of(pid);

    // Collect all pids in the same thread group (excluding self)
    let siblings: alloc::vec::Vec<usize> = {
        let procs = scheduler::procs_lock();
        let v = procs.iter()
            .filter(|p| p.pid != pid && thread::tgid_of(p.pid) == tgid)
            .map(|p| p.pid)
            .collect();
        scheduler::procs_unlock();
        v
    };

    for sibling_pid in siblings {
        let kstack_top = {
            let procs = scheduler::procs_lock();
            let top = procs.iter().find(|p| p.pid == sibling_pid)
                           .map_or(0, |p| p.kstack_top);
            scheduler::procs_unlock();
            top
        };
        exit_clear_child_tid(sibling_pid);
        thread::unregister_thread(sibling_pid);
        if kstack_top != 0 { free_kstack(kstack_top); }
        {
            let procs = scheduler::procs_lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == sibling_pid) {
                p.state     = State::Zombie;
                p.exit_code = status;
            }
            scheduler::procs_unlock();
        }
        wait::notify_exit(sibling_pid);
    }

    // Exit self
    do_exit(pid, status);
    0
}
