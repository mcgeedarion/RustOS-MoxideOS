//! Process-management subsystem.
//!
//! Invariants:
//! - `proc_table` is the authoritative PID/TID index for live tasks.
//! - Scheduler-visible task state transitions go through `scheduler` +
//!   `thread`.
//! - Signal delivery and reaping semantics are centralized in `signal` and
//!   `wait`.
//! - Namespace, credentials, and cgroup membership must remain coherent across
//!   `fork`/`clone`/`exec`.

pub mod cgroup;
pub mod clone;
pub mod context;
pub mod creds;
pub mod cwd;
pub mod dynlink {
    extern crate alloc;
    use alloc::string::String;

    pub fn find_interp(_elf_data: &[u8]) -> Option<String> {
        None
    }

    pub fn load_interp(_interp_path: &str) -> Result<(usize, usize), isize> {
        Err(-38)
    }
}
pub mod exec;
pub mod exit {
    pub fn do_exit(_pid: usize, _code: i32) {}

    pub fn sys_exit(status: i32) -> isize {
        do_exit(crate::proc::scheduler::current_pid(), status);
        0
    }

    pub fn sys_exit_group(status: i32) -> isize {
        sys_exit(status)
    }
}
pub mod fork;
pub mod fork_syscall;
pub mod futex {
    pub fn sys_futex(
        _uaddr: usize,
        _op: u32,
        _val: u32,
        _timeout: usize,
        _uaddr2: usize,
        _val3: u32,
    ) -> isize {
        -38
    }

    pub fn sys_set_robust_list(_head: usize, _len: usize) -> isize {
        0
    }

    pub fn sys_get_robust_list(_tid: usize, _headp: usize, _lenp: usize) -> isize {
        -38
    }
}
pub mod ipc;
pub mod itimer {
    pub fn tick() {}
}
pub mod namespace;
pub mod nanosleep {
    pub fn sys_nanosleep(_req_va: usize, _rem_va: usize) -> isize {
        -38
    }

    pub fn sys_clock_gettime(_clockid: u32, _timespec_va: usize) -> isize {
        -38
    }

    pub fn sleep_ns_internal(_delta_ns: u64) -> isize {
        0
    }
}
pub mod net_ns {
    use crate::proc::namespace::NsId;

    pub fn create_net_ns(_ns_id: NsId) {}
    pub fn destroy_net_ns(_ns_id: NsId) {}
}
pub mod pid;
pub mod proc_table;
pub use proc_table as table;
pub mod process;
pub mod ptrace;
pub mod rlimit;
pub mod rusage;
pub mod scheduler;
pub mod signal;

pub mod session {
    pub fn set_pgid(pid: usize, pgid: usize) -> isize {
        crate::proc::creds::sys_setpgid(pid as u32, pgid as u32)
    }

    pub fn get_pgid(pid: usize) -> isize {
        let target = if pid == 0 {
            crate::proc::scheduler::current_pid()
        } else {
            pid
        };
        crate::proc::scheduler::with_proc(target, |p| p.pgid as isize).unwrap_or(-3)
    }

    pub fn setsid() -> isize {
        crate::proc::creds::sys_setsid()
    }

    pub fn get_sid(pid: usize) -> isize {
        crate::proc::creds::sys_getsid(pid as u32)
    }
}
pub mod task_types;
pub use task_types as task;
pub mod thread;
pub mod time_ns;
pub mod wait;
// GUESS: file missing, no callers anywhere in tree, declaration orphaned.
// pub mod seccomp_filter;

// GUESS: callers use crate::proc::cow_fault; canonical is mm::cow_fault.
pub use crate::mm::cow_fault;
