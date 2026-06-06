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
pub mod cwd;
pub mod exec;
pub mod fork;
pub mod fork_syscall;
pub mod ipc;
pub mod namespace;
pub mod pid;
pub mod proc_table;
pub mod process;
pub mod ptrace;
pub mod rlimit;
pub mod rusage;
pub mod scheduler;
pub mod signal;
pub mod task_types;
pub mod thread;
pub mod time_ns;
pub mod wait;
// GUESS: file missing, no callers anywhere in tree, declaration orphaned.
// pub mod seccomp_filter;

// GUESS: callers use crate::proc::cow_fault; canonical is mm::cow_fault.
pub use crate::mm::cow_fault;
