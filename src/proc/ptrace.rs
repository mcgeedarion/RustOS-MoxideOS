//! ptrace(2) — process tracing and debugging interface.
//!
//! ## Architecture
//! The full ptrace dispatch (sys_ptrace_impl) lives in syscall/stubs.rs and
//! uses the constants, types, and register helpers defined here.  This file
//! is the single source of truth for:
//!   - PTRACE_* / PTRACE_O_* constants  (consumed by signal.rs, wait.rs)
//!   - PtraceState enum                 (field on proc::process::Task)
//!   - build_user_regs_pub / apply_user_regs_pub  (used by proc_debug.rs too)
//!   - ptrace_syscall_stop              (called from signal.rs on syscall entry)
//!   - sys_ptrace wrapper            