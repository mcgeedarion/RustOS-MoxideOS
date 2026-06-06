//! Path utilities — thin re-export layer.
//!
//! Current callers (`syscall::stubs`) just need `resolve_path(&str) -> String`,
//! which already exists in `crate::fs::stat_syscalls`. Re-export so the
//! `crate::fs::path::resolve_path` import path resolves cleanly.

pub use crate::fs::stat_syscalls::resolve_path;
