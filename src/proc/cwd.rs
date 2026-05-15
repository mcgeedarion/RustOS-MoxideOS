//! Per-process current working directory.
//!
//! The cwd is stored as an absolute path string inside `Pcb::cwd`.
//! All accessors go through the process table lock so there are no
//! separate data structures to keep in sync.

extern crate alloc;
use alloc::string::{String, ToString};

/// Return the cwd for `pid`.  Defaults to `"/"` if the process is not found.
pub fn get_cwd(pid: usize) -> String {
    crate::proc::scheduler::with_proc(pid, |p| p.cwd.clone())
        .unwrap_or_else(|| String::from("/"))
}

/// Set the cwd for `pid`.
/// The caller is responsible for validating that `path` is an absolute,
/// canonical path that names an existing directory.
pub fn set_cwd(pid: usize, path: &str) {
    crate::proc::scheduler::with_proc_mut(pid, |p, _pl| {
        p.cwd = path.to_string();
    });
}

/// Normalise a user-supplied path against the current cwd of `pid`.
///
/// Rules
/// - Absolute path → returned as-is (after stripping trailing `/`).
/// - Relative path → prepend cwd, then collapse `.` / `..` components.
/// - Result always starts with `/` and never ends with `/` (except root).
pub fn resolve(pid: usize, path: &str) -> String {
    let base = if path.starts_with('/') {
        path.to_string()
    } else {
        let cwd = get_cwd(pid);
        alloc::format!("{}/{}", cwd.trim_end_matches('/'), path)
    };
    canonicalise(&base)
}

/// Collapse `.` and `..` in an absolute path.
fn canonicalise(path: &str) -> String {
    let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => { parts.pop(); }
            s    => parts.push(s),
        }
    }
    if parts.is_empty() {
        String::from("/")
    } else {
        let mut out = String::new();
        for s in &parts {
            out.push('/');
            out.push_str(s);
        }
        out
    }
}
