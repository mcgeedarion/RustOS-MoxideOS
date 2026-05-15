//! Per-process current working directory.
//!
//! Linux keeps `fs->pwd` inside the process's `fs_struct`.  We approximate
//! that with a global table keyed by pid.  The table is cheap: it is only
//! written on chdir/fchdir/fork/exit and read on getcwd/path resolution.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::collections::BTreeMap;
use spin::Mutex;

static CWD_TABLE: Mutex<BTreeMap<usize, String>> = Mutex::new(BTreeMap::new());

/// Return the cwd for `pid`.  Defaults to `"/"` if never set.
pub fn get_cwd(pid: usize) -> String {
    CWD_TABLE.lock()
        .get(&pid)
        .cloned()
        .unwrap_or_else(|| String::from("/"))
}

/// Set the cwd for the current process to `path`.
///
/// Returns:
///  *  `0`   – success
///  * `-2`   – ENOENT  (path does not exist)
///  * `-20`  – ENOTDIR (path is not a directory)
pub fn set_cwd(pid: usize, path: &str) -> isize {
    // Pseudo-fs roots are always valid directories.
    let is_pseudo = path == "/"
        || path.starts_with("/proc")
        || path.starts_with("/dev")
        || path.starts_with("/sys")
        || path.starts_with("/tmp");

    if !is_pseudo {
        // Ask the VFS whether the path exists and is a directory.
        match crate::fs::vfs::stat(path) {
            None     => return -2,   // ENOENT
            Some(vs) => {
                if !vs.is_dir { return -20; } // ENOTDIR
            }
        }
    }

    // Normalise: strip trailing slash unless it is the root itself.
    let normalised = if path.len() > 1 {
        path.trim_end_matches('/').to_string()
    } else {
        path.to_string()
    };

    CWD_TABLE.lock().insert(pid, normalised);
    0
}

/// Copy the parent's cwd into the child.  Called by fork.
pub fn fork_cwd(parent_pid: usize, child_pid: usize) {
    let parent_cwd = get_cwd(parent_pid);
    CWD_TABLE.lock().insert(child_pid, parent_cwd);
}

/// Remove the cwd entry for `pid`.  Called during exit cleanup.
pub fn clear_cwd(pid: usize) {
    CWD_TABLE.lock().remove(&pid);
}
