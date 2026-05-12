//! cgroupfs — /sys/fs/cgroup virtual filesystem (cgroup v2 unified hierarchy).
//!
//! ## Mount point
//!
//!   /sys/fs/cgroup/        ← root cgroup (CgroupId 1)
//!   /sys/fs/cgroup/foo/    ← child cgroup created with mkdir(2)
//!   /sys/fs/cgroup/foo/bar ← grandchild
//!
//! ## Files exposed in every cgroup directory
//!
//!   cgroup.procs      r/w  — list of member PIDs (newline-separated); write a PID to move it
//!   cgroup.children   r    — list of child CgroupIds
//!   cpu.weight        r/w  — scheduler weight 1..10000 (default 100)
//!   cpu.stat          r    — accumulated CPU usage (usage_usec <n>)
//!   memory.max        r/w  — memory hard limit in bytes, or "max"
//!   memory.current    r    — current RSS in bytes
//!   pids.max          r/w  — max live PIDs in subtree, or "max"
//!   pids.current      r    — current live PID count
//!   io.weight         r/w  — block-IO scheduler weight 1..10000 (default 100)
//!
//! ## Syscall integration
//!
//!   sys_open(path)    path starts with "/sys/fs/cgroup"  → cgroupfs_open()
//!   sys_read(fd, …)   fd is a cgroupfs fd               → cgroupfs_read()
//!   sys_write(fd, …)  fd is a cgroupfs fd               → cgroupfs_write()
//!   sys_close(fd)                                        → cgroupfs_close()
//!   getdents64(fd)    fd is a cgroupfs directory fd      → cgroupfs_list_dir()
//!   sys_mkdir(path)                                      → cgroupfs_mkdir()
//!   sys_rmdir(path)                                      → cgroupfs_rmdir()
//!
//! File nodes that are directories return `is_dir = true` and have empty
//! content bytes; reads on them return 0.  Writable files accept `sys_write`
//! which delegates to `cgroup::write_knob`.
//!
//! ## Synthetic fd space
//!
//!   CGROUPFS_FD_BASE  0x7100_0000   (above SYSFS_FD_BASE 0x7000_0000)
//!
//! All fds in this range are owned by cgroupfs and dispatched from
//! `io_syscalls.rs`.

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::proc::cgroup::{
    self as cgroup,
    CgroupId, ROOT_CGROUP,
};

// ─── Synthetic fd base ────────────────────────────────────────────────────────

pub const CGROUPFS_FD_BASE: usize = 0x7100_0000;

// ─── Per-fd state ─────────────────────────────────────────────────────────────

struct CgEntry {
    /// Absolute path that was opened, e.g. "/sys/fs/cgroup/foo/cpu.weight".
    path:    String,
    /// cgroup the path belongs to.
    cg_id:   CgroupId,
    /// The knob file name within the cgroup dir, e.g. "cpu.weight".
    /// Empty string → this is a directory open.
    knob:    String,
    /// True if this fd was opened on a directory.
    is_dir:  bool,
    /// Cached read content (generated once at open time).
    content: Vec<u8>,
    /// Current read offset.
    offset:  usize,
}

static TABLE: Mutex<BTreeMap<usize, CgEntry>> = Mutex::new(BTreeMap::new());
static COUNTER: AtomicUsize = AtomicUsize::new(0);

// ─── Public: fd predicate ────────────────────────────────────────────────────

/// Returns true when `fdno` is an open cgroupfs fd.
pub fn is_cgroupfs_fd(fdno: usize) -> bool {
    fdno >= CGROUPFS_FD_BASE && TABLE.lock().contains_key(&fdno)
}

// ─── Public: open ─────────────────────────────────────────────────────────────

/// Called by `sys_open` when the path starts with `/sys/fs/cgroup`.
/// Returns a synthetic fd (>= CGROUPFS_FD_BASE) or a negative errno.
///
/// - Opening a cgroup directory: `is_dir = true`, content is empty.
/// - Opening a knob file: reads the current value via `cgroup::read_knob`,
///   stores it so subsequent `sys_read` calls can seek through it.
pub fn cgroupfs_open(path: &str) -> isize {
    let (cg_id, knob) = match resolve_path(path) {
        Some(r) => r,
        None    => return -2, // ENOENT
    };

    let (is_dir, content) = if knob.is_empty() {
        // Directory open.
        (true, Vec::new())
    } else {
        // Knob file open: materialise content now.
        match cgroup::read_knob(cg_id, &knob) {
            Some(s) => (false, s.into_bytes()),
            None    => return -2,
        }
    };

    let id   = COUNTER.fetch_add(1, Ordering::Relaxed);
    let fdno = CGROUPFS_FD_BASE + id;
    TABLE.lock().insert(fdno, CgEntry {
        path:    path.to_string(),
        cg_id,
        knob,
        is_dir,
        content,
        offset: 0,
    });
    fdno as isize
}

// ─── Public: read ────────────────────────────────────────────────────────────

/// Copy up to `buf.len()` bytes from the fd's content starting at the stored
/// offset.  Advances the offset.  Returns bytes copied or negative errno.
pub fn cgroupfs_read(fdno: usize, buf: &mut [u8]) -> isize {
    let chunk: Vec<u8> = {
        let mut tbl = TABLE.lock();
        match tbl.get_mut(&fdno) {
            None    => return -9, // EBADF
            Some(e) => {
                if e.is_dir || e.offset >= e.content.len() { return 0; }
                let avail = &e.content[e.offset..];
                let n = avail.len().min(buf.len());
                let chunk = avail[..n].to_vec();
                e.offset += n;
                chunk
            }
        }
    };
    let n = chunk.len();
    buf[..n].copy_from_slice(&chunk);
    n as isize
}

// ─── Public: write ───────────────────────────────────────────────────────────

/// Write `data` to a cgroupfs knob file.  Delegates to `cgroup::write_knob`.
/// Returns bytes written on success, or negative errno.
pub fn cgroupfs_write(fdno: usize, data: &[u8]) -> isize {
    let (cg_id, knob) = {
        let tbl = TABLE.lock();
        match tbl.get(&fdno) {
            None    => return -9, // EBADF
            Some(e) => {
                if e.is_dir { return -21; } // EISDIR
                (e.cg_id, e.knob.clone())
            }
        }
    };
    let s = match core::str::from_utf8(data) {
        Ok(s)  => s,
        Err(_) => return -22, // EINVAL
    };
    let rc = cgroup::write_knob(cg_id, &knob, s);
    if rc < 0 { return rc; }

    // Refresh cached content so a subsequent read sees the updated value.
    if let Some(new_content) = cgroup::read_knob(cg_id, &knob) {
        let mut tbl = TABLE.lock();
        if let Some(e) = tbl.get_mut(&fdno) {
            e.content = new_content.into_bytes();
            e.offset  = 0;
        }
    }
    data.len() as isize
}

// ─── Public: close ───────────────────────────────────────────────────────────

pub fn cgroupfs_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

// ─── Public: getdents ────────────────────────────────────────────────────────

/// A single directory entry returned from `cgroupfs_list_dir`.
pub struct CgDirEntry {
    pub name:   String,
    pub is_dir: bool,
}

/// Return the immediate children of the directory opened as `fdno`.
/// Returns `None` if the fd is not a directory.
pub fn cgroupfs_list_dir(fdno: usize) -> Option<Vec<CgDirEntry>> {
    let (cg_id, path) = {
        let tbl = TABLE.lock();
        let e = tbl.get(&fdno)?;
        if !e.is_dir { return None; }
        (e.cg_id, e.path.clone())
    };
    Some(list_dir_for(cg_id, &path))
}

/// Enumerate the children of the cgroup directory at `path` without an open fd.
/// Used by VFS stat/getdents paths that don't first open the directory.
pub fn cgroupfs_list_dir_by_path(path: &str) -> Option<Vec<CgDirEntry>> {
    let (cg_id, knob) = resolve_path(path)?;
    if !knob.is_empty() { return None; } // it's a file, not a directory
    Some(list_dir_for(cg_id, path))
}

fn list_dir_for(cg_id: CgroupId, _path: &str) -> Vec<CgDirEntry> {
    let mut entries: Vec<CgDirEntry> = Vec::new();

    // Static knob files present in every cgroup directory.
    for name in KNOB_FILES {
        entries.push(CgDirEntry { name: name.to_string(), is_dir: false });
    }

    // Dynamic child cgroup subdirectories.
    if let Some(children_str) = cgroup::read_knob(cg_id, "cgroup.children") {
        for line in children_str.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            // Each child id — look up its name via path helpers.
            if let Ok(child_id) = line.parse::<CgroupId>() {
                let child_path = cgroup::cgid_to_path(child_id);
                // Extract the last component as the directory name.
                if let Some(seg) = child_path.split('/').last() {
                    if !seg.is_empty() {
                        entries.push(CgDirEntry { name: seg.to_string(), is_dir: true });
                    }
                }
            }
        }
    }
    entries
}

/// Canonical knob files present in every cgroup directory.
const KNOB_FILES: &[&str] = &[
    "cgroup.procs",
    "cgroup.children",
    "cpu.weight",
    "cpu.stat",
    "memory.max",
    "memory.current",
    "pids.max",
    "pids.current",
    "io.weight",
];

// ─── Public: mkdir / rmdir ───────────────────────────────────────────────────

/// Create a new child cgroup.  `path` is the full path of the new directory,
/// e.g. `/sys/fs/cgroup/containers/web`.
/// Returns 0 on success, negative errno on failure.
pub fn cgroupfs_mkdir(path: &str) -> isize {
    // The new cgroup's name is the last path component.
    let (parent_path, name) = match rsplit_path(path) {
        Some(pair) => pair,
        None       => return -22, // EINVAL
    };
    let parent_id = match cgroup::path_to_cgid(parent_path) {
        Some(id) => id,
        None     => return -2, // ENOENT
    };
    match cgroup::create_cgroup(parent_id, name) {
        Ok(_)  => 0,
        Err(e) => e as isize,
    }
}

/// Remove a cgroup.  `path` is the full path, e.g. `/sys/fs/cgroup/foo`.
/// Returns 0 on success, negative errno on failure.
pub fn cgroupfs_rmdir(path: &str) -> isize {
    match cgroup::path_to_cgid(path) {
        Some(id) => cgroup::remove_cgroup(id),
        None     => -2, // ENOENT
    }
}

// ─── stat / access helpers ───────────────────────────────────────────────────

/// Quick existence check used by sys_stat / sys_access for cgroupfs paths.
/// Returns `Some(is_dir)` if the path exists, `None` if it does not.
pub fn cgroupfs_exists(path: &str) -> Option<bool> {
    let (_, knob) = resolve_path(path)?;
    Some(knob.is_empty())
}

// ─── Path resolution ──────────────────────────────────────────────────────────

/// Parse a cgroupfs path into (CgroupId, knob_name).
///
/// - If the path ends at a cgroup directory: knob = "".
/// - If it ends at a known knob file:        knob = file name.
/// - Returns `None` for paths that don't exist.
fn resolve_path(path: &str) -> Option<(CgroupId, String)> {
    let stripped = path
        .strip_prefix("/sys/fs/cgroup")
        .unwrap_or(path)
        .trim_matches('/');

    if stripped.is_empty() {
        return Some((ROOT_CGROUP, String::new()));
    }

    // Walk the path components; the last component might be a knob file.
    let components: Vec<&str> = stripped.split('/').collect();
    let (dir_parts, last) = components.split_at(components.len() - 1);
    let last = last[0];

    // Build the directory prefix.
    let dir_path = if dir_parts.is_empty() {
        "/sys/fs/cgroup".to_string()
    } else {
        alloc::format!("/sys/fs/cgroup/{}", dir_parts.join("/"))
    };

    if KNOB_FILES.contains(&last) {
        // Last component is a knob: resolve the parent directory first.
        let cg_id = cgroup::path_to_cgid(&dir_path)?;
        Some((cg_id, last.to_string()))
    } else {
        // Try resolving the full path as a cgroup directory.
        let full = alloc::format!("/sys/fs/cgroup/{}", stripped);
        let cg_id = cgroup::path_to_cgid(&full)?;
        Some((cg_id, String::new()))
    }
}

/// Split `/a/b/c` into `("/a/b", "c")`.
fn rsplit_path(path: &str) -> Option<(&str, &str)> {
    let path = path.trim_end_matches('/');
    let pos = path.rfind('/')?;
    if pos == 0 { return None; }
    Some((&path[..pos], &path[pos + 1..]))
}
