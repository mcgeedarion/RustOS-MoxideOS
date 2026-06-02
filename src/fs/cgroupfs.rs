//! cgroupfs — synthetic /sys/fs/cgroup filesystem (cgroup v2 unified hierarchy).
//!
//! ## Overview
//!
//! This module provides the VFS-facing surface for cgroupfs.  All reads and
//! writes ultimately delegate to [`crate::proc::cgroup`], which owns the
//! authoritative `CgroupTable`.
//!
//! ## fd allocation
//!
//! Synthetic fds are allocated in the range **600–699** to avoid collisions
//! with procfs (256–511) and sysfs (512–599).
//!
//! ## Functions called from `vfs_ops`
//!
//! | `vfs_ops` call site          | Function here                   |
//! |------------------------------|---------------------------------|
//! | `read_all` / `write_all`     | `cgroupfs_open/read/close`      |
//! | `stat_impl`                  | `cgroupfs_exists`               |
//! | `readdir`                    | `cgroupfs_list_dir_by_path`     |
//! | `mkdir`                      | `cgroupfs_mkdir`                |
//! | `rmdir`                      | `cgroupfs_rmdir`                |

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::proc::cgroup;

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

#[derive(Clone)]
struct CgFd {
    content: Vec<u8>,
    offset:  usize,
}

static CGFS_FDS: Mutex<BTreeMap<usize, CgFd>> = Mutex::new(BTreeMap::new());

fn next_cgfs_fd() -> usize {
    let guard = CGFS_FDS.lock();
    for candidate in 600..700 {
        if !guard.contains_key(&candidate) { return candidate; }
    }
    600
}

/// Returns true if `fdno` is a cgroupfs synthetic fd.
pub fn is_cgroupfs_fd(fdno: usize) -> bool {
    CGFS_FDS.lock().contains_key(&fdno)
}

/// Open a cgroupfs knob file and return a synthetic fd, or negative errno.
/// `path` is an absolute path like `/sys/fs/cgroup/foo/cpu.weight`.
pub fn cgroupfs_open(path: &str) -> isize {
    // Split path into cgroup directory and knob filename.
    let (dir, file) = match path.rfind('/') {
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None      => return -2,
    };

    // Resolve the cgroup dir to a CgroupId.
    let cgid = match cgroup::path_to_cgid(dir) {
        Some(id) => id,
        None     => return -2,
    };

    // Read the knob content (or synthesise a directory listing).
    let content: Vec<u8> = if file.is_empty() || file == "/" {
        // Opening the directory itself — return sorted entry names.
        dir_listing_bytes(cgid)
    } else if KNOB_FILES.contains(&file) {
        match cgroup::read_knob(cgid, file) {
            Some(s) => s.into_bytes(),
            None    => return -2,
        }
    } else {
        return -2;
    };

    let fdno = next_cgfs_fd();
    CGFS_FDS.lock().insert(fdno, CgFd { content, offset: 0 });
    fdno as isize
}

/// Read bytes from a cgroupfs synthetic fd.
pub fn cgroupfs_read(fdno: usize, buf: &mut [u8]) -> isize {
    let mut guard = CGFS_FDS.lock();
    let fd = match guard.get_mut(&fdno) {
        Some(f) => f,
        None    => return -9, // EBADF
    };
    let start = fd.offset.min(fd.content.len());
    let avail = &fd.content[start..];
    let n = avail.len().min(buf.len());
    buf[..n].copy_from_slice(&avail[..n]);
    fd.offset += n;
    n as isize
}

/// Release a cgroupfs synthetic fd.
pub fn cgroupfs_close(fdno: usize) {
    CGFS_FDS.lock().remove(&fdno);
}

/// Check whether `path` exists under cgroupfs.
/// Returns `Some(true)` for directories, `Some(false)` for knob files,
/// `None` if the path does not exist.
pub fn cgroupfs_exists(path: &str) -> Option<bool> {
    let stripped = path.strip_prefix("/sys/fs/cgroup").unwrap_or(path);

    // Root mount point itself.
    if stripped.is_empty() || stripped == "/" {
        return Some(true);
    }

    // Split into parent directory and final component.
    let s = stripped.trim_start_matches('/');
    match s.rfind('/') {
        None => {
            // Single component: either a child cgroup dir or a root-level knob.
            if KNOB_FILES.contains(&s) {
                // Root-level knob.
                return Some(false);
            }
            // Child cgroup of root?
            let cgid = cgroup::path_to_cgid(path)?;
            let _ = cgid;
            Some(true)
        }
        Some(slash) => {
            let dir  = &stripped[..stripped.rfind('/').unwrap()];
            let file = &stripped[stripped.rfind('/').unwrap() + 1..];
            if KNOB_FILES.contains(&file) {
                // Verify the parent cgroup exists.
                let full_dir = alloc::format!("/sys/fs/cgroup{}", dir);
                cgroup::path_to_cgid(&full_dir)?;
                Some(false)
            } else {
                // Must be a cgroup directory.
                let cgid = cgroup::path_to_cgid(path)?;
                let _ = cgid;
                Some(true)
            }
        }
    }
}

/// A single directory entry returned by `cgroupfs_list_dir_by_path`.
pub struct CgDirEntry {
    pub name:   String,
    pub is_dir: bool,
}

/// List the contents of a cgroupfs directory path.
/// Returns `None` if the path does not resolve to a cgroup directory.
pub fn cgroupfs_list_dir_by_path(path: &str) -> Option<Vec<CgDirEntry>> {
    let cgid = cgroup::path_to_cgid(path)?;
    let mut entries: Vec<CgDirEntry> = Vec::new();

    // Synthetic `.` and `..`.
    entries.push(CgDirEntry { name: String::from("."),  is_dir: true });
    entries.push(CgDirEntry { name: String::from(".."), is_dir: true });

    // Child cgroup directories.
    let children = cgroup_children(cgid);
    for child_name in children {
        entries.push(CgDirEntry { name: child_name, is_dir: true });
    }

    // Knob files.
    for &knob in KNOB_FILES {
        entries.push(CgDirEntry { name: String::from(knob), is_dir: false });
    }

    Some(entries)
}

/// Create a new child cgroup by mkdir on the cgroupfs path.
/// Returns 0 on success, negative errno on failure.
pub fn cgroupfs_mkdir(path: &str) -> isize {
    // Split into parent path and new cgroup name.
    let idx = match path.rfind('/') {
        Some(i) if i < path.len() - 1 => i,
        _ => return -22, // EINVAL — trailing slash or no slash
    };
    let parent_path = &path[..idx];
    let child_name  = &path[idx + 1..];

    // Resolve parent.
    let parent_path = if parent_path.is_empty() { "/sys/fs/cgroup" } else { parent_path };
    let parent_cgid = match cgroup::path_to_cgid(parent_path) {
        Some(id) => id,
        None     => return -2, // ENOENT
    };

    match cgroup::create_cgroup(parent_cgid, child_name) {
        Ok(_)  => 0,
        Err(e) => e as isize,
    }
}

/// Remove a cgroup by rmdir on the cgroupfs path.
/// Returns 0 on success, negative errno on failure.
pub fn cgroupfs_rmdir(path: &str) -> isize {
    let cgid = match cgroup::path_to_cgid(path) {
        Some(id) => id,
        None     => return -2,
    };
    cgroup::remove_cgroup(cgid)
}

/// Build a newline-separated directory listing byte string for a cgroup dir.
fn dir_listing_bytes(cgid: cgroup::CgroupId) -> Vec<u8> {
    let mut out = String::new();
    for name in cgroup_children(cgid) {
        out.push_str(&name);
        out.push('\n');
    }
    for knob in KNOB_FILES {
        out.push_str(knob);
        out.push('\n');
    }
    out.into_bytes()
}

/// Return the names of direct child cgroups of `cgid`.
fn cgroup_children(cgid: cgroup::CgroupId) -> Vec<String> {
    // We can't hold the CGROUPS lock across a public call, so we snapshot.
    // cgroup::read_knob provides "cgroup.children" as a newline-separated
    // list of CgroupIds.  We convert those back to names via cgid_to_path.
    let raw = cgroup::read_knob(cgid, "cgroup.children")
        .unwrap_or_default();
    let mut names = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Ok(child_id) = line.parse::<u32>() {
            let full = cgroup::cgid_to_path(child_id);
            // Extract just the last path component.
            if let Some(name) = full.split('/').last() {
                if !name.is_empty() {
                    names.push(String::from(name));
                }
            }
        }
    }
    names
}
