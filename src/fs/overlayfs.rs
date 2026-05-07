//! OverlayFS — union filesystem with lower (read-only) and upper (read-write) layers.
//!
//! ## Architecture
//! ```
//!  userspace open("/overlay/foo")
//!        │
//!        ▼
//!  overlayfs lookup
//!        │
//!        ├─ upper layer check  (/upper/foo  exists?) ──► serve from upper
//!        │                     (.wh.foo     exists?) ──► ENOENT (whiteout)
//!        │
//!        └─ lower layer check  (/lower/foo  exists?) ──► copy-up then serve
//!                              (not found)           ──► ENOENT
//! ```
//!
//! ## Copy-up
//! On the first write to a lower-layer file, the entire file is copied into
//! the upper layer before the write is applied.  Subsequent opens see the
//! upper-layer copy.
//!
//! ## Whiteouts
//! Deletes in the upper layer are represented as zero-byte marker files
//! named `.wh.<original-name>`.  A whiteout hides the file in the lower layer.
//!
//! ## VFS integration
//! `overlayfs` is invoked from `vfs_ops` when `mount::resolve` returns
//! `FsType::Overlayfs`.  The lower/upper/work paths are resolved through
//! their own filesystems (typically ext2 for both, or tmpfs for upper).

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
    format,
};

use crate::fs::mount::{self, FsType};

// ── Error constants ───────────────────────────────────────────────────────────
const ENOENT:  isize = -2;
const EIO:     isize = -5;
const EACCES:  isize = -13;
const ENOTDIR: isize = -20;
const EISDIR:  isize = -21;
const ENOSPC:  isize = -28;

// ── Whiteout prefix ───────────────────────────────────────────────────────────
const WH_PREFIX: &str = ".wh.";

// ── Layer paths ───────────────────────────────────────────────────────────────

/// Options extracted from the mount table for a given overlayfs mount.
#[derive(Clone, Debug)]
pub struct OverlayMount {
    pub lower: String,
    pub upper: String,
    pub work:  String,
}

impl OverlayMount {
    pub fn from_opts(opts: &crate::fs::mount::OverlayOpts) -> Self {
        OverlayMount {
            lower: opts.lower.clone(),
            upper: opts.upper.clone(),
            work:  opts.work.clone(),
        }
    }

    // Full absolute paths for a given relative sub-path
    fn upper_path(&self, rel: &str) -> String { join(&self.upper, rel) }
    fn lower_path(&self, rel: &str) -> String { join(&self.lower, rel) }
    fn whiteout_path(&self, rel: &str) -> String {
        let (dir, base) = split_last(rel);
        join(&self.upper, &join(dir, &format!("{}{}", WH_PREFIX, base)))
    }
    fn work_path(&self, rel: &str) -> String { join(&self.work, rel) }
}

// ── Existence / metadata helpers ─────────────────────────────────────────────
// These forward to vfs_ops which dispatches to the correct underlying fs.

fn path_exists(path: &str) -> bool {
    crate::fs::vfs_ops::stat(path).is_ok()
}

fn path_is_dir(path: &str) -> bool {
    crate::fs::vfs_ops::stat(path)
        .map(|s| s.is_dir)
        .unwrap_or(false)
}

fn read_file(path: &str) -> Result<Vec<u8>, isize> {
    crate::fs::vfs_ops::read_all(path)
}

fn write_file(path: &str, data: &[u8]) -> Result<(), isize> {
    crate::fs::vfs_ops::write_all(path, data)
}

fn create_file(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::create(path)
}

fn create_dir(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::mkdir(path)
}

fn remove_file(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::unlink(path)
}

fn list_dir(path: &str) -> Result<Vec<String>, isize> {
    crate::fs::vfs_ops::readdir(path)
}

// ── Public overlay operations ─────────────────────────────────────────────────

/// Resolve an overlay-relative path to the concrete layer path that should be
/// used for reading.  Returns `Err(ENOENT)` if the file is whited-out or absent.
pub fn lookup(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    let (_, base) = split_last(rel);
    let wh = om.whiteout_path(rel);
    if path_exists(&wh) {
        return Err(ENOENT); // whiteout
    }
    let up = om.upper_path(rel);
    if path_exists(&up) {
        return Ok(up);
    }
    let lo = om.lower_path(rel);
    if path_exists(&lo) {
        return Ok(lo);
    }
    Err(ENOENT)
}

/// Open for reading: returns the resolved concrete path.
pub fn open_read(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    lookup(om, rel)
}

/// Open for writing: triggers copy-up if the file only exists in lower.
/// Returns the upper-layer path ready for writes.
pub fn open_write(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    let up = om.upper_path(rel);
    if path_exists(&up) {
        return Ok(up);
    }
    let lo = om.lower_path(rel);
    if path_exists(&lo) {
        // Copy-up: read from lower, write to upper (via work dir for atomicity)
        copy_up(om, rel, &lo, &up)?;
        return Ok(up);
    }
    Err(ENOENT)
}

/// Create a new file in the upper layer.
pub fn create(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    let up = om.upper_path(rel);
    // Remove any stale whiteout
    let wh = om.whiteout_path(rel);
    if path_exists(&wh) { let _ = remove_file(&wh); }
    create_file(&up)?;
    Ok(up)
}

/// Read a file through the overlay.
pub fn read(om: &OverlayMount, rel: &str, buf: &mut Vec<u8>) -> Result<usize, isize> {
    let path = open_read(om, rel)?;
    let data = read_file(&path)?;
    let n = data.len();
    *buf = data;
    Ok(n)
}

/// Write a file through the overlay (copy-up if needed).
pub fn write(om: &OverlayMount, rel: &str, data: &[u8]) -> Result<(), isize> {
    let path = open_write(om, rel)
        .or_else(|_| create(om, rel))?;
    write_file(&path, data)
}

/// Unlink: place a whiteout in the upper layer.
pub fn unlink(om: &OverlayMount, rel: &str) -> Result<(), isize> {
    // If file exists in upper, remove it
    let up = om.upper_path(rel);
    if path_exists(&up) { remove_file(&up)?; }
    // If it exists in lower, lay a whiteout
    let lo = om.lower_path(rel);
    if path_exists(&lo) {
        let wh = om.whiteout_path(rel);
        create_file(&wh)?;
    } else if !path_exists(&up) {
        return Err(ENOENT);
    }
    Ok(())
}

/// mkdir: create directory in upper layer.  If it exists in lower, just
/// create a corresponding directory in upper (no copy-up needed for dirs).
pub fn mkdir(om: &OverlayMount, rel: &str) -> Result<(), isize> {
    let up = om.upper_path(rel);
    if path_exists(&up) { return Err(-17); } // EEXIST
    create_dir(&up)
}

/// rmdir: whiteout + remove upper if present.
pub fn rmdir(om: &OverlayMount, rel: &str) -> Result<(), isize> {
    let entries = readdir(om, rel)?;
    let non_trivial: Vec<_> = entries.iter()
        .filter(|e| *e != "." && *e != "..")
        .collect();
    if !non_trivial.is_empty() { return Err(-39); } // ENOTEMPTY
    let up = om.upper_path(rel);
    if path_is_dir(&up) { remove_file(&up)?; }
    let lo = om.lower_path(rel);
    if path_is_dir(&lo) {
        let wh = om.whiteout_path(rel);
        create_file(&wh)?;
    }
    Ok(())
}

/// readdir: merge upper + lower, applying whiteouts.
pub fn readdir(om: &OverlayMount, rel: &str) -> Result<Vec<String>, isize> {
    let up_path = om.upper_path(rel);
    let lo_path = om.lower_path(rel);

    let mut names: Vec<String> = Vec::new();
    let mut whiteouts: Vec<String> = Vec::new();

    // Scan upper
    if path_is_dir(&up_path) {
        for name in list_dir(&up_path)? {
            if name.starts_with(WH_PREFIX) {
                whiteouts.push(name[WH_PREFIX.len()..].to_string());
            } else {
                names.push(name);
            }
        }
    }

    // Scan lower, skip whited-out names and duplicates already in upper
    if path_is_dir(&lo_path) {
        for name in list_dir(&lo_path)? {
            if whiteouts.contains(&name) { continue; }
            if names.contains(&name)      { continue; }
            names.push(name);
        }
    }

    Ok(names)
}

/// rename within the overlay.
pub fn rename(om: &OverlayMount, old_rel: &str, new_rel: &str) -> Result<(), isize> {
    // Copy-up old if in lower, write to new upper location, whiteout old
    let data = {
        let mut buf = Vec::new();
        read(om, old_rel, &mut buf)?;
        buf
    };
    write(om, new_rel, &data)?;
    unlink(om, old_rel)
}

// ── Copy-up ───────────────────────────────────────────────────────────────────

/// Atomically copy a file from `lower_path` → `upper_path` via the work dir.
fn copy_up(om: &OverlayMount, rel: &str, lower_path: &str, upper_path: &str) -> Result<(), isize> {
    let (dir, base) = split_last(rel);
    // Ensure upper parent directory exists
    ensure_upper_dir(om, dir)?;
    // Stage into work dir first
    let work_stage = om.work_path(base);
    let data = read_file(lower_path)?;
    write_file(&work_stage, &data)?;
    // "Rename" from work to upper — we write directly to upper since we have
    // no rename primitive across filesystems; for same-fs this is atomic.
    write_file(upper_path, &data)?;
    let _ = remove_file(&work_stage);
    Ok(())
}

/// Recursively ensure that the upper-layer mirror of `dir` exists.
fn ensure_upper_dir(om: &OverlayMount, dir: &str) -> Result<(), isize> {
    if dir == "/" || dir.is_empty() { return Ok(()); }
    let up_dir = om.upper_path(dir);
    if path_is_dir(&up_dir) { return Ok(()); }
    let (parent, _) = split_last(dir);
    ensure_upper_dir(om, parent)?;
    create_dir(&up_dir)
}

// ── Path utilities ────────────────────────────────────────────────────────────

fn join(base: &str, rel: &str) -> String {
    let base = base.trim_end_matches('/');
    let rel  = rel.trim_start_matches('/');
    if rel.is_empty() { base.to_string() }
    else { format!("{}/{}", base, rel) }
}

/// Split `/a/b/c` → (`"/a/b"`, `"c"`).  Root gives `("/", "")`.  
fn split_last(path: &str) -> (&str, &str) {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) if i == 0 => ("/", &p[1..]),
        Some(i)           => (&p[..i], &p[i+1..]),
        None              => ("/", p),
    }
}
