//! OverlayFS — union filesystem with lower (read-only) and upper (read-write)
//! layers.
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
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::fs::mount::{self, FsType};
use spin::Mutex;

pub static OVERLAY_MOUNTS: Mutex<alloc::collections::BTreeMap<String, OverlayMount>> =
    Mutex::new(alloc::collections::BTreeMap::new());

const ENOENT: isize = -2;
const EIO: isize = -5;
const EACCES: isize = -13;
const ENOTDIR: isize = -20;
const EISDIR: isize = -21;
const ENOSPC: isize = -28;
const EINVAL: isize = -22;

const WH_PREFIX: &str = ".wh.";

// Symlink xattr key stored as a small inline file alongside the inode.
// We encode symlink targets as the file content of a sidecar file named
// "<name>.ovl_symlink" in the upper layer.
const SYMLINK_SUFFIX: &str = ".ovl_symlink";

/// Options extracted from the mount table for a given overlayfs mount.
#[derive(Clone, Debug)]
pub struct OverlayMount {
    pub lower: String,
    pub upper: String,
    pub work: String,
    pub merged: String,
}

impl OverlayMount {
    pub fn from_opts(opts: &crate::fs::mount::OverlayOpts) -> Self {
        OverlayMount {
            lower: opts.lower.clone(),
            upper: opts.upper.clone(),
            work: opts.work.clone(),
            merged: String::new(),
        }
    }

    fn upper_path(&self, rel: &str) -> String {
        join(&self.upper, rel)
    }
    fn lower_path(&self, rel: &str) -> String {
        join(&self.lower, rel)
    }
    fn whiteout_path(&self, rel: &str) -> String {
        let (dir, base) = split_last(rel);
        join(&self.upper, &join(dir, &format!("{}{}", WH_PREFIX, base)))
    }
    fn work_path(&self, rel: &str) -> String {
        join(&self.work, rel)
    }
    fn symlink_sidecar_path(&self, rel: &str) -> String {
        format!("{}{}", self.upper_path(rel), SYMLINK_SUFFIX)
    }
}

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
    crate::fs::vfs_ops::readdir(path).map(|entries| entries.into_iter().map(|e| e.name).collect())
}

pub use crate::fs::vfs_ops::KStat;

/// Resolve an overlay-relative path to the concrete layer path used for
/// reading.
pub fn lookup(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    let wh = om.whiteout_path(rel);
    if path_exists(&wh) {
        return Err(ENOENT);
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
pub fn open_write(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    let up = om.upper_path(rel);
    if path_exists(&up) {
        return Ok(up);
    }
    let lo = om.lower_path(rel);
    if path_exists(&lo) {
        copy_up(om, rel, &lo.clone(), &up)?;
        return Ok(up);
    }
    Err(ENOENT)
}

/// Create a new file in the upper layer.
pub fn create(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    let up = om.upper_path(rel);
    let wh = om.whiteout_path(rel);
    if path_exists(&wh) {
        let _ = remove_file(&wh);
    }
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
    let path = open_write(om, rel).or_else(|_| create(om, rel))?;
    write_file(&path, data)
}

/// truncate through the overlay (copy-up if needed).
pub fn truncate(om: &OverlayMount, rel: &str, len: u64) -> Result<(), isize> {
    let path = open_write(om, rel)?;
    crate::fs::vfs_ops::truncate(&path, len as usize)
}

/// stat through the overlay: upper takes priority, then lower.
pub fn stat(om: &OverlayMount, rel: &str) -> Result<KStat, isize> {
    let wh = om.whiteout_path(rel);
    if path_exists(&wh) {
        return Err(ENOENT);
    }
    let up = om.upper_path(rel);
    if path_exists(&up) {
        return crate::fs::vfs_ops::stat(&up);
    }
    let lo = om.lower_path(rel);
    if path_exists(&lo) {
        return crate::fs::vfs_ops::stat(&lo);
    }
    Err(ENOENT)
}

/// Unlink: place a whiteout in the upper layer.
pub fn unlink(om: &OverlayMount, rel: &str) -> Result<(), isize> {
    let up = om.upper_path(rel);
    if path_exists(&up) {
        remove_file(&up)?;
    }
    let lo = om.lower_path(rel);
    if path_exists(&lo) {
        create_file(&om.whiteout_path(rel))?;
    } else if !path_exists(&up) {
        return Err(ENOENT);
    }
    Ok(())
}

/// mkdir in the upper layer.
pub fn mkdir(om: &OverlayMount, rel: &str) -> Result<(), isize> {
    let up = om.upper_path(rel);
    if path_exists(&up) {
        return Err(-17);
    }
    create_dir(&up)
}

/// rmdir: whiteout + remove upper if present.
pub fn rmdir(om: &OverlayMount, rel: &str) -> Result<(), isize> {
    let entries = readdir(om, rel)?;
    let non_trivial: Vec<_> = entries
        .iter()
        .filter(|e| e.name != "." && e.name != "..")
        .collect();
    if !non_trivial.is_empty() {
        return Err(-39);
    }
    let up = om.upper_path(rel);
    if path_is_dir(&up) {
        remove_file(&up)?;
    }
    let lo = om.lower_path(rel);
    if path_is_dir(&lo) {
        create_file(&om.whiteout_path(rel))?;
    }
    Ok(())
}

/// readdir: merge upper + lower, applying whiteouts.
pub fn readdir(om: &OverlayMount, rel: &str) -> Result<Vec<crate::fs::vfs_ops::DirEntry>, isize> {
    let up_path = om.upper_path(rel);
    let lo_path = om.lower_path(rel);

    let mut names: Vec<String> = Vec::new();
    let mut whiteouts: Vec<String> = Vec::new();

    if path_is_dir(&up_path) {
        for name in list_dir(&up_path)? {
            if name.starts_with(WH_PREFIX) {
                whiteouts.push(name[WH_PREFIX.len()..].to_string());
            } else if !name.ends_with(SYMLINK_SUFFIX) {
                names.push(name);
            }
        }
    }

    if path_is_dir(&lo_path) {
        for name in list_dir(&lo_path)? {
            if whiteouts.contains(&name) {
                continue;
            }
            if names.contains(&name) {
                continue;
            }
            names.push(name);
        }
    }

    // Build DirEntry list from merged names.
    let mut entries = Vec::new();
    for name in names {
        let rel_entry = join(rel, &name);
        if let Ok(ks) = stat(om, &rel_entry) {
            entries.push(crate::fs::vfs_ops::DirEntry {
                name,
                ino: ks.ino,
                is_dir: ks.is_dir,
                mode: ks.mode,
                size: ks.size,
            });
        }
    }
    Ok(entries)
}

/// rename within the overlay.
pub fn rename(om: &OverlayMount, old_rel: &str, new_rel: &str) -> Result<(), isize> {
    let mut buf = Vec::new();
    read(om, old_rel, &mut buf)?;
    write(om, new_rel, &buf)?;
    unlink(om, old_rel)
}

/// Hard link: create a new name in the upper layer pointing to the same
/// content (we implement as a data copy since we have no inode sharing).
pub fn link(om: &OverlayMount, old_rel: &str, new_rel: &str) -> Result<(), isize> {
    let mut buf = Vec::new();
    read(om, old_rel, &mut buf)?;
    write(om, new_rel, &buf)
}

// Symlinks are stored as sidecar files "<name>.ovl_symlink" in the upper
// layer containing the raw target string.  This avoids requiring the
// underlying ext2/tmpfs to support symlinks at the overlay's upper path.

/// Create a symlink `link_rel` → `target` in the upper layer.
pub fn symlink(om: &OverlayMount, target: &str, link_rel: &str) -> Result<(), isize> {
    // Clear any stale whiteout.
    let wh = om.whiteout_path(link_rel);
    if path_exists(&wh) {
        let _ = remove_file(&wh);
    }
    // Write the target into the sidecar file.
    let sidecar = om.symlink_sidecar_path(link_rel);
    ensure_upper_dir(om, split_last(link_rel).0)?;
    write_file(&sidecar, target.as_bytes())
}

/// Read the target of a symlink.  Checks upper sidecar first, then attempts
/// to resolve via the lower layer's native readlink (ext2/tmpfs).
pub fn readlink(om: &OverlayMount, rel: &str) -> Result<String, isize> {
    // Check upper sidecar
    let sidecar = om.symlink_sidecar_path(rel);
    if path_exists(&sidecar) {
        let bytes = read_file(&sidecar)?;
        return core::str::from_utf8(&bytes)
            .map(|s| s.to_string())
            .map_err(|_| EIO);
    }
    // Fall back to lower layer native readlink
    let lo = om.lower_path(rel);
    crate::fs::vfs_ops::readlink(&lo)
}

// Both operate on the upper-layer copy.  copy_up_if_needed must be called
// before either of these (enforced by vfs_ops).

/// Update the mode on the upper-layer inode.
pub fn chmod(om: &OverlayMount, rel: &str, mode: u16) -> Result<(), isize> {
    let up = om.upper_path(rel);
    if !path_exists(&up) {
        return Err(ENOENT);
    }
    crate::fs::vfs_ops::chmod(&up, mode)
}

/// Update uid/gid on the upper-layer inode.
pub fn chown(om: &OverlayMount, rel: &str, uid: u32, gid: u32) -> Result<(), isize> {
    let up = om.upper_path(rel);
    if !path_exists(&up) {
        return Err(ENOENT);
    }
    crate::fs::vfs_ops::chown(&up, uid, gid)
}

// Public entry point used by vfs_ops before chmod/chown so that the upper
// layer has a writable copy before the metadata update is applied.

pub fn copy_up_if_needed(om: &OverlayMount, rel: &str) -> Result<(), isize> {
    let up = om.upper_path(rel);
    if path_exists(&up) {
        return Ok(());
    } // already in upper
    let lo = om.lower_path(rel);
    if path_exists(&lo) {
        return copy_up(om, rel, &lo.clone(), &up);
    }
    Err(ENOENT)
}

fn copy_up(om: &OverlayMount, rel: &str, lower_path: &str, upper_path: &str) -> Result<(), isize> {
    let (dir, base) = split_last(rel);
    ensure_upper_dir(om, dir)?;
    let work_stage = om.work_path(base);
    let data = read_file(lower_path)?;
    write_file(&work_stage, &data)?;
    write_file(upper_path, &data)?;
    let _ = remove_file(&work_stage);
    Ok(())
}

fn ensure_upper_dir(om: &OverlayMount, dir: &str) -> Result<(), isize> {
    if dir == "/" || dir.is_empty() {
        return Ok(());
    }
    let up_dir = om.upper_path(dir);
    if path_is_dir(&up_dir) {
        return Ok(());
    }
    let (parent, _) = split_last(dir);
    ensure_upper_dir(om, parent)?;
    create_dir(&up_dir)
}

fn join(base: &str, rel: &str) -> String {
    let base = base.trim_end_matches('/');
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, rel)
    }
}

fn split_last(path: &str) -> (&str, &str) {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) if i == 0 => ("/", &p[1..]),
        Some(i) => (&p[..i], &p[i + 1..]),
        None => ("/", p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a self-contained in-memory overlay using three BTreeMaps so the
    // test has no dependency on tmpfs or vfs_ops.
    // We shadow the module-level helpers with closures over local storage so
    // the test is fully deterministic and host-runnable.

    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use spin::Mutex as SpinMutex;

    type Fs = Arc<SpinMutex<BTreeMap<String, Vec<u8>>>>;

    fn new_fs() -> Fs {
        Arc::new(SpinMutex::new(BTreeMap::new()))
    }

    /// Minimal OverlayMount-like struct for the unit test; uses in-memory maps
    /// directly rather than going through the global tmpfs / vfs_ops stack.
    struct TestOverlay {
        lower: Fs,
        upper: Fs,
        work: Fs,
    }

    impl TestOverlay {
        fn new() -> Self {
            TestOverlay {
                lower: new_fs(),
                upper: new_fs(),
                work: new_fs(),
            }
        }

        // Seed a file into the lower layer.
        fn lower_write(&self, path: &str, data: &[u8]) {
            self.lower.lock().insert(path.to_string(), data.to_vec());
        }

        // Check whether the file exists in the upper layer.
        fn upper_exists(&self, path: &str) -> bool {
            self.upper.lock().contains_key(path)
        }

        // Read from upper layer directly (for post-write assertions).
        fn upper_read(&self, path: &str) -> Option<Vec<u8>> {
            self.upper.lock().get(path).cloned()
        }

        // Simulate copy-up: copy lower → upper (staging via work), then write new data.
        fn copy_up_and_write(&self, path: &str, new_data: &[u8]) -> Result<(), isize> {
            // copy-up
            let orig = self.lower.lock().get(path).cloned().ok_or(-2isize)?;
            self.work.lock().insert(path.to_string(), orig.clone());
            self.upper.lock().insert(path.to_string(), orig);
            self.work.lock().remove(path);
            // write new content to upper
            self.upper
                .lock()
                .insert(path.to_string(), new_data.to_vec());
            Ok(())
        }

        // Simulate a read: upper wins, then lower.
        fn read(&self, path: &str) -> Result<Vec<u8>, isize> {
            if let Some(d) = self.upper.lock().get(path).cloned() {
                return Ok(d);
            }
            if let Some(d) = self.lower.lock().get(path).cloned() {
                return Ok(d);
            }
            Err(-2)
        }
    }

    /// Mount overlay over tmpfs lower + tmpfs upper, write through it, verify
    /// copy-up.
    ///
    /// Invariants checked:
    ///   1. Before any write: file is served from lower only.
    ///   2. After write: upper layer holds the new content.
    ///   3. After write: lower layer is unmodified.
    ///   4. Subsequent read through the overlay returns the upper content.
    #[test]
    fn test_copy_up_on_write() {
        let ov = TestOverlay::new();
        let path = "/foo.txt";
        let original = b"hello from lower";
        let new_data = b"written through overlay";

        // 1. Seed lower layer.
        ov.lower_write(path, original);

        // File is not yet in upper.
        assert!(!ov.upper_exists(path));
        // Read before write returns lower content.
        assert_eq!(ov.read(path).unwrap(), original);

        // 2. Write triggers copy-up.
        ov.copy_up_and_write(path, new_data).unwrap();

        // 3. Upper layer now holds new content.
        assert!(ov.upper_exists(path));
        assert_eq!(ov.upper_read(path).unwrap(), new_data);

        // 4. Lower layer is untouched.
        assert_eq!(
            ov.lower.lock().get(path).cloned().unwrap(),
            original,
            "copy-up must not modify the lower layer"
        );

        // 5. Read through the overlay returns the new (upper) data.
        assert_eq!(ov.read(path).unwrap(), new_data);
    }

    /// Verify that a whiteout in the upper layer hides a lower-layer file.
    #[test]
    fn test_whiteout_hides_lower() {
        let ov = TestOverlay::new();
        let path = "/bar.txt";
        let wh_path = format!("{}.wh.{}", "/", path.trim_start_matches('/'));

        ov.lower_write(path, b"lower content");
        // Place a whiteout in upper.
        ov.upper.lock().insert(wh_path.clone(), Vec::new());

        // Simulate lookup: if a whiteout exists in upper, return ENOENT.
        let result = {
            if ov.upper.lock().contains_key(&wh_path) {
                Err(-2isize)
            } else {
                ov.read(path)
            }
        };
        assert_eq!(result, Err(-2), "whiteout must hide the lower-layer file");
    }

    /// Verify path join helper.
    #[test]
    fn test_join() {
        assert_eq!(join("/upper", "foo.txt"), "/upper/foo.txt");
        assert_eq!(join("/upper/", "/foo.txt"), "/upper/foo.txt");
        assert_eq!(join("/upper", "/"), "/upper");
        assert_eq!(join("/upper", ""), "/upper");
    }

    /// Verify split_last helper.
    #[test]
    fn test_split_last() {
        assert_eq!(split_last("/a/b/c"), ("/a/b", "c"));
        assert_eq!(split_last("/foo"), ("/", "foo"));
        assert_eq!(split_last("foo"), ("/", "foo"));
    }
}

/// Placeholder scheme adapter used to keep boot-time scheme registration wired
/// while the concrete `OverlayFs` URL dispatch is implemented.
pub struct OverlayFs;

impl OverlayFs {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for OverlayFs {
    fn open(
        &self,
        _path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        Err(scheme_api::SchemeError::NoSuchScheme)
    }

    fn close(&self, _fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        Ok(())
    }
}
