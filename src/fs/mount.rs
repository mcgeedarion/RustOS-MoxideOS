//! Mount table, sys_mount, sys_umount2, and path→filesystem resolution.
//!
//! ## Design
//! A single global `MountTable` holds an ordered `Vec<MountEntry>`.  Entries
//! are sorted by mount-point length (longest first) so that the first prefix
//! match is always the most specific one.
//!
//! ## FsHandle
//! `FsHandle` is the opaque token returned to callers such as `vfs_ops`.  It
//! carries both the filesystem type and the mount-relative sub-path so the
//! backend never has to know its own mount-point.
//!
//! ## Supported filesystem types
//! | FsType     | Backend module       | Typical mount point(s)    |
//! |------------|----------------------|---------------------------|
//! | Ext2       | fs::ext2             | /                         |
//! | Fat32      | fs::fat32            | /boot/efi, /mnt/usb       |
//! | Tmpfs      | fs::ramfs            | /tmp, /run, /dev/shm      |
//! | Overlayfs  | fs::overlayfs        | /overlay, container roots |
//! | Devfs      | fs::devfs            | /dev                      |
//! | Procfs     | fs::procfs           | /proc                     |
//! | Sysfs      | fs::sysfs            | /sys                      |

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use spin::Mutex;

// ── Filesystem type discriminant ────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum FsType {
    Ext2,
    Fat32,
    Tmpfs,
    Overlayfs,
    Devfs,
    Procfs,
    Sysfs,
}

impl FsType {
    /// Parse the kernel-facing filesystem name string (as passed to mount(2)).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ext2" | "ext3" | "ext4" => Some(FsType::Ext2),
            "vfat" | "fat32" | "fat" => Some(FsType::Fat32),
            "tmpfs"                  => Some(FsType::Tmpfs),
            "overlay" | "overlayfs"  => Some(FsType::Overlayfs),
            "devtmpfs" | "devfs"     => Some(FsType::Devfs),
            "proc"                   => Some(FsType::Procfs),
            "sysfs"                  => Some(FsType::Sysfs),
            _                        => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FsType::Ext2      => "ext2",
            FsType::Fat32     => "vfat",
            FsType::Tmpfs     => "tmpfs",
            FsType::Overlayfs => "overlay",
            FsType::Devfs     => "devtmpfs",
            FsType::Procfs    => "proc",
            FsType::Sysfs     => "sysfs",
        }
    }
}

// ── Mount flags (mirrors Linux MS_* bits) ───────────────────────────────────

pub const MS_RDONLY:      u64 = 1 << 0;
pub const MS_NOSUID:      u64 = 1 << 1;
pub const MS_NODEV:       u64 = 1 << 2;
pub const MS_NOEXEC:      u64 = 1 << 3;
pub const MS_REMOUNT:     u64 = 1 << 5;
pub const MS_BIND:        u64 = 1 << 12;
pub const MS_MOVE:        u64 = 1 << 13;
pub const MS_SILENT:      u64 = 1 << 15;

// umount2 flags
pub const MNT_FORCE:      u32 = 1;
pub const MNT_DETACH:     u32 = 2;
pub const MNT_EXPIRE:     u32 = 4;

// ── Per-entry overlay options ────────────────────────────────────────────────

/// Extra parameters carried for overlayfs mounts.
#[derive(Clone, Debug)]
pub struct OverlayOpts {
    pub lower:   String,   // lower (read-only) directory
    pub upper:   String,   // upper (read-write) directory
    pub work:    String,   // work directory (must be on same fs as upper)
}

// ── MountEntry ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MountEntry {
    pub mountpoint: String,   // absolute path, no trailing slash except root
    pub fstype:     FsType,
    pub source:     String,   // device path or "none"
    pub flags:      u64,
    pub overlay:    Option<OverlayOpts>,
}

// ── FsHandle — returned to vfs_ops callers ───────────────────────────────────

/// Identifies which filesystem owns a path and the mount-relative sub-path.
#[derive(Clone, Debug)]
pub struct FsHandle {
    pub fstype:   FsType,
    pub subpath:  String,   // path relative to the mount point
    pub flags:    u64,
    pub overlay:  Option<OverlayOpts>,
}

impl FsHandle {
    pub fn is_readonly(&self) -> bool {
        self.flags & MS_RDONLY != 0
    }
}

// ── Global mount table ───────────────────────────────────────────────────────

pub struct MountTable {
    entries: Vec<MountEntry>,
}

impl MountTable {
    const fn new() -> Self {
        MountTable { entries: Vec::new() }
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Re-sort entries: longest mount-point first (most specific wins).
    fn sort(&mut self) {
        self.entries.sort_by(|a, b| b.mountpoint.len().cmp(&a.mountpoint.len()));
    }

    fn normalize(path: &str) -> String {
        let p = path.trim_end_matches('/');
        if p.is_empty() { "/".to_string() } else { p.to_string() }
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /// Add a mount entry (called from sys_mount and kernel init).
    pub fn mount(
        &mut self,
        source:     &str,
        target:     &str,
        fstype:     FsType,
        flags:      u64,
        overlay:    Option<OverlayOpts>,
    ) -> Result<(), isize> {
        let mp = Self::normalize(target);

        // MS_REMOUNT — update flags on existing entry.
        if flags & MS_REMOUNT != 0 {
            for e in &mut self.entries {
                if e.mountpoint == mp {
                    e.flags = flags & !MS_REMOUNT;
                    return Ok(());
                }
            }
            return Err(-22); // EINVAL — nothing mounted here
        }

        // Reject duplicate mount points (use MS_REMOUNT to update).
        if self.entries.iter().any(|e| e.mountpoint == mp) {
            return Err(-16); // EBUSY
        }

        self.entries.push(MountEntry {
            mountpoint: mp,
            fstype,
            source: source.to_string(),
            flags,
            overlay,
        });
        self.sort();
        Ok(())
    }

    /// Remove a mount entry.
    pub fn umount(&mut self, target: &str, flags: u32) -> Result<(), isize> {
        let mp = Self::normalize(target);
        // MNT_DETACH: mark busy mounts for lazy removal — we just remove immediately.
        let _ = flags;
        let before = self.entries.len();
        self.entries.retain(|e| e.mountpoint != mp);
        if self.entries.len() == before { Err(-22) } else { Ok(()) } // EINVAL
    }

    /// Resolve an absolute path to an `FsHandle` carrying the responsible
    /// filesystem type and the mount-relative sub-path.
    ///
    /// Returns `Err(-2)` (ENOENT) if no mount covers the path (should not
    /// happen once `/` is mounted).
    pub fn resolve(&self, path: &str) -> Result<FsHandle, isize> {
        let path = if path.starts_with('/') { path.to_string() }
                   else { alloc::format!("/\0") }; // relative path — treat as ENOENT
        for entry in &self.entries {
            let mp = &entry.mountpoint;
            let matches = if mp == "/" {
                path.starts_with('/')
            } else {
                path.starts_with(mp.as_str()) &&
                (path.len() == mp.len() ||
                 path.as_bytes().get(mp.len()) == Some(&b'/'))
            };
            if matches {
                let rel = if mp == "/" {
                    path.trim_start_matches('/').to_string()
                } else {
                    path[mp.len()..].trim_start_matches('/').to_string()
                };
                let subpath = if rel.is_empty() { "/".to_string() }
                              else { alloc::format!("/{}", rel) };
                return Ok(FsHandle {
                    fstype:  entry.fstype.clone(),
                    subpath,
                    flags:   entry.flags,
                    overlay: entry.overlay.clone(),
                });
            }
        }
        Err(-2) // ENOENT
    }

    /// Return a snapshot of all current mount entries (for /proc/mounts).
    pub fn list(&self) -> Vec<MountEntry> {
        self.entries.clone()
    }
}

// ── Global instance ──────────────────────────────────────────────────────────

static MOUNT_TABLE: Mutex<MountTable> = Mutex::new(MountTable::new());

/// Kernel-internal mount helper (called from arch init, not via syscall).
pub fn kernel_mount(
    source:  &str,
    target:  &str,
    fstype:  FsType,
    flags:   u64,
    overlay: Option<OverlayOpts>,
) -> Result<(), isize> {
    MOUNT_TABLE.lock().mount(source, target, fstype, flags, overlay)
}

/// Resolve a path to its owning filesystem handle.  Called by vfs_ops.
pub fn resolve(path: &str) -> Result<FsHandle, isize> {
    MOUNT_TABLE.lock().resolve(path)
}

/// Return the full mount list (for /proc/mounts rendering).
pub fn list_mounts() -> Vec<MountEntry> {
    MOUNT_TABLE.lock().list()
}

// ── Kernel boot mounts ───────────────────────────────────────────────────────

/// Called once from the kernel main entry point after the PMM is ready.
/// Registers the canonical set of virtual/pseudo filesystems so that path
/// resolution works before any userspace mount(2) is processed.
pub fn init_mounts() {
    let mut tbl = MOUNT_TABLE.lock();
    // Root ext2 (block device wired separately in ext2.rs)
    let _ = tbl.mount("sda",  "/",     FsType::Ext2,   0,            None);
    // EFI System Partition — FAT32 read-only by default; efi_rw() remounts rw
    let _ = tbl.mount("sda1", "/boot/efi", FsType::Fat32, MS_RDONLY,  None);
    // tmpfs mounts
    let _ = tbl.mount("tmpfs", "/tmp",     FsType::Tmpfs,  MS_NOSUID | MS_NODEV, None);
    let _ = tbl.mount("tmpfs", "/run",     FsType::Tmpfs,  MS_NOSUID | MS_NODEV, None);
    let _ = tbl.mount("tmpfs", "/dev/shm", FsType::Tmpfs,  MS_NOSUID | MS_NODEV, None);
    // Pseudo-filesystems
    let _ = tbl.mount("devtmpfs", "/dev",  FsType::Devfs,  MS_NOSUID,  None);
    let _ = tbl.mount("proc",     "/proc", FsType::Procfs, MS_NOSUID | MS_NODEV | MS_NOEXEC, None);
    let _ = tbl.mount("sysfs",    "/sys",  FsType::Sysfs,  MS_NOSUID | MS_NODEV | MS_NOEXEC, None);
    tbl.sort();
}

// ── sys_mount / sys_umount2 syscall handlers ─────────────────────────────────

/// sys_mount(source, target, fstype_str, flags, data_ptr)
/// `data_ptr` is ignored for all types except overlayfs, where it is expected
/// to be a comma-separated option string: `lowerdir=X,upperdir=Y,workdir=Z`.
pub fn sys_mount(
    source:   &str,
    target:   &str,
    fstype_s: &str,
    flags:    u64,
    data:     &str,
) -> isize {
    let fstype = match FsType::from_str(fstype_s) {
        Some(t) => t,
        None    => return -22, // EINVAL
    };

    // Parse overlayfs options from `data`.
    let overlay = if fstype == FsType::Overlayfs {
        let mut lower = String::new();
        let mut upper = String::new();
        let mut work  = String::new();
        for kv in data.split(',') {
            if let Some(v) = kv.strip_prefix("lowerdir=")  { lower = v.to_string(); }
            if let Some(v) = kv.strip_prefix("upperdir=")  { upper = v.to_string(); }
            if let Some(v) = kv.strip_prefix("workdir=")   { work  = v.to_string(); }
        }
        if lower.is_empty() { return -22; } // lowerdir is mandatory
        Some(OverlayOpts { lower, upper, work })
    } else {
        None
    };

    match MOUNT_TABLE.lock().mount(source, target, fstype, flags, overlay) {
        Ok(())   => 0,
        Err(e)   => e,
    }
}

/// sys_umount2(target, flags)
pub fn sys_umount2(target: &str, flags: u32) -> isize {
    match MOUNT_TABLE.lock().umount(target, flags) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}
