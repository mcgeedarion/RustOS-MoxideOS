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
//! | Ext2       | fs::ext2             | /  (rw, plain ext2/ext3)  |
//! | Ext4       | fs::ext4             | /  (ro, ext4 with extents)|
//! | Fat32      | fs::fat32            | /boot/efi, /mnt/usb       |
//! | ExFat      | fs::exfat            | /mnt/usb (exFAT drives)   |
//! | Ntfs       | fs::ntfs             | /mnt/win (ro)             |
//! | Cdfs       | fs::cdfs             | /mnt/cdrom (ISO 9660, ro) |
//! | Tmpfs      | fs::ramfs            | /tmp, /run, /dev/shm      |
//! | Overlayfs  | fs::overlayfs        | /overlay, container roots |
//! | Devfs      | fs::devfs            | /dev                      |
//! | Procfs     | fs::procfs           | /proc                     |
//! | Sysfs      | fs::sysfs            | /sys                      |
//! | Cgroupfs   | fs::cgroupfs         | /sys/fs/cgroup            |
//! | Btrfs      | fs::btrfs            | /  (rw, CoW B-tree)       |

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use spin::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub enum FsType {
    Ext2,
    Ext4,
    Fat32,
    ExFat,
    Ntfs,
    Cdfs,
    Tmpfs,
    Overlayfs,
    Devfs,
    Procfs,
    Sysfs,
    Cgroupfs,
    Btrfs,
}

impl FsType {
    /// Parse the kernel-facing filesystem name string (as passed to mount(2)).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ext2" | "ext3"           => Some(FsType::Ext2),
            "ext4"                    => Some(FsType::Ext4),
            "vfat" | "fat32" | "fat"  => Some(FsType::Fat32),
            "exfat"                   => Some(FsType::ExFat),
            "ntfs" | "ntfs-3g"        => Some(FsType::Ntfs),
            "iso9660" | "cdfs"        => Some(FsType::Cdfs),
            "tmpfs"                   => Some(FsType::Tmpfs),
            "overlay" | "overlayfs"   => Some(FsType::Overlayfs),
            "devtmpfs" | "devfs"      => Some(FsType::Devfs),
            "proc"                    => Some(FsType::Procfs),
            "sysfs"                   => Some(FsType::Sysfs),
            "cgroup2" | "cgroup"      => Some(FsType::Cgroupfs),
            "btrfs"                   => Some(FsType::Btrfs),
            _                         => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FsType::Ext2      => "ext2",
            FsType::Ext4      => "ext4",
            FsType::Fat32     => "vfat",
            FsType::ExFat     => "exfat",
            FsType::Ntfs      => "ntfs",
            FsType::Cdfs      => "iso9660",
            FsType::Tmpfs     => "tmpfs",
            FsType::Overlayfs => "overlay",
            FsType::Devfs     => "devtmpfs",
            FsType::Procfs    => "proc",
            FsType::Sysfs     => "sysfs",
            FsType::Cgroupfs  => "cgroup2",
            FsType::Btrfs     => "btrfs",
        }
    }
}

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

/// Extra parameters carried for overlayfs mounts.
#[derive(Clone, Debug)]
pub struct OverlayOpts {
    pub lower:   String,   // lower (read-only) directory
    pub upper:   String,   // upper (read-write) directory
    pub work:    String,   // work directory (must be on same fs as upper)
}

#[derive(Clone, Debug)]
pub struct MountEntry {
    pub mountpoint: String,   // absolute path, no trailing slash except root
    pub fstype:     FsType,
    pub source:     String,   // device path or "none"
    pub flags:      u64,
    pub overlay:    Option<OverlayOpts>,
}

/// Identifies which filesystem owns a path and the mount-relative sub-path.
#[derive(Clone, Debug)]
pub struct FsHandle {
    pub fstype:      FsType,
    pub subpath:     String,   // path relative to the mount point
    pub flags:       u64,
    pub overlay:     Option<OverlayOpts>,
    pub mount_point: String,   // the mount-point itself (for overlay lookup)
}

impl FsHandle {
    pub fn is_readonly(&self) -> bool {
        self.flags & MS_RDONLY != 0
    }
}

pub struct MountTable {
    entries: Vec<MountEntry>,
}

impl MountTable {
    const fn new() -> Self {
        MountTable { entries: Vec::new() }
    }

    fn sort(&mut self) {
        self.entries.sort_by(|a, b| b.mountpoint.len().cmp(&a.mountpoint.len()));
    }

    fn normalize(path: &str) -> String {
        let p = path.trim_end_matches('/');
        if p.is_empty() { "/".to_string() } else { p.to_string() }
    }

    pub fn mount(
        &mut self,
        source:     &str,
        target:     &str,
        fstype:     FsType,
        flags:      u64,
        overlay:    Option<OverlayOpts>,
    ) -> Result<(), isize> {
        let mp = Self::normalize(target);

        if flags & MS_REMOUNT != 0 {
            for e in &mut self.entries {
                if e.mountpoint == mp {
                    e.flags = flags & !MS_REMOUNT;
                    return Ok(());
                }
            }
            return Err(-22);
        }

        if self.entries.iter().any(|e| e.mountpoint == mp) {
            return Err(-16);
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

    pub fn umount(&mut self, target: &str, flags: u32) -> Result<(), isize> {
        let mp = Self::normalize(target);
        let _ = flags;
        let before = self.entries.len();
        self.entries.retain(|e| e.mountpoint != mp);
        if self.entries.len() == before { Err(-22) } else { Ok(()) }
    }

    pub fn resolve(&self, path: &str) -> Result<FsHandle, isize> {
        let path = if path.starts_with('/') { path.to_string() }
                   else { alloc::format!("/\0") };
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
                    fstype:      entry.fstype.clone(),
                    subpath,
                    flags:       entry.flags,
                    overlay:     entry.overlay.clone(),
                    mount_point: mp.clone(),
                });
            }
        }
        Err(-2)
    }

    pub fn list(&self) -> Vec<MountEntry> {
        self.entries.clone()
    }
}

static MOUNT_TABLE: Mutex<MountTable> = Mutex::new(MountTable::new());

pub fn kernel_mount(
    source:  &str,
    target:  &str,
    fstype:  FsType,
    flags:   u64,
    overlay: Option<OverlayOpts>,
) -> Result<(), isize> {
    MOUNT_TABLE.lock().mount(source, target, fstype, flags, overlay)
}

pub fn resolve(path: &str) -> Result<FsHandle, isize> {
    MOUNT_TABLE.lock().resolve(path)
}

pub fn list_mounts() -> Vec<MountEntry> {
    MOUNT_TABLE.lock().list()
}

/// Called once from the kernel main entry point after the PMM is ready.
/// Registers canonical virtual/pseudo filesystems and detects the root
/// block-device filesystem type automatically via fs_recognizer.
pub fn init_mounts() {
    let mut tbl = MOUNT_TABLE.lock();

    // Read the first 64 KiB of the root block device for FS detection.
    // This covers all magic locations including Btrfs (at 0x10040).
    let boot_sector = crate::block::read_blocks(0, 128); // 128 * 512 = 65536 bytes

    // Auto-detect root filesystem type.
    let root_fstype = boot_sector
        .as_deref()
        .and_then(|data| crate::fs::fs_recognizer::probe(data))
        .unwrap_or_else(|| {
            log::warn!("mount: fs_recognizer could not identify root FS; defaulting to ext2");
            FsType::Ext2
        });

    let root_flags = match root_fstype {
        FsType::Ntfs | FsType::Cdfs | FsType::Ext4 => MS_RDONLY,
        _ => 0,
    };

    log::info!("mount: root filesystem detected as '{}'",
        crate::fs::fs_recognizer::fs_type_name(&root_fstype));

    let _ = tbl.mount("sda", "/", root_fstype, root_flags, None);

    // EFI System Partition (FAT32, read-only by default).
    let _ = tbl.mount("sda1", "/boot/efi", FsType::Fat32, MS_RDONLY, None);

    // tmpfs mounts.
    let _ = tbl.mount("tmpfs", "/tmp",     FsType::Tmpfs, MS_NOSUID | MS_NODEV, None);
    let _ = tbl.mount("tmpfs", "/run",     FsType::Tmpfs, MS_NOSUID | MS_NODEV, None);
    let _ = tbl.mount("tmpfs", "/dev/shm", FsType::Tmpfs, MS_NOSUID | MS_NODEV, None);

    // Pseudo-filesystems.
    let _ = tbl.mount("devtmpfs", "/dev",  FsType::Devfs,  MS_NOSUID, None);
    let _ = tbl.mount("proc",     "/proc", FsType::Procfs, MS_NOSUID | MS_NODEV | MS_NOEXEC, None);
    let _ = tbl.mount("sysfs",    "/sys",  FsType::Sysfs,  MS_NOSUID | MS_NODEV | MS_NOEXEC, None);

    // cgroup v2 unified hierarchy.
    let _ = tbl.mount("cgroup2", "/sys/fs/cgroup", FsType::Cgroupfs,
                      MS_NOSUID | MS_NODEV | MS_NOEXEC, None);

    tbl.sort();
}

pub fn sys_mount(
    source:   &str,
    target:   &str,
    fstype_s: &str,
    flags:    u64,
    data:     &str,
) -> isize {
    // "auto" delegates to the recognizer: read first 64 KiB of the source device.
    let fstype = if fstype_s == "auto" {
        let boot_sector = crate::block::read_blocks(0, 128);
        boot_sector
            .as_deref()
            .and_then(|d| crate::fs::fs_recognizer::probe(d))
            .unwrap_or(FsType::Ext2)
    } else {
        match FsType::from_str(fstype_s) {
            Some(t) => t,
            None    => return -22,
        }
    };

    // NTFS and CDFS are always read-only.
    let flags = match fstype {
        FsType::Ntfs | FsType::Cdfs => flags | MS_RDONLY,
        _ => flags,
    };

    let overlay = if fstype == FsType::Overlayfs {
        let mut lower = String::new();
        let mut upper = String::new();
        let mut work  = String::new();
        for kv in data.split(',') {
            if let Some(v) = kv.strip_prefix("lowerdir=")  { lower = v.to_string(); }
            if let Some(v) = kv.strip_prefix("upperdir=")  { upper = v.to_string(); }
            if let Some(v) = kv.strip_prefix("workdir=")   { work  = v.to_string(); }
        }
        if lower.is_empty() { return -22; }
        Some(OverlayOpts { lower, upper, work })
    } else {
        None
    };

    match MOUNT_TABLE.lock().mount(source, target, fstype, flags, overlay.clone()) {
        Err(e) => return e,
        Ok(()) => {}
    }

    // For overlayfs: register the OverlayMount into OVERLAY_MOUNTS so that
    // vfs_ops::overlay_mount() can find it.  This was previously missing,
    // causing every vfs_ops call on an overlayfs path to return ENOENT.
    if let Some(opts) = overlay {
        let rc = crate::fs::vfs_ops::overlay_mount_at(target, opts);
        if rc.is_err() {
            // Roll back the mount table entry to keep the two tables consistent.
            let _ = MOUNT_TABLE.lock().umount(target, 0);
            return -12; // ENOMEM (shouldn't happen, but be safe)
        }
    }

    0
}

pub fn sys_umount2(target: &str, flags: u32) -> isize {
    match MOUNT_TABLE.lock().umount(target, flags) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}
