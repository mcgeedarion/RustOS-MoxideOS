//! Mount namespace.
//!
//! A mount namespace holds an independent copy of the VFS mount table.
//! `copy_of()` performs a shallow clone of the parent's mount list
//! (bind-mount semantics).  Individual mounts can then be added/removed
//! without affecting the parent.
//!
//! ## Linux syscall semantics modelled
//!
//!   clone(CLONE_NEWNS) / unshare(CLONE_NEWNS)
//!   mount(2)  — adds a MountEntry to the current ns
//!   umount(2) — removes a MountEntry
//!   /proc/self/mounts  — enumerate via `mount_list()`
//!   pivot_root(2)      — stub (swaps root and put_old)

extern crate alloc;
use alloc::{string::String, vec::Vec, sync::Arc};
use spin::Mutex;
use crate::security::ns::alloc_ns_id;

/// A single mount-point record.
#[derive(Clone, Debug)]
pub struct MountEntry {
    /// Device string ("devtmpfs", "/dev/sda1", etc.)
    pub device:    String,
    /// Absolute mountpoint path.
    pub mountpt:   String,
    /// Filesystem type string.
    pub fstype:    String,
    /// Mount flags (MS_RDONLY etc. matching Linux UAPI).
    pub flags:     u64,
    /// Propagation peer group id (0 = private).
    pub peer_grp:  u32,
}

/// MS_* mount flag constants (UAPI).
pub mod ms {
    pub const RDONLY:     u64 = 1;
    pub const NOSUID:     u64 = 2;
    pub const NODEV:      u64 = 4;
    pub const NOEXEC:     u64 = 8;
    pub const SYNCHRONOUS:u64 = 16;
    pub const REMOUNT:    u64 = 32;
    pub const MANDLOCK:   u64 = 64;
    pub const NOATIME:    u64 = 1024;
    pub const BIND:       u64 = 4096;
    pub const SHARED:     u64 = 1 << 20;
    pub const PRIVATE:    u64 = 1 << 18;
    pub const SLAVE:      u64 = 1 << 19;
    pub const UNBINDABLE: u64 = 1 << 17;
}

pub struct MntNs {
    pub id:     u64,
    mounts:     Mutex<Vec<MountEntry>>,
}

impl MntNs {
    /// Initial mount namespace — populated with the kernel's root mount.
    pub fn new_init() -> Self {
        let mut mounts = Vec::new();
        mounts.push(MountEntry {
            device:   String::from("rootfs"),
            mountpt:  String::from("/"),
            fstype:   String::from("rootfs"),
            flags:    0,
            peer_grp: 1,
        });
        MntNs { id: alloc_ns_id(), mounts: Mutex::new(mounts) }
    }

    /// Shallow clone of `parent`'s mount list (CLONE_NEWNS semantics).
    pub fn copy_of(parent: &Arc<MntNs>) -> Self {
        let list = parent.mounts.lock().clone();
        MntNs { id: alloc_ns_id(), mounts: Mutex::new(list) }
    }

    /// Add a mount entry (mount(2)).
    /// Returns EBUSY if `mountpt` is already occupied and REMOUNT not set.
    pub fn mount(
        &self,
        device: String, mountpt: String, fstype: String, flags: u64,
    ) -> Result<(), isize> {
        let mut list = self.mounts.lock();
        if flags & ms::REMOUNT != 0 {
            if let Some(e) = list.iter_mut().find(|e| e.mountpt == mountpt) {
                e.flags = flags & !ms::REMOUNT;
                return Ok(());
            }
            return Err(-2); // ENOENT
        }
        if list.iter().any(|e| e.mountpt == mountpt) { return Err(-16); } // EBUSY
        list.push(MountEntry { device, mountpt, fstype, flags, peer_grp: 0 });
        Ok(())
    }

    /// Remove a mount entry (umount2(2)).
    pub fn umount(&self, mountpt: &str, _flags: u64) -> Result<(), isize> {
        let mut list = self.mounts.lock();
        let pos = list.iter().position(|e| e.mountpt == mountpt)
            .ok_or(-22isize)?; // EINVAL
        // Refuse to unmount root.
        if list[pos].mountpt == "/" { return Err(-16); } // EBUSY
        list.remove(pos);
        Ok(())
    }

    /// Read-only snapshot of all mounts (for /proc/self/mounts).
    pub fn mount_list(&self) -> Vec<MountEntry> {
        self.mounts.lock().clone()
    }

    /// pivot_root stub: swap root and put_old mountpoints.
    pub fn pivot_root(&self, new_root: &str, put_old: &str) -> Result<(), isize> {
        let mut list = self.mounts.lock();
        let nr = list.iter_mut().find(|e| e.mountpt == new_root)
            .ok_or(-2isize)?;
        let new_device = nr.device.clone();
        let new_fstype = nr.fstype.clone();
        let new_flags  = nr.flags;
        // Move old root to put_old.
        if let Some(old) = list.iter_mut().find(|e| e.mountpt == "/") {
            old.mountpt = String::from(put_old);
        }
        // Promote new_root to /.
        if let Some(e) = list.iter_mut().find(|e| e.mountpt == new_root) {
            e.mountpt = String::from("/");
        }
        let _ = (new_device, new_fstype, new_flags);
        Ok(())
    }

    /// Check if `path` resolves under any mount (simple prefix match).
    pub fn lookup(&self, path: &str) -> Option<MountEntry> {
        let list = self.mounts.lock();
        list.iter()
            .filter(|e| path.starts_with(e.mountpt.as_str()))
            .max_by_key(|e| e.mountpt.len())
            .cloned()
    }
}
