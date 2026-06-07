//! VFS helper functions that extend the core VFS 
//!

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex as SpinMutex;

/// Update the atime and/or mtime of the file at `path`.
pub fn set_times(path: &str, atime_ns: Option<u64>, mtime_ns: Option<u64>) {
    crate::fs::vfs::with_inode_mut(path, |inode| {
        if let Some(a) = atime_ns {
            inode.atime_ns = a;
        }
        if let Some(m) = mtime_ns {
            inode.mtime_ns = m;
        }
    });
}

/// Flush every dirty buffer in the VFS page cache to persistent storage.
pub fn sync_all() {
    crate::fs::vfs::flush_all_dirty();
}

/// Flush the file backing `fd` to storage (fsync semantics: metadata + data).
pub fn fsync_fd(fd: usize) -> isize {
    crate::fs::vfs::flush_fd(fd, true /* include_metadata */)
}

/// Flush only the data pages of `fd` (fdatasync semantics).
pub fn fdatasync_fd(fd: usize) -> isize {
    crate::fs::vfs::flush_fd(fd, false /* data only */)
}

/// Lock operations for flock(2).
#[repr(u8)]
#[allow(dead_code)]
enum FlockOp {
    SharedLock = 1,
    ExclusiveLock = 2,
    Unlock = 8,
    NonBlock = 4,
}

/// Advisory lock entry: (inode_id) → (holder_fd, shared_count, exclusive)
#[derive(Clone, Default)]
struct AdvisoryLock {
    /// Number of fds holding a shared (LOCK_SH) lock.
    shared_count: u32,
    /// fd holding an exclusive (LOCK_EX) lock, or 0 if none.
    exclusive_fd: usize,
}

static FLOCK_TABLE: SpinMutex<BTreeMap<u64 /* inode_id */, AdvisoryLock>> =
    SpinMutex::new(BTreeMap::new());

/// Implements `flock(fd, operation)`.
pub fn sys_flock(fd: usize, operation: i32) -> isize {
    const LOCK_SH: i32 = 1;
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    const LOCK_UN: i32 = 8;

    let op_bits = operation & !(LOCK_NB);
    let nonblock = (operation & LOCK_NB) != 0;

    // Resolve fd → inode id.
    let inode_id = match crate::fs::vfs::inode_id_of_fd(fd) {
        Some(id) => id,
        None => return -9, // EBADF
    };

    let mut table = FLOCK_TABLE.lock();
    let entry = table.entry(inode_id).or_default();

    match op_bits {
        x if x == LOCK_UN => {
            // Release whatever lock this fd holds.
            if entry.exclusive_fd == fd {
                entry.exclusive_fd = 0;
            } else if entry.shared_count > 0 {
                entry.shared_count -= 1;
            }
            0
        },
        x if x == LOCK_SH => {
            // Shared lock: allowed unless an exclusive lock is held.
            if entry.exclusive_fd != 0 && entry.exclusive_fd != fd {
                if nonblock {
                    return -11;
                } // EWOULDBLOCK
                  // Blocking: spin-wait (advisory only, simple implementation).
                drop(table);
                while crate::fs::vfs::inode_id_of_fd(fd)
                    .map(|id| {
                        FLOCK_TABLE
                            .lock()
                            .get(&id)
                            .map(|e| e.exclusive_fd != 0 && e.exclusive_fd != fd)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
                {
                    crate::proc::scheduler::schedule();
                }
                table = FLOCK_TABLE.lock();
                let e2 = table.entry(inode_id).or_default();
                e2.shared_count += 1;
            } else {
                entry.shared_count += 1;
            }
            0
        },
        x if x == LOCK_EX => {
            // Exclusive: allowed only when no other lock is held.
            let blocked =
                entry.exclusive_fd != 0 && entry.exclusive_fd != fd || entry.shared_count > 0;
            if blocked {
                if nonblock {
                    return -11;
                }
                drop(table);
                loop {
                    let free = crate::fs::vfs::inode_id_of_fd(fd)
                        .map(|id| {
                            let t = FLOCK_TABLE.lock();
                            t.get(&id)
                                .map(|e| {
                                    (e.exclusive_fd == 0 || e.exclusive_fd == fd)
                                        && e.shared_count == 0
                                })
                                .unwrap_or(true)
                        })
                        .unwrap_or(true);
                    if free {
                        break;
                    }
                    crate::proc::scheduler::schedule();
                }
                table = FLOCK_TABLE.lock();
                let e2 = table.entry(inode_id).or_default();
                e2.exclusive_fd = fd;
            } else {
                entry.exclusive_fd = fd;
            }
            0
        },
        _ => -22, // EINVAL
    }
}

/// Release all flock advisory locks held by `fd` (called on close).
pub fn flock_release_fd(fd: usize) {
    let mut table = FLOCK_TABLE.lock();
    let inode_id = match crate::fs::vfs::inode_id_of_fd(fd) {
        Some(id) => id,
        None => return,
    };
    if let Some(entry) = table.get_mut(&inode_id) {
        if entry.exclusive_fd == fd {
            entry.exclusive_fd = 0;
        }
        if entry.shared_count > 0 {
            entry.shared_count -= 1;
        }
    }
}

/// NR 221  posix_fadvise(fd, offset, len, advice)
pub fn sys_posix_fadvise(_fd: usize, _offset: i64, _len: i64, advice: i32) -> isize {
    const POSIX_FADV_NORMAL: i32 = 0;
    const POSIX_FADV_SEQUENTIAL: i32 = 2;
    const POSIX_FADV_RANDOM: i32 = 1;
    const POSIX_FADV_NOREUSE: i32 = 5;
    const POSIX_FADV_WILLNEED: i32 = 3;
    const POSIX_FADV_DONTNEED: i32 = 4;
    match advice {
        POSIX_FADV_NORMAL
        | POSIX_FADV_SEQUENTIAL
        | POSIX_FADV_RANDOM
        | POSIX_FADV_NOREUSE
        | POSIX_FADV_WILLNEED
        | POSIX_FADV_DONTNEED => 0,
        _ => -22, // EINVAL
    }
}
