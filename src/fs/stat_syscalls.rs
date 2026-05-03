//! fstat and lseek syscall wrappers.
//!
//! ## sys_fstat [NR 5]
//!   Fills a Linux x86-64 `struct stat` (144 bytes) at `statbuf_va`.
//!   Only the fields musl stdio / libc require are populated; the rest
//!   are zeroed.  Sufficient for fopen/fread/fwrite/fclose and stat(2).
//!
//!   x86-64 struct stat layout (offsets in bytes):
//!     0   st_dev      u64
//!     8   st_ino      u64
//!     16  st_nlink    u64
//!     24  st_mode     u32   (S_IFREG | 0644)
//!     28  st_uid      u32
//!     32  st_gid      u32
//!     36  __pad0      u32
//!     40  st_rdev     u64
//!     48  st_size     i64   ← file size in bytes
//!     56  st_blksize  i64   ← preferred I/O block size
//!     64  st_blocks   i64   ← 512-byte block count
//!     72  st_atim     u64,u64
//!     88  st_mtim     u64,u64
//!     104 st_ctim     u64,u64
//!     120 __unused[3] u64×3
//!   total: 144 bytes
//!
//! ## sys_lseek [NR 8]
//!   Thin wrapper over vfs::seek(fd, offset, whence).
//!   whence: SEEK_SET=0, SEEK_CUR=1, SEEK_END=2.

use crate::fs::vfs;

/// sizeof(struct stat) on x86-64 Linux.
const STAT_SIZE: usize = 144;

/// S_IFREG | 0644 = regular file, owner rw, group/other r.
const S_IFREG_0644: u32 = 0o10_0644;

/// Preferred I/O block size reported to userspace.
const BLKSIZE: i64 = 4096;

// ── sys_fstat [NR 5] ────────────────────────────────────────────────────────────

/// sys_fstat(fd, statbuf_va) → 0 / -errno
pub fn sys_fstat(fd: usize, statbuf_va: usize) -> isize {
    if statbuf_va < 0x1000
        || statbuf_va.saturating_add(STAT_SIZE) > 0x0000_8000_0000_0000
    {
        return -14; // EFAULT
    }

    let size = match vfs::fstat(fd) {
        Some(s) => s as i64,
        None    => return -9, // EBADF
    };

    // Zero the entire 144-byte buffer first.
    unsafe { core::ptr::write_bytes(statbuf_va as *mut u8, 0, STAT_SIZE); }

    unsafe {
        let base = statbuf_va as *mut u8;
        // st_nlink  @ 16
        (base.add(16) as *mut u64).write_unaligned(1u64);
        // st_mode   @ 24
        (base.add(24) as *mut u32).write_unaligned(S_IFREG_0644);
        // st_size   @ 48
        (base.add(48) as *mut i64).write_unaligned(size);
        // st_blksize@ 56
        (base.add(56) as *mut i64).write_unaligned(BLKSIZE);
        // st_blocks @ 64  (512-byte units, rounded up)
        let blocks = (size + 511) / 512;
        (base.add(64) as *mut i64).write_unaligned(blocks);
    }

    0
}

// ── sys_lseek [NR 8] ───────────────────────────────────────────────────────────

/// sys_lseek(fd, offset, whence) → new_offset / -errno
pub fn sys_lseek(fd: usize, offset: i64, whence: i32) -> isize {
    vfs::seek(fd, offset, whence)
}
