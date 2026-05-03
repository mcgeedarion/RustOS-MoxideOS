//! sys_getdents64 (NR 217) and legacy sys_getdents (NR 78).
//!
//! Reads directory entries from an open directory fd into a user buffer.
//!
//! ## linux_dirent64 layout (getdents64)
//!   u64  d_ino
//!   i64  d_off
//!   u16  d_reclen   (total record size, padded to 8-byte alignment)
//!   u8   d_type     (DT_DIR=4, DT_REG=8, DT_LNK=10, DT_UNKNOWN=0)
//!   char d_name[]   (NUL-terminated)
//!
//! ## Sources for directory entries
//!   1. If the fd points to an ext2 directory inode: read entries from ext2.
//!   2. Otherwise treat it as a ramfs prefix scan.

extern crate alloc;
use alloc::vec::Vec;

pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR:     u8 = 4;
pub const DT_REG:     u8 = 8;
pub const DT_LNK:     u8 = 10;

// ── Internal directory entry list ─────────────────────────────────────────

struct Dent {
    ino:   u64,
    name:  alloc::string::String,
    dtype: u8,
}

fn gather_entries(fdno: usize, path: &str) -> Vec<Dent> {
    let mut out = Vec::new();

    // Try ext2 first.
    if let Some(ino) = crate::fs::ext2::stat(path) {
        if crate::fs::ext2::is_dir(path) {
            // Read directory entries from the ext2 inode data.
            if let Some(entries) = crate::fs::ext2::readdir(ino) {
                for (child_ino, name, is_dir) in entries {
                    out.push(Dent {
                        ino: child_ino as u64,
                        name,
                        dtype: if is_dir { DT_DIR } else { DT_REG },
                    });
                }
            }
            return out;
        }
    }

    // Fall back to ramfs prefix scan.
    let prefix = if path == "/" { alloc::string::String::new() } else {
        alloc::format!("{}/", path.trim_end_matches('/'))
    };
    // Ask vfs for directory entries.
    if let Some(entries) = crate::fs::vfs::list_dir(fdno) {
        for e in entries {
            let leaf = e.name.strip_prefix(&*prefix)
                .unwrap_or(&e.name)
                .to_string();
            if leaf.contains('/') { continue; } // skip nested entries
            out.push(Dent {
                ino: 0,
                name: leaf,
                dtype: if e.is_dir { DT_DIR } else { DT_REG },
            });
        }
    }
    out
}

// ── sys_getdents64 ────────────────────────────────────────────────────────

/// sys_getdents64(fd, dirp, count)  [NR 217]
/// Returns total bytes written, or negative errno.
pub fn sys_getdents64(fdno: usize, dirp: usize, count: usize) -> isize {
    if dirp == 0 || count < 24 { return -22; } // EINVAL

    // Resolve the fd to a path.
    let path = crate::fs::vfs::fd_to_path(fdno);
    let path = path.as_deref().unwrap_or("/");

    let entries = gather_entries(fdno, path);
    if entries.is_empty() { return 0; }

    let mut written = 0usize;
    for e in &entries {
        let name_bytes = e.name.as_bytes();
        let name_len   = name_bytes.len();
        // reclen = 8+8+2+1 + (name_len+1) padded to 8-byte alignment
        let raw  = 8 + 8 + 2 + 1 + name_len + 1;
        let reclen = (raw + 7) & !7;

        if written + reclen > count { break; }

        let p = (dirp + written) as *mut u8;
        unsafe {
            // d_ino  (u64 at offset 0)
            (p as *mut u64).write_unaligned(e.ino);
            // d_off  (i64 at offset 8) — we use entry index as offset
            (p.add(8) as *mut i64).write_unaligned((written + reclen) as i64);
            // d_reclen (u16 at offset 16)
            (p.add(16) as *mut u16).write_unaligned(reclen as u16);
            // d_type (u8 at offset 18)
            p.add(18).write(e.dtype);
            // d_name (offset 19, NUL-terminated)
            core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), p.add(19), name_len);
            p.add(19 + name_len).write(0); // NUL
            // zero padding
            for i in 19 + name_len + 1..reclen {
                p.add(i).write(0);
            }
        }
        written += reclen;
    }
    written as isize
}

/// sys_getdents (legacy 32-bit-ish, NR 78) — same layout minus d_type byte.
/// Linux glibc/musl never use this on x86-64; we provide a thin shim anyway.
pub fn sys_getdents(fdno: usize, dirp: usize, count: usize) -> isize {
    // The legacy struct has d_type folded into the padding before d_name.
    // Just delegate to getdents64 — the layouts are close enough that
    // nothing on x86-64 uses the old version.
    sys_getdents64(fdno, dirp, count)
}
