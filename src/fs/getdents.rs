//! sys_getdents64 (NR 217) and legacy sys_getdents (NR 78).
//!
//! ## linux_dirent64 layout
//!   u64  d_ino      (offset 0)
//!   i64  d_off      (offset 8)
//!   u16  d_reclen   (offset 16, padded to 8-byte alignment)
//!   u8   d_type     (offset 18)
//!   char d_name[]   (offset 19, NUL-terminated)

extern crate alloc;
use alloc::vec::Vec;
use crate::uaccess::{copy_to_user, validate_user_ptr};

pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR:     u8 = 4;
pub const DT_REG:     u8 = 8;
pub const DT_LNK:     u8 = 10;

// Maximum name length we will encode; names longer than this are skipped.
// Keeps reclen inside u16 range: 19 + 65516 + 1 padded to 8 = 65536 = u16::MAX+1
// so we cap at 255 (matching Linux FILENAME_MAX for safety).
const MAX_NAME_LEN: usize = 255;

struct Dent {
    ino:   u64,
    name:  alloc::string::String,
    dtype: u8,
}

fn gather_entries(fdno: usize, path: &str) -> Vec<Dent> {
    let mut out = Vec::new();
    if let Some(ino) = crate::fs::ext2::stat(path) {
        if crate::fs::ext2::is_dir(path) {
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
    let prefix = if path == "/" { alloc::string::String::new() } else {
        alloc::format!("{}/", path.trim_end_matches('/'))
    };
    if let Some(entries) = crate::fs::vfs::list_dir(fdno) {
        for e in entries {
            let leaf = e.name.strip_prefix(&*prefix)
                .unwrap_or(&e.name)
                .to_string();
            if leaf.contains('/') { continue; }
            out.push(Dent {
                ino: 0,
                name: leaf,
                dtype: if e.is_dir { DT_DIR } else { DT_REG },
            });
        }
    }
    out
}

/// sys_getdents64(fd, dirp, count)  [NR 217]
pub fn sys_getdents64(fdno: usize, dirp: usize, count: usize) -> isize {
    if dirp == 0 || count < 24 { return -22; } // EINVAL
    if !validate_user_ptr(dirp, count) { return -14; } // EFAULT

    let path = crate::fs::vfs::fd_to_path(fdno);
    let path = path.as_deref().unwrap_or("/");
    let entries = gather_entries(fdno, path);
    if entries.is_empty() { return 0; }

    let mut written = 0usize;
    for e in &entries {
        let name_bytes = e.name.as_bytes();
        let name_len   = name_bytes.len();
        // Skip entries with names too long to fit in the dirent.
        if name_len > MAX_NAME_LEN { continue; }

        // reclen = fixed 19 bytes + name + NUL, padded to 8-byte alignment.
        let raw    = 19 + name_len + 1;
        let reclen = (raw + 7) & !7;
        // reclen must fit in u16 (guaranteed by MAX_NAME_LEN = 255).
        debug_assert!(reclen <= u16::MAX as usize);

        if written + reclen > count { break; }

        // Build the record into a kernel buffer, then copy_to_user.
        let mut rec = alloc::vec![0u8; reclen];
        rec[0..8].copy_from_slice(&e.ino.to_le_bytes());
        rec[8..16].copy_from_slice(&((written + reclen) as i64).to_le_bytes());
        rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        rec[18] = e.dtype;
        rec[19..19 + name_len].copy_from_slice(name_bytes);
        // rec[19 + name_len] = 0 already (vec zeroed); padding also zeroed.

        if copy_to_user(dirp + written, &rec).is_err() { return -14; }
        written += reclen;
    }
    written as isize
}

/// sys_getdents (legacy NR 78) — thin shim; nothing on x86-64 uses the old version.
pub fn sys_getdents(fdno: usize, dirp: usize, count: usize) -> isize {
    sys_getdents64(fdno, dirp, count)
}
