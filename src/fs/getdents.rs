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
const MAX_NAME_LEN: usize = 255;

struct Dent {
    ino:   u64,
    name:  alloc::string::String,
    dtype: u8,
}

/// Parse a "/proc/<N>/..." prefix from `path` and return (pid, rest_after_prefix).
/// Returns None if the path doesn't match /proc/<decimal>/.
fn strip_proc_pid(path: &str) -> Option<(usize, &str)> {
    let rest = path.strip_prefix("/proc/")?;
    let slash = rest.find('/').unwrap_or(rest.len());
    let pid: usize = rest[..slash].parse().ok()?;
    Some((pid, &rest[slash..]))
}

fn gather_entries(fdno: usize, path: &str) -> Vec<Dent> {
    let mut out = Vec::new();

    // Synthesise 7 symlink dirents for `ls /proc/self/ns/`.
    if let Some((pid, rest)) = strip_proc_pid(path) {
        if rest == "/ns" || rest == "/ns/" {
            for name in crate::fs::procfs::NS_NAMES {
                let ns_id = crate::proc::namespace::ns_id_of(pid, name)
                    .unwrap_or(crate::proc::namespace::INIT_NS);
                out.push(Dent {
                    ino:   ns_id,
                    name:  alloc::string::String::from(*name),
                    dtype: DT_LNK,
                });
            }
            return out;
        }
    }

    // Emit a minimal set of well-known entries so that `ls /proc/self/`
    // returns something useful.
    if let Some((_pid, "")) = strip_proc_pid(path) {
        for name in &["ns", "fd", "exe", "maps", "stat", "status", "limits", "cmdline"] {
            out.push(Dent {
                ino:   0,
                name:  alloc::string::String::from(*name),
                dtype: if *name == "ns" || *name == "fd" { DT_DIR } else { DT_LNK },
            });
        }
        return out;
    }

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
        if name_len > MAX_NAME_LEN { continue; }

        let raw    = 19 + name_len + 1;
        let reclen = (raw + 7) & !7;
        debug_assert!(reclen <= u16::MAX as usize);

        if written + reclen > count { break; }

        let mut rec = alloc::vec![0u8; reclen];
        rec[0..8].copy_from_slice(&e.ino.to_le_bytes());
        rec[8..16].copy_from_slice(&((written + reclen) as i64).to_le_bytes());
        rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        rec[18] = e.dtype;
        rec[19..19 + name_len].copy_from_slice(name_bytes);

        if copy_to_user(dirp + written, &rec).is_err() { return -14; }
        written += reclen;
    }
    written as isize
}

/// sys_getdents (legacy NR 78) — thin shim.
pub fn sys_getdents(fdno: usize, dirp: usize, count: usize) -> isize {
    sys_getdents64(fdno, dirp, count)
}
