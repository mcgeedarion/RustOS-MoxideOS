//! kmtest/fs — filesystem test suite
//!
//! Covers:
//!   open / read / write / close round-trip
//!   write then read-back integrity
//!   rename atomicity (src disappears, dst appears)
//!   unlink removes the file
//!   open O_CREAT | O_EXCL on existing file returns EEXIST
//!   stat reflects correct size after write
//!   lseek positions correctly; read at offset returns expected data

use crate::fs::{
    io_syscalls::{sys_close, sys_open, sys_read, sys_write},
    stat_syscalls::sys_lseek,
    stat_syscalls::{sys_rename, sys_stat, sys_unlink},
};
use kmtest::{register, KmTestResult};

// O_* and S_* flag literals (matching Linux ABI).
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const S_IRUSR: u32 = 0o400;
const S_IWUSR: u32 = 0o200;
const S_MODE: u32 = S_IRUSR | S_IWUSR;
const SEEK_SET: i32 = 0;
const SEEK_END: i32 = 2;

// Test scratch paths — in tmpfs so they don't persist across reboots.
const PATH_A: &[u8] = b"/tmp/kmtest_fs_a\0";
const PATH_B: &[u8] = b"/tmp/kmtest_fs_b\0";

fn path(p: &[u8]) -> usize {
    p.as_ptr() as usize
}

/// Open (create), write, close, re-open (read), read back, compare.
fn fs_write_read_roundtrip() -> KmTestResult {
    let data = b"hello kmtest";
    let fd = sys_open(path(PATH_A), O_WRONLY | O_CREAT | O_TRUNC, S_MODE);
    if fd < 0 {
        return Err("open for write failed");
    }
    let n = sys_write(fd as usize, data.as_ptr() as usize, data.len());
    if n != data.len() as isize {
        sys_close(fd as usize);
        return Err("write returned wrong count");
    }
    sys_close(fd as usize);

    let fd2 = sys_open(path(PATH_A), O_RDONLY, 0);
    if fd2 < 0 {
        return Err("open for read failed");
    }
    let mut buf = [0u8; 32];
    let r = sys_read(fd2 as usize, buf.as_mut_ptr() as usize, buf.len());
    sys_close(fd2 as usize);
    if r != data.len() as isize {
        return Err("read returned wrong count");
    }
    if &buf[..data.len()] != data {
        return Err("read data does not match written data");
    }
    let _ = sys_unlink(path(PATH_A));
    Ok(())
}

/// O_CREAT | O_EXCL on an already-existing file must return -EEXIST.
fn fs_excl_existing() -> KmTestResult {
    // Ensure file exists.
    let fd = sys_open(path(PATH_A), O_WRONLY | O_CREAT | O_TRUNC, S_MODE);
    if fd < 0 {
        return Err("setup open failed");
    }
    sys_close(fd as usize);

    let fd2 = sys_open(path(PATH_A), O_WRONLY | O_CREAT | O_EXCL, S_MODE);
    let _ = sys_unlink(path(PATH_A));
    if fd2 >= 0 {
        sys_close(fd2 as usize);
        return Err("O_EXCL on existing file should have failed");
    }
    // -EEXIST = -17
    if fd2 != -17 {
        return Err("O_EXCL returned wrong errno (expected EEXIST)");
    }
    Ok(())
}

/// rename: src disappears, dst appears with original content.
fn fs_rename_atomic() -> KmTestResult {
    let data = b"rename_test";
    let fd = sys_open(path(PATH_A), O_WRONLY | O_CREAT | O_TRUNC, S_MODE);
    if fd < 0 {
        return Err("rename setup open failed");
    }
    sys_write(fd as usize, data.as_ptr() as usize, data.len());
    sys_close(fd as usize);

    let r = sys_rename(path(PATH_A), path(PATH_B));
    if r != 0 {
        return Err("rename failed");
    }

    // src must be gone.
    let fd_src = sys_open(path(PATH_A), O_RDONLY, 0);
    if fd_src >= 0 {
        sys_close(fd_src as usize);
        let _ = sys_unlink(path(PATH_B));
        return Err("source still exists after rename");
    }

    // dst must have the data.
    let fd_dst = sys_open(path(PATH_B), O_RDONLY, 0);
    if fd_dst < 0 {
        return Err("destination missing after rename");
    }
    let mut buf = [0u8; 32];
    let n = sys_read(fd_dst as usize, buf.as_mut_ptr() as usize, buf.len());
    sys_close(fd_dst as usize);
    let _ = sys_unlink(path(PATH_B));
    if n != data.len() as isize || &buf[..data.len()] != data {
        return Err("data corrupted across rename");
    }
    Ok(())
}

/// unlink removes the file; subsequent open returns -ENOENT.
fn fs_unlink_removes() -> KmTestResult {
    let fd = sys_open(path(PATH_A), O_WRONLY | O_CREAT | O_TRUNC, S_MODE);
    if fd < 0 {
        return Err("unlink setup failed");
    }
    sys_close(fd as usize);

    let r = sys_unlink(path(PATH_A));
    if r != 0 {
        return Err("unlink failed");
    }

    let fd2 = sys_open(path(PATH_A), O_RDONLY, 0);
    if fd2 >= 0 {
        sys_close(fd2 as usize);
        return Err("file still openable after unlink");
    }
    Ok(())
}

/// stat reflects correct st_size after a write.
fn fs_stat_size() -> KmTestResult {
    let data = b"size_test_data";
    let fd = sys_open(path(PATH_A), O_WRONLY | O_CREAT | O_TRUNC, S_MODE);
    if fd < 0 {
        return Err("stat size open failed");
    }
    sys_write(fd as usize, data.as_ptr() as usize, data.len());
    sys_close(fd as usize);

    // stat uses a 144-byte kernel stat64 struct; st_size is at offset 48.
    let mut st = [0u8; 144];
    let r = sys_stat(path(PATH_A), st.as_mut_ptr() as usize);
    let _ = sys_unlink(path(PATH_A));
    if r != 0 {
        return Err("stat failed");
    }
    let size = i64::from_ne_bytes(st[48..56].try_into().unwrap());
    if size != data.len() as i64 {
        return Err("stat st_size does not match written length");
    }
    Ok(())
}

/// lseek(SEEK_END) then write appends; lseek(SEEK_SET,0) then read recovers
/// all.
fn fs_lseek_append_read() -> KmTestResult {
    let first = b"hello";
    let second = b"world";
    let fd = sys_open(path(PATH_A), O_RDWR | O_CREAT | O_TRUNC, S_MODE);
    if fd < 0 {
        return Err("lseek open failed");
    }
    sys_write(fd as usize, first.as_ptr() as usize, first.len());
    // Seek to end and append.
    let pos = sys_lseek(fd as usize, 0, SEEK_END);
    if pos < 0 {
        sys_close(fd as usize);
        return Err("lseek SEEK_END failed");
    }
    sys_write(fd as usize, second.as_ptr() as usize, second.len());
    // Seek back to start.
    let p2 = sys_lseek(fd as usize, 0, SEEK_SET);
    if p2 != 0 {
        sys_close(fd as usize);
        return Err("lseek SEEK_SET failed");
    }
    let mut buf = [0u8; 16];
    let n = sys_read(fd as usize, buf.as_mut_ptr() as usize, buf.len());
    sys_close(fd as usize);
    let _ = sys_unlink(path(PATH_A));
    let expected_len = (first.len() + second.len()) as isize;
    if n != expected_len {
        return Err("lseek append+read: wrong byte count");
    }
    if &buf[..first.len()] != first {
        return Err("first chunk corrupted after lseek");
    }
    if &buf[first.len()..first.len() + second.len()] != second {
        return Err("second chunk corrupted after lseek");
    }
    Ok(())
}

pub fn register() {
    register!("fs_write_read_roundtrip", fs_write_read_roundtrip);
    register!("fs_excl_existing", fs_excl_existing);
    register!("fs_rename_atomic", fs_rename_atomic);
    register!("fs_unlink_removes", fs_unlink_removes);
    register!("fs_stat_size", fs_stat_size);
    register!("fs_lseek_append_read", fs_lseek_append_read);
}
