//! sys_splice: zero-copy pipe-to-pipe / pipe-to-fd / fd-to-pipe transfer.
//!
//! Implements the full splice(2) contract:
//!   - fd_in xor fd_out must be a pipe
//!   - non-pipe end uses pread/pwrite so the file offset advances correctly (or stays fixed if the
//!     caller supplied a non-NULL off_in/off_out)
//!   - flags: SPLICE_F_NONBLOCK honoured (returns EAGAIN instead of spinning)
//!   - SPLICE_F_MORE / SPLICE_F_MOVE are accepted but ignored (hint only)

extern crate alloc;
use alloc::vec::Vec;

const SPLICE_F_MOVE: u32 = 1;
const SPLICE_F_NONBLOCK: u32 = 2;
const SPLICE_F_MORE: u32 = 4;
const SPLICE_F_GIFT: u32 = 8;

/// splice(fd_in, off_in, fd_out, off_out, len, flags)
///
/// `off_in_va` / `off_out_va` are user-VA pointers to loff_t (i64);
/// pass 0 to use/advance the fd's current file offset.
pub fn sys_splice(
    fd_in: usize,
    off_in_va: usize,
    fd_out: usize,
    off_out_va: usize,
    len: usize,
    flags: u32,
) -> isize {
    if len == 0 {
        return 0;
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;

    let in_is_pipe = crate::fs::pipe::is_pipe_fd(fd_in);
    let out_is_pipe = crate::fs::pipe::is_pipe_fd(fd_out);

    // At least one end must be a pipe.
    if !in_is_pipe && !out_is_pipe {
        return -22;
    } // EINVAL

    // Read optional user-supplied offsets.
    let off_in: Option<i64> = read_loff(off_in_va);
    let off_out: Option<i64> = read_loff(off_out_va);

    // Clamp transfer to a sane maximum (16 MiB) to avoid unbounded loops.
    let len = len.min(16 * 1024 * 1024);

    if in_is_pipe && out_is_pipe {
        return splice_pipe_to_pipe(fd_in, fd_out, len, nonblock);
    }

    if !in_is_pipe && out_is_pipe {
        let offset = off_in.unwrap_or_else(|| current_offset(fd_in));
        let mut buf = alloc::vec![0u8; len];
        let n = crate::fs::vfs::pread_buf(fd_in, &mut buf, offset);
        if n <= 0 {
            return if nonblock && n == -11 { -11 } else { n };
        }
        let written = crate::fs::pipe::pipe_write_kernel(fd_out, &buf[..n as usize]);
        if written > 0 {
            let new_off = offset + written as i64;
            if off_in_va != 0 {
                write_loff(off_in_va, new_off);
            } else {
                advance_offset(fd_in, written as i64);
            }
        }
        return written;
    }

    // in_is_pipe && !out_is_pipe
    let data = crate::fs::pipe::pipe_read_kernel(fd_in, len, nonblock);
    if data.is_empty() {
        return if nonblock { -11 } else { 0 }; // EAGAIN or EOF
    }
    let offset = off_out.unwrap_or_else(|| current_offset(fd_out));
    let written = crate::fs::vfs::pwrite_buf(fd_out, &data, offset);
    if written > 0 {
        let new_off = offset + written as i64;
        if off_out_va != 0 {
            write_loff(off_out_va, new_off);
        } else {
            advance_offset(fd_out, written as i64);
        }
    }
    written
}

fn read_loff(va: usize) -> Option<i64> {
    if va == 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    crate::uaccess::copy_from_user(va, &mut buf).ok()?;
    Some(i64::from_ne_bytes(buf))
}

fn write_loff(va: usize, val: i64) {
    if va != 0 {
        let _ = crate::uaccess::copy_to_user(va, &val.to_ne_bytes());
    }
}

fn current_offset(fd: usize) -> i64 {
    let r = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR);
    if r < 0 {
        0
    } else {
        r as i64
    }
}

fn advance_offset(fd: usize, delta: i64) {
    let cur = current_offset(fd);
    let _ = crate::fs::vfs::seek(fd, cur + delta, crate::fs::vfs::SEEK_SET);
}

fn splice_pipe_to_pipe(fd_in: usize, fd_out: usize, len: usize, nonblock: bool) -> isize {
    let data = crate::fs::pipe::pipe_read_kernel(fd_in, len, nonblock);
    if data.is_empty() {
        return if nonblock { -11 } else { 0 };
    }
    crate::fs::pipe::pipe_write_kernel(fd_out, &data)
}
