//! Anonymous pipe — sys_pipe2 / sys_pipe (NR 22 / NR 293).
//!
//! Each pipe is a fixed-size ring buffer shared between a read-end FD
//! and a write-end FD.  Both ends hold an Arc to the same Mutex<PipeBuf>.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::uaccess::copy_to_user;

// ── Pipe buffer ─────────────────────────────────────────────────────────────────

const PIPE_BUF_CAP: usize = 65536;

struct PipeBuf {
    data:       Vec<u8>,
    write_open: bool,
}

type SharedPipe = Arc<Mutex<PipeBuf>>;

// ── Pipe FD table ──────────────────────────────────────────────────────────────

#[derive(Clone)]
enum PipeEnd { Read, Write }

#[derive(Clone)]
struct PipeFd {
    buf: SharedPipe,
    end: PipeEnd,
}

const PIPE_TABLE_SIZE: usize = 64;
static PIPE_TABLE: Mutex<[Option<PipeFd>; PIPE_TABLE_SIZE]> =
    Mutex::new([const { None }; PIPE_TABLE_SIZE]);

pub const PIPE_FD_BASE: usize = 0x2000_0000;

fn alloc_pipe_fd(pfd: PipeFd) -> Option<usize> {
    let mut tbl = PIPE_TABLE.lock();
    for (i, slot) in tbl.iter_mut().enumerate() {
        if slot.is_none() { *slot = Some(pfd); return Some(PIPE_FD_BASE + i); }
    }
    None
}

// ── Public query helpers ─────────────────────────────────────────────────────────

pub fn is_pipe_fd(fdno: usize) -> bool {
    if fdno < PIPE_FD_BASE || fdno >= PIPE_FD_BASE + PIPE_TABLE_SIZE { return false; }
    PIPE_TABLE.lock()[fdno - PIPE_FD_BASE].is_some()
}

/// poll readiness for a pipe fd.
pub fn pipe_poll(fdno: usize, events: u32) -> u32 {
    use crate::fs::poll::{POLLIN, POLLOUT, POLLHUP, POLLNVAL, POLLRDNORM, POLLWRNORM};
    let idx = fdno - PIPE_FD_BASE;
    let pfd = { PIPE_TABLE.lock()[idx].clone() };
    let pfd = match pfd { Some(p) => p, None => return POLLNVAL };
    let inner = pfd.buf.lock();
    match pfd.end {
        PipeEnd::Read => {
            if !inner.write_open && inner.data.is_empty() {
                return POLLHUP;
            }
            let mut r = 0u32;
            if events & POLLIN != 0 && !inner.data.is_empty() {
                r |= POLLIN | POLLRDNORM;
            }
            r
        }
        PipeEnd::Write => {
            let mut r = 0u32;
            if events & POLLOUT != 0 && inner.data.len() < PIPE_BUF_CAP {
                r |= POLLOUT | POLLWRNORM;
            }
            r
        }
    }
}

pub fn pipe_read(fdno: usize, buf: &mut [u8]) -> isize {
    let idx = fdno - PIPE_FD_BASE;
    let pfd = { PIPE_TABLE.lock()[idx].clone() };
    let pfd = match pfd { Some(p) => p, None => return -9 };
    match pfd.end { PipeEnd::Write => return -9, PipeEnd::Read => {} }
    let mut spins = 0usize;
    loop {
        let mut inner = pfd.buf.lock();
        if !inner.data.is_empty() {
            let n = buf.len().min(inner.data.len());
            buf[..n].copy_from_slice(&inner.data[..n]);
            inner.data.drain(..n);
            return n as isize;
        }
        if !inner.write_open { return 0; }
        drop(inner);
        spins += 1;
        if spins > 5_000_000 { return -11; } // EAGAIN
        core::hint::spin_loop();
    }
}

pub fn pipe_write(fdno: usize, buf: &[u8]) -> isize {
    let idx = fdno - PIPE_FD_BASE;
    let pfd = { PIPE_TABLE.lock()[idx].clone() };
    let pfd = match pfd { Some(p) => p, None => return -9 };
    match pfd.end { PipeEnd::Read => return -9, PipeEnd::Write => {} }
    let mut inner = pfd.buf.lock();
    if inner.data.len() + buf.len() > PIPE_BUF_CAP { return -11; }
    inner.data.extend_from_slice(buf);
    buf.len() as isize
}

pub fn pipe_close(fdno: usize) -> bool {
    if fdno < PIPE_FD_BASE || fdno >= PIPE_FD_BASE + PIPE_TABLE_SIZE { return false; }
    let idx = fdno - PIPE_FD_BASE;
    let pfd = {
        let mut tbl = PIPE_TABLE.lock();
        let p = tbl[idx].clone();
        tbl[idx] = None;
        p
    };
    if let Some(p) = pfd {
        if let PipeEnd::Write = p.end { p.buf.lock().write_open = false; }
        true
    } else { false }
}

// ── sys_pipe / sys_pipe2 ───────────────────────────────────────────────────────

pub fn sys_pipe(pipefd_va: usize) -> isize { sys_pipe2(pipefd_va, 0) }

pub fn sys_pipe2(pipefd_va: usize, _flags: u32) -> isize {
    if !crate::uaccess::validate_user_ptr(pipefd_va, 8) { return -14; }

    let buf = Arc::new(Mutex::new(PipeBuf { data: Vec::new(), write_open: true }));
    let read_fd = match alloc_pipe_fd(PipeFd { buf: buf.clone(), end: PipeEnd::Read }) {
        Some(fd) => fd,
        None => return -24, // EMFILE
    };
    let write_fd = match alloc_pipe_fd(PipeFd { buf, end: PipeEnd::Write }) {
        Some(fd) => fd,
        None => { pipe_close(read_fd); return -24; }
    };

    // Write [read_fd, write_fd] as two i32 LE values via copy_to_user.
    // On failure, close both fds to avoid leaking them.
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&(read_fd  as i32).to_le_bytes());
    out[4..8].copy_from_slice(&(write_fd as i32).to_le_bytes());
    if copy_to_user(pipefd_va, &out).is_err() {
        pipe_close(read_fd);
        pipe_close(write_fd);
        return -14; // EFAULT
    }
    0
}
