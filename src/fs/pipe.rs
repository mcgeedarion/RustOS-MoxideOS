//! Anonymous pipe — sys_pipe2 / sys_pipe (NR 22 / NR 293).
//!
//! Each pipe is a fixed-size ring buffer shared between a read-end FD
//! and a write-end FD.  Both ends hold an Arc to the same Mutex<PipeBuf>.
//!
//! ## Ring buffer layout
//!   `data` is a fixed [u8; PIPE_BUF_CAP] array.
//!   `head` is the index of the next byte to read.
//!   `len`  is the number of valid bytes in the buffer.
//!   Write wraps around at PIPE_BUF_CAP.  No heap allocation after init.

extern crate alloc;
use alloc::sync::Arc;
use alloc::boxed::Box;
use spin::Mutex;
use crate::uaccess::copy_to_user;

// ── Pipe buffer ─────────────────────────────────────────────────────────────────────────────

pub const PIPE_BUF_CAP: usize = 65536;

struct PipeBuf {
    data:       Box<[u8; PIPE_BUF_CAP]>,
    head:       usize,  // index of next byte to read
    len:        usize,  // bytes currently in buffer
    write_open: bool,
}

impl PipeBuf {
    fn new() -> Self {
        PipeBuf {
            data:       Box::new([0u8; PIPE_BUF_CAP]),
            head:       0,
            len:        0,
            write_open: true,
        }
    }

    /// Read up to `buf.len()` bytes from the ring. Returns bytes read.
    fn read_into(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.len);
        if n == 0 { return 0; }
        let tail = (self.head + n).min(PIPE_BUF_CAP);
        let first = tail - self.head;
        buf[..first].copy_from_slice(&self.data[self.head..tail]);
        if first < n {
            // Wrap around
            buf[first..n].copy_from_slice(&self.data[..n - first]);
        }
        self.head = (self.head + n) % PIPE_BUF_CAP;
        self.len -= n;
        n
    }

    /// Write `buf` into the ring. Returns bytes written (may be less than
    /// buf.len() if the buffer would overflow — callers check capacity first).
    fn write_from(&mut self, buf: &[u8]) -> usize {
        let free = PIPE_BUF_CAP - self.len;
        let n = buf.len().min(free);
        if n == 0 { return 0; }
        let write_head = (self.head + self.len) % PIPE_BUF_CAP;
        let until_wrap = PIPE_BUF_CAP - write_head;
        if n <= until_wrap {
            self.data[write_head..write_head + n].copy_from_slice(&buf[..n]);
        } else {
            self.data[write_head..].copy_from_slice(&buf[..until_wrap]);
            self.data[..n - until_wrap].copy_from_slice(&buf[until_wrap..n]);
        }
        self.len += n;
        n
    }

    #[inline] fn is_empty(&self) -> bool { self.len == 0 }
    #[inline] fn is_full(&self)  -> bool { self.len == PIPE_BUF_CAP }
}

type SharedPipe = Arc<Mutex<PipeBuf>>;

// ── Pipe FD table ───────────────────────────────────────────────────────────────────────────

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

// ── Public query helpers ──────────────────────────────────────────────────────────────────────

pub fn is_pipe_fd(fdno: usize) -> bool {
    if fdno < PIPE_FD_BASE || fdno >= PIPE_FD_BASE + PIPE_TABLE_SIZE { return false; }
    PIPE_TABLE.lock()[fdno - PIPE_FD_BASE].is_some()
}

/// Poll readiness for a pipe fd. Reads state directly without cloning the Arc.
pub fn pipe_poll(fdno: usize, events: u32) -> u32 {
    use crate::fs::poll::{POLLIN, POLLOUT, POLLHUP, POLLNVAL, POLLRDNORM, POLLWRNORM};
    if fdno < PIPE_FD_BASE || fdno >= PIPE_FD_BASE + PIPE_TABLE_SIZE {
        return POLLNVAL;
    }
    let idx = fdno - PIPE_FD_BASE;
    // Acquire PIPE_TABLE lock to get a reference to the Arc, then drop the
    // table lock before acquiring the PipeBuf lock — avoids lock ordering issues.
    let buf_arc: SharedPipe = {
        let tbl = PIPE_TABLE.lock();
        match tbl[idx].as_ref() {
            Some(pfd) => pfd.buf.clone(),
            None      => return POLLNVAL,
        }
    };
    // Re-read end kind without holding the table lock.
    let end_is_read = {
        let tbl = PIPE_TABLE.lock();
        match tbl[idx].as_ref() {
            Some(pfd) => matches!(pfd.end, PipeEnd::Read),
            None      => return POLLNVAL,
        }
    };
    let inner = buf_arc.lock();
    if end_is_read {
        if !inner.write_open && inner.is_empty() { return POLLHUP; }
        if events & POLLIN != 0 && !inner.is_empty() { return POLLIN | POLLRDNORM; }
        0
    } else {
        if events & POLLOUT != 0 && !inner.is_full() { return POLLOUT | POLLWRNORM; }
        0
    }
}

pub fn pipe_read(fdno: usize, buf: &mut [u8]) -> isize {
    if fdno < PIPE_FD_BASE || fdno >= PIPE_FD_BASE + PIPE_TABLE_SIZE { return -9; }
    let idx = fdno - PIPE_FD_BASE;
    let pfd: PipeFd = {
        let tbl = PIPE_TABLE.lock();
        match tbl[idx].clone() { Some(p) => p, None => return -9 }
    };
    match pfd.end { PipeEnd::Write => return -9, PipeEnd::Read => {} }
    let mut spins = 0usize;
    loop {
        let mut inner = pfd.buf.lock();
        if !inner.is_empty() {
            let n = inner.read_into(buf);
            return n as isize;
        }
        if !inner.write_open { return 0; } // EOF
        drop(inner);
        spins += 1;
        if spins > 5_000_000 { return -11; } // EAGAIN
        core::hint::spin_loop();
    }
}

pub fn pipe_write(fdno: usize, buf: &[u8]) -> isize {
    if fdno < PIPE_FD_BASE || fdno >= PIPE_FD_BASE + PIPE_TABLE_SIZE { return -9; }
    let idx = fdno - PIPE_FD_BASE;
    let pfd: PipeFd = {
        let tbl = PIPE_TABLE.lock();
        match tbl[idx].clone() { Some(p) => p, None => return -9 }
    };
    match pfd.end { PipeEnd::Read => return -9, PipeEnd::Write => {} }
    let mut inner = pfd.buf.lock();
    if inner.len + buf.len() > PIPE_BUF_CAP { return -11; } // EAGAIN
    inner.write_from(buf);
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

// ── sys_pipe / sys_pipe2 ───────────────────────────────────────────────────────────────────────

pub fn sys_pipe(pipefd_va: usize) -> isize { sys_pipe2(pipefd_va, 0) }

pub fn sys_pipe2(pipefd_va: usize, _flags: u32) -> isize {
    if !crate::uaccess::validate_user_ptr(pipefd_va, 8) { return -14; }

    let buf = Arc::new(Mutex::new(PipeBuf::new()));
    let read_fd = match alloc_pipe_fd(PipeFd { buf: buf.clone(), end: PipeEnd::Read }) {
        Some(fd) => fd,
        None => return -24, // EMFILE
    };
    let write_fd = match alloc_pipe_fd(PipeFd { buf, end: PipeEnd::Write }) {
        Some(fd) => fd,
        None => { pipe_close(read_fd); return -24; }
    };

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&(read_fd  as i32).to_le_bytes());
    out[4..8].copy_from_slice(&(write_fd as i32).to_le_bytes());
    if copy_to_user(pipefd_va, &out).is_err() {
        pipe_close(read_fd);
        pipe_close(write_fd);
        return -14;
    }
    0
}
