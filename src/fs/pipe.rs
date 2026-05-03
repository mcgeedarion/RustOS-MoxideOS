//! Anonymous pipe — sys_pipe2 / sys_pipe (NR 22 / NR 293).
//!
//! Each pipe is a fixed-size ring buffer shared between a read-end FD
//! and a write-end FD.  Both ends hold an Arc to the same Mutex<PipeBuf>.
//!
//! ## Wiring
//!   sys_pipe(pipefd_va)   — writes [read_fd, write_fd] to user pointer
//!   sys_pipe2(pipefd_va, flags) — flags: O_CLOEXEC(0x80000), O_NONBLOCK(0x800)
//!
//! ## VFS integration
//!   Pipe FDs are tracked in the global PIPE_TABLE keyed by fd number.
//!   vfs::read / vfs::write check is_pipe_fd(fdno) before the FD table.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

// ── Pipe buffer ──────────────────────────────────────────────────────────

const PIPE_BUF_CAP: usize = 65536; // 64 KiB; matches Linux default

struct PipeBuf {
    data:       Vec<u8>,
    write_open: bool,  // false once the write-end FD is closed
}

type SharedPipe = Arc<Mutex<PipeBuf>>;

// ── Pipe FD table ─────────────────────────────────────────────────────

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

// Pipe fd numbers start above the normal VFS fd space and below devfs.
const PIPE_FD_BASE: usize = 0x2000_0000;

fn alloc_pipe_fd(pfd: PipeFd) -> Option<usize> {
    let mut tbl = PIPE_TABLE.lock();
    for (i, slot) in tbl.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(pfd);
            return Some(PIPE_FD_BASE + i);
        }
    }
    None
}

// ── Public query helpers (called from vfs.rs) ───────────────────────────

pub fn is_pipe_fd(fdno: usize) -> bool {
    if fdno < PIPE_FD_BASE || fdno >= PIPE_FD_BASE + PIPE_TABLE_SIZE { return false; }
    let idx = fdno - PIPE_FD_BASE;
    PIPE_TABLE.lock()[idx].is_some()
}

pub fn pipe_read(fdno: usize, buf: &mut [u8]) -> isize {
    let idx = fdno - PIPE_FD_BASE;
    let pfd = { let tbl = PIPE_TABLE.lock(); tbl[idx].clone() };
    let pfd = match pfd { Some(p) => p, None => return -9 };
    match pfd.end {
        PipeEnd::Write => return -9, // EBADF
        PipeEnd::Read  => {}
    }
    // Spin-wait until data is available or write end is closed.
    let mut spins = 0usize;
    loop {
        let mut inner = pfd.buf.lock();
        if !inner.data.is_empty() {
            let n = buf.len().min(inner.data.len());
            buf[..n].copy_from_slice(&inner.data[..n]);
            inner.data.drain(..n);
            return n as isize;
        }
        if !inner.write_open { return 0; } // EOF
        drop(inner);
        spins += 1;
        if spins > 5_000_000 {
            // Non-blocking timeout — return EAGAIN.
            return -11;
        }
        core::hint::spin_loop();
    }
}

pub fn pipe_write(fdno: usize, buf: &[u8]) -> isize {
    let idx = fdno - PIPE_FD_BASE;
    let pfd = { let tbl = PIPE_TABLE.lock(); tbl[idx].clone() };
    let pfd = match pfd { Some(p) => p, None => return -9 };
    match pfd.end {
        PipeEnd::Read  => return -9,
        PipeEnd::Write => {}
    }
    let mut inner = pfd.buf.lock();
    // Enforce pipe capacity.
    if inner.data.len() + buf.len() > PIPE_BUF_CAP {
        return -11; // EAGAIN (pipe full)
    }
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
        if let PipeEnd::Write = p.end {
            p.buf.lock().write_open = false; // signal EOF to readers
        }
        true
    } else {
        false
    }
}

// ── sys_pipe / sys_pipe2 ───────────────────────────────────────────────

/// sys_pipe(pipefd_va)  [NR 22]
/// Writes two 32-bit fd numbers to the user address `pipefd_va`:
///   pipefd[0] = read end, pipefd[1] = write end.
pub fn sys_pipe(pipefd_va: usize) -> isize {
    sys_pipe2(pipefd_va, 0)
}

/// sys_pipe2(pipefd_va, flags)  [NR 293]
/// flags: O_CLOEXEC (0o2000000) is accepted but not enforced (no exec yet).
pub fn sys_pipe2(pipefd_va: usize, _flags: u32) -> isize {
    if pipefd_va == 0 || pipefd_va < 0x1000 { return -14; } // EFAULT

    let buf = Arc::new(Mutex::new(PipeBuf {
        data: Vec::new(),
        write_open: true,
    }));

    let read_fd = match alloc_pipe_fd(PipeFd { buf: buf.clone(), end: PipeEnd::Read }) {
        Some(fd) => fd,
        None     => return -24, // EMFILE
    };
    let write_fd = match alloc_pipe_fd(PipeFd { buf, end: PipeEnd::Write }) {
        Some(fd) => fd,
        None => {
            pipe_close(read_fd);
            return -24;
        }
    };

    // Write [read_fd, write_fd] as two i32 values to user space.
    unsafe {
        let p = pipefd_va as *mut i32;
        p.add(0).write_volatile(read_fd  as i32);
        p.add(1).write_volatile(write_fd as i32);
    }
    0
}
