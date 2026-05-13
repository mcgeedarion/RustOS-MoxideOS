//! PipeScheme — anonymous pipes as a first-class scheme.
//!
//! # Overview
//!
//! A pipe is a uni-directional byte channel between two file descriptors.
//! Traditionally the kernel has a bespoke code path for `pipe(2)` that
//! bypasses the VFS entirely.  Here we model it as a scheme instead:
//!
//! ```text
//! open("pipe:", O_RDWR)
//!     → PipeScheme::open() allocates a 4 KiB ring buffer
//!     → returns SchemeFileId(N)          ← write end
//!        SchemeFileId(N+1) is the read end (same buffer)
//! ```
//!
//! Both ends are then registered in `SCHEME_FD_STORE` by `create_pipe()`
//! so that all subsequent I/O goes through the standard
//! `scheme_fd_read` / `scheme_fd_write` / `scheme_fd_close` dispatch.
//!
//! # Why this matters
//!
//! Because pipe fds live in `SCHEME_FD_STORE` alongside `tcp:` and `file:`
//! fds, a future `select()` / `poll()` / `io_uring` implementation can
//! iterate the store uniformly with no special-casing for pipes.
//!
//! # Ring buffer layout
//!
//! ```text
//! [ 0 .. head )           ← consumed (free)
//! [ head .. tail )        ← pending bytes
//! [ tail .. cap )         ← free space
//! ```
//!
//! `push` writes at `tail`; `pop` reads from `head`.  Both wrap modulo
//! `cap`.  The buffer is full when `(tail + 1) % cap == head`.
//!
//! # EOF semantics
//!
//! `writers` on `PipeBuf` is a reference count initialised to 1.  Closing
//! the write end decrements it.  `read()` returns `Ok(0)` (POSIX EOF) when
//! the ring is empty **and** `writers == 0`.

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use scheme_api::{OpenFlags, SchemeError, SchemeFileId};
use crate::fs::scheme_table::Scheme;
use crate::fs::scheme_fd::{alloc_scheme_backing_fd, scheme_fd_register};

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

struct PipeBuf {
    ring:    Vec<u8>,
    head:    usize,
    tail:    usize,
    cap:     usize,
    /// Number of open write-end handles.  Starts at 1.
    /// When it reaches 0 and the ring is empty, read returns EOF.
    writers: usize,
}

impl PipeBuf {
    fn new(cap: usize) -> Self {
        Self { ring: vec![0u8; cap], head: 0, tail: 0, cap, writers: 1 }
    }

    fn is_empty(&self) -> bool { self.head == self.tail }

    fn is_full(&self) -> bool { (self.tail + 1) % self.cap == self.head }

    /// Copy as many bytes from `buf` into the ring as will fit.
    /// Returns the number of bytes actually written.
    fn push(&mut self, buf: &[u8]) -> usize {
        let mut n = 0;
        for &b in buf {
            if self.is_full() { break; }
            self.ring[self.tail] = b;
            self.tail = (self.tail + 1) % self.cap;
            n += 1;
        }
        n
    }

    /// Drain up to `buf.len()` bytes from the ring into `buf`.
    /// Returns the number of bytes copied.
    fn pop(&mut self, buf: &mut [u8]) -> usize {
        let mut n = 0;
        for slot in buf.iter_mut() {
            if self.is_empty() { break; }
            *slot = self.ring[self.head];
            self.head = (self.head + 1) % self.cap;
            n += 1;
        }
        n
    }
}

// ---------------------------------------------------------------------------
// Global pipe table
// ---------------------------------------------------------------------------
//
// Keyed by the *write-end* fid (always even).  The read-end fid is
// write_fid + 1 (always odd); both share the same `PipeBuf`.

static PIPES:    Mutex<BTreeMap<u32, PipeBuf>> = Mutex::new(BTreeMap::new());
static PIPE_CTR: AtomicU32                    = AtomicU32::new(2);

/// Allocate a new pipe-buffer ID.  IDs are even and start at 2.
/// The read-end fid is always `id + 1`.
fn alloc_pipe_id() -> u32 {
    // Increment by 2 to keep write-end IDs always even.
    PIPE_CTR.fetch_add(2, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// PipeScheme
// ---------------------------------------------------------------------------

pub struct PipeScheme;

impl Scheme for PipeScheme {
    /// Allocate a new 4 KiB ring buffer and return the write-end fid.
    ///
    /// The `path` component of `"pipe:"` is ignored — all opens create a
    /// fresh unconnected pair.  Named pipes (FIFOs) would be a separate
    /// scheme (`fifo:<name>`) if added later.
    fn open(&self, _path: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        let id = alloc_pipe_id();
        PIPES.lock().insert(id, PipeBuf::new(4096));
        Ok(SchemeFileId(id as usize))
    }

    /// Read from the **read end** (fid is odd: write_fid + 1).
    ///
    /// Returns `Ok(0)` on EOF (write end closed + ring empty).
    /// Returns `Err(SchemeError::WouldBlock)` when the ring is empty but
    /// the write end is still open (analogous to `EAGAIN` on a non-blocking
    /// pipe).
    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        // The write-end id is one less than the read-end id.
        let write_id = (fid.0 as u32).saturating_sub(1);
        let mut pipes = PIPES.lock();
        let pipe = pipes.get_mut(&write_id).ok_or(SchemeError::NotFound)?;

        if pipe.is_empty() {
            if pipe.writers == 0 {
                return Ok(0);  // EOF
            }
            return Err(SchemeError::WouldBlock);
        }
        Ok(pipe.pop(buf))
    }

    /// Write to the **write end** (fid is even).
    ///
    /// Returns `Err(SchemeError::Io)` (EPIPE equivalent) if the read end
    /// has already been closed, i.e. the pipe-buffer entry is gone.
    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let mut pipes = PIPES.lock();
        let pipe = pipes.get_mut(&(fid.0 as u32))
            .ok_or(SchemeError::Io)?;  // read end gone → EPIPE
        Ok(pipe.push(buf))
    }

    /// Close one end of the pipe.
    ///
    /// * **Write end** (even fid): decrement `writers`.  Buffer stays alive
    ///   until the read end also closes so pending bytes can be drained.
    /// * **Read end** (odd fid): remove the buffer entirely.  Any subsequent
    ///   write to the write end will receive `SchemeError::Io` (EPIPE).
    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        let id = fid.0 as u32;
        let is_write_end = id % 2 == 0;

        let mut pipes = PIPES.lock();
        if is_write_end {
            if let Some(pipe) = pipes.get_mut(&id) {
                pipe.writers = pipe.writers.saturating_sub(1);
                // If the write end drops to 0 *and* the ring is already empty,
                // remove the buffer now so the read-end close is a no-op.
                if pipe.writers == 0 && pipe.is_empty() {
                    pipes.remove(&id);
                }
            }
        } else {
            // Read end closing: remove the buffer so future writes see EPIPE.
            let write_id = id.saturating_sub(1);
            pipes.remove(&write_id);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Syscall-layer helper
// ---------------------------------------------------------------------------

/// Allocate a (read_backing_fd, write_backing_fd) pair backed by a fresh
/// `PipeBuf` and register both ends in `SCHEME_FD_STORE`.
///
/// This is the only function `syscall/pipe.rs` needs to call:
///
/// ```rust
/// // In sys_pipe:
/// let (rfd, wfd) = crate::ipc::pipe_scheme::create_pipe()?;
/// unsafe {
///     *(fds as *mut [usize; 2]) = [rfd, wfd];
/// }
/// ```
pub fn create_pipe() -> Result<(usize, usize), SchemeError> {
    let scheme: Arc<dyn Scheme> = Arc::new(PipeScheme);

    // open() allocates the ring buffer and returns the write-end fid.
    let wfid = scheme.open("", OpenFlags::RDWR)?;
    // Read-end fid is write_fid + 1 by convention.
    let rfid = SchemeFileId(wfid.0 + 1);

    // Allocate two synthetic backing-fd numbers from the free-list allocator.
    let write_bfd = alloc_scheme_backing_fd();
    let read_bfd  = alloc_scheme_backing_fd();

    // Register both ends so scheme_fd_read / scheme_fd_write / scheme_fd_close
    // can dispatch them without knowing they are pipes.
    scheme_fd_register(write_bfd, Arc::clone(&scheme), wfid);
    scheme_fd_register(read_bfd,  Arc::clone(&scheme), rfid);

    // (read_bfd, write_bfd) mirrors the POSIX pipe(fds) convention:
    // fds[0] = read end, fds[1] = write end.
    Ok((read_bfd, write_bfd))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_write_read() {
        let scheme = PipeScheme;
        let wfid = scheme.open("", OpenFlags::RDWR).unwrap();
        let rfid = SchemeFileId(wfid.0 + 1);

        let written = scheme.write(wfid, b"hello").unwrap();
        assert_eq!(written, 5);

        let mut buf = [0u8; 8];
        let n = scheme.read(rfid, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn eof_after_write_end_close() {
        let scheme = PipeScheme;
        let wfid = scheme.open("", OpenFlags::RDWR).unwrap();
        let rfid = SchemeFileId(wfid.0 + 1);

        // Write something, then close the write end.
        scheme.write(wfid, b"eof").unwrap();
        scheme.close(wfid).unwrap();

        // Drain the buffered bytes.
        let mut buf = [0u8; 8];
        let n = scheme.read(rfid, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"eof");

        // Next read must return EOF (Ok(0)).
        let n2 = scheme.read(rfid, &mut buf).unwrap();
        assert_eq!(n2, 0, "expected EOF");
    }

    #[test]
    fn would_block_when_empty_but_writer_alive() {
        let scheme = PipeScheme;
        let wfid = scheme.open("", OpenFlags::RDWR).unwrap();
        let rfid = SchemeFileId(wfid.0 + 1);

        let mut buf = [0u8; 4];
        let err = scheme.read(rfid, &mut buf).unwrap_err();
        assert!(matches!(err, SchemeError::WouldBlock));
    }

    #[test]
    fn epipe_when_read_end_closed() {
        let scheme = PipeScheme;
        let wfid = scheme.open("", OpenFlags::RDWR).unwrap();
        let rfid = SchemeFileId(wfid.0 + 1);

        // Close the read end first.
        scheme.close(rfid).unwrap();

        // Write must fail with Io (EPIPE).
        let err = scheme.write(wfid, b"data").unwrap_err();
        assert!(matches!(err, SchemeError::Io));
    }

    #[test]
    fn ring_buffer_wraps_correctly() {
        // Tiny ring of 8 bytes to force wrap-around.
        let id = alloc_pipe_id();
        PIPES.lock().insert(id, PipeBuf::new(8));
        let wfid = SchemeFileId(id as usize);
        let rfid = SchemeFileId(id as usize + 1);
        let scheme = PipeScheme;

        // Fill 7 bytes (ring is full at cap-1 = 7).
        assert_eq!(scheme.write(wfid, b"1234567").unwrap(), 7);

        // Read 4, then write 4 more — exercises the wrap.
        let mut buf = [0u8; 4];
        assert_eq!(scheme.read(rfid, &mut buf).unwrap(), 4);
        assert_eq!(scheme.write(wfid, b"abcd").unwrap(), 4);

        // Read everything remaining (3 + 4 = 7 bytes).
        let mut out = [0u8; 16];
        let n = scheme.read(rfid, &mut out).unwrap();
        assert_eq!(n, 7);
        assert_eq!(&out[..7], b"567abcd");
    }
}
