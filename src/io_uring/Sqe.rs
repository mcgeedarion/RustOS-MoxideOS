// src/io_uring/sqe.rs
//
// Submission Queue Entry (SQE) — mirrors the Linux io_uring_sqe layout
// but trimmed to the opcodes RustOS actually dispatches.
//
// Field layout follows the Linux ABI so the struct is compatible with any
// virtio or pass-through mechanism we might add later.

use core::mem;

// ── Opcode constants (Linux ABI values) ───────────────────────────────────────

pub mod op {
    pub const NOP:     u8 = 0;
    pub const READV:   u8 = 1;
    pub const WRITEV:  u8 = 2;
    pub const READ:    u8 = 22; // IORING_OP_READ   (fixed-buffer variant)
    pub const WRITE:   u8 = 23; // IORING_OP_WRITE
    pub const ACCEPT:  u8 = 13; // IORING_OP_ACCEPT
    pub const CONNECT: u8 = 16; // IORING_OP_CONNECT
    pub const CLOSE:   u8 = 19; // IORING_OP_CLOSE
    pub const TIMEOUT: u8 = 11; // IORING_OP_TIMEOUT
}

// ── Flags ─────────────────────────────────────────────────────────────────────

pub mod sqe_flags {
    /// Use fixed (pre-registered) file descriptor index.
    pub const FIXED_FILE: u8 = 1 << 0;
    /// Drain all previously submitted SQEs before issuing this one.
    pub const IO_DRAIN:   u8 = 1 << 1;
    /// Link this SQE to the next; the next runs only if this succeeds.
    pub const IO_LINK:    u8 = 1 << 2;
    /// Perform the operation on a hardlink; fail-safe variant of IO_LINK.
    pub const IO_HARDLINK: u8 = 1 << 3;
    /// Always perform the operation asynchronously.
    pub const ASYNC:      u8 = 1 << 4;
}

// ── SQE struct ────────────────────────────────────────────────────────────────

/// One entry in the submission queue.
///
/// All pointer fields carry a raw address; the dispatcher is responsible for
/// validating and re-materialising them.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Sqe {
    /// Operation code — one of the `op::*` constants.
    pub opcode: u8,
    /// Per-SQE flags — `sqe_flags::*`.
    pub flags: u8,
    /// ioprio (unused for now; set to 0).
    pub ioprio: u16,
    /// File descriptor (or pre-registered index when FIXED_FILE is set).
    pub fd: i32,

    // Union: off / addr2 / cmd_op+__pad1
    /// File offset for read/write.  For network ops this is 0.
    pub off: u64,

    // Union: addr / splice_off_in
    /// Buffer address (for read/write) or sockaddr address (for connect).
    pub addr: u64,

    /// Transfer length in bytes.
    pub len: u32,

    // Union: rw_flags / fsync_flags / poll_events / sync_range_flags /
    //        msg_flags / timeout_flags / accept_flags / cancel_flags /
    //        open_flags / statx_flags / fadvise_advice / splice_flags /
    //        rename_flags / unlink_flags / hardlink_flags / xattr_flags /
    //        msg_ring_flags / uring_cmd_flags
    pub op_flags: u32,

    /// Caller-supplied token echoed back in the CQE.  Used to key the waker
    /// table — must be unique per in-flight operation.
    pub user_data: u64,

    // Union: buf_index / buf_group / __pad2[3]
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub __pad2: u64,
}

impl Sqe {
    /// Return a zero-initialised SQE (const so it can seed static arrays).
    #[inline]
    pub const fn zeroed() -> Self {
        // SAFETY: Sqe is repr(C) with no non-zero-valid constraints.
        unsafe { mem::zeroed() }
    }

    // ── Builders ──────────────────────────────────────────────────────────────

    /// Prepare a fixed-buffer READ: read `len` bytes from `fd` at `offset`
    /// into the buffer at virtual address `buf_addr`.
    pub fn read(fd: i32, buf_addr: u64, len: u32, offset: u64, token: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = op::READ;
        sqe.fd = fd;
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.off = offset;
        sqe.user_data = token;
        sqe
    }

    /// Prepare a WRITE: write `len` bytes from buffer at `buf_addr` to `fd`
    /// at `offset`.
    pub fn write(fd: i32, buf_addr: u64, len: u32, offset: u64, token: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = op::WRITE;
        sqe.fd = fd;
        sqe.addr = buf_addr;
        sqe.len = len;
        sqe.off = offset;
        sqe.user_data = token;
        sqe
    }

    /// Prepare an ACCEPT on a listening socket `fd`.
    ///
    /// `sockaddr_addr` — address of a `sockaddr_storage`-sized buffer to fill.
    /// `addrlen_addr`  — address of a `socklen_t` (u32) that will be updated.
    pub fn accept(
        fd: i32,
        sockaddr_addr: u64,
        addrlen_addr: u64,
        accept_flags: u32,
        token: u64,
    ) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = op::ACCEPT;
        sqe.fd = fd;
        sqe.addr = sockaddr_addr;
        sqe.addr3 = addrlen_addr;
        sqe.op_flags = accept_flags;
        sqe.user_data = token;
        sqe
    }

    /// Prepare a CONNECT to the sockaddr at `sockaddr_addr` (length `addrlen`)
    /// through non-blocking socket `fd`.
    pub fn connect(fd: i32, sockaddr_addr: u64, addrlen: u32, token: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = op::CONNECT;
        sqe.fd = fd;
        sqe.addr = sockaddr_addr;
        sqe.len = addrlen;
        sqe.user_data = token;
        sqe
    }

    /// Prepare a NOP (useful for testing the ring machinery).
    pub fn nop(token: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = op::NOP;
        sqe.user_data = token;
        sqe
    }

    /// Attach a flag to an already-constructed SQE.
    #[inline]
    pub fn with_flag(mut self, flag: u8) -> Self {
        self.flags |= flag;
        self
    }
}
