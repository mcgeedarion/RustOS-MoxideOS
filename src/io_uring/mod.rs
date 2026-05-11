//! io_uring — high-performance asynchronous I/O interface.
//!
//! ## Architecture
//!
//! ```text
//!  User-space process                    Kernel
//!  ─────────────────                     ──────
//!  SQ ring  (mmap'd)  ──── SQEs ──────► submission engine
//!                                            │
//!                                       ops::dispatch()
//!                                            │
//!  CQ ring  (mmap'd)  ◄─── CQEs ─────── completion engine
//! ```
//!
//! Two contiguous shared-memory rings live in PMM pages that are mapped
//! into both kernel and user VA space:
//!
//!   • **SQ ring** — fixed-size array of `IoUringSqe` (64 bytes each).
//!     The user enqueues entries, updates `sq_tail`, then calls
//!     `io_uring_enter` to ask the kernel to drain them.
//!
//!   • **CQ ring** — fixed-size array of `IoUringCqe` (16 bytes each).
//!     The kernel appends completions; the user drains by reading
//!     `cq_head`..`cq_tail`.
//!
//! ## Supported opcodes
//!
//! | Code | Name              | Notes |
//! |------|-------------------|-------|
//! | 0    | NOP               | always succeeds |
//! | 1    | READV             | scatter-gather read |
//! | 2    | WRITEV            | scatter-gather write |
//! | 3    | FSYNC             | flush file data |
//! | 4    | READ_FIXED        | read into registered buffer |
//! | 5    | WRITE_FIXED       | write from registered buffer |
//! | 6    | POLL_ADD          | one-shot poll |
//! | 7    | POLL_REMOVE       | cancel poll |
//! | 8    | SYNC_FILE_RANGE   | partial fsync |
//! | 9    | SENDMSG           | sendmsg(2) |
//! | 10   | RECVMSG           | recvmsg(2) |
//! | 11   | TIMEOUT           | relative/absolute timeout |
//! | 12   | TIMEOUT_REMOVE    | cancel timeout |
//! | 13   | ACCEPT            | accept(2) |
//! | 14   | ASYNC_CANCEL      | cancel any inflight |
//! | 15   | LINK_TIMEOUT      | timeout linked to next op |
//! | 16   | CONNECT           | connect(2) |
//! | 17   | FALLOCATE         | fallocate(2) |
//! | 18   | OPENAT            | openat(2) |
//! | 19   | CLOSE             | close(2) |
//! | 20   | STATX             | statx(2) |
//! | 21   | READ              | pread(2) |
//! | 22   | WRITE             | pwrite(2) |
//! | 23   | FADVISE           | fadvise(2) |
//! | 24   | MADVISE           | madvise(2) |
//! | 25   | SEND              | send(2) |
//! | 26   | RECV              | recv(2) |
//! | 27   | OPENAT2           | openat2(2) |
//! | 28   | EPOLL_CTL         | epoll_ctl(2) |
//! | 29   | SPLICE            | splice(2) |
//! | 30   | PROVIDE_BUFFERS   | register user buffers |
//! | 31   | REMOVE_BUFFERS    | unregister buffers |
//!
//! ## Syscall numbers (x86-64 Linux ABI)
//!
//! | NR  | Name               | Signature |
//! |-----|--------------------|-----------|
//! | 425 | `io_uring_setup`   | `(entries: u32, params: *mut IoUringParams) -> fd` |
//! | 426 | `io_uring_enter`   | `(fd, to_submit, min_complete, flags, sig, sig_sz) -> submitted` |
//! | 427 | `io_uring_register`| `(fd, opcode, arg, nr_args) -> isize` |

pub mod ops;
pub mod ring;
pub mod syscall;

pub use ring::{IoUringRing, IoUringSqe, IoUringCqe, IoUringParams};
pub use syscall::{sys_io_uring_setup, sys_io_uring_enter, sys_io_uring_register};
