// src/io_uring/ops/mod.rs
//
// Opcode dispatch.
//
// `dispatch()` is called by the SQ processing loop for each dequeued SQE.
// It routes to the appropriate handler and returns an i32 result that is
// stored verbatim in the CQE `res` field (Linux convention: non-negative =
// success, negative = negated errno).

pub mod accept;
pub mod connect;
pub mod read;
pub mod write;

use crate::io_uring::{
    cqe::errno,
    sqe::{op, Sqe},
};

/// Dispatch one SQE to its handler and return the result.
///
/// Returns a raw `i32` (Linux errno convention) for embedding in a CQE.
pub fn dispatch(sqe: &Sqe) -> i32 {
    match sqe.opcode {
        op::NOP => {
            log::trace!("[io_uring] NOP token={:#x}", sqe.user_data);
            0
        }

        op::READ => read::handle(sqe),

        op::WRITE => write::handle(sqe),

        op::ACCEPT => accept::handle(sqe),

        op::CONNECT => connect::handle(sqe),

        op::CLOSE => handle_close(sqe),

        unknown => {
            log::warn!(
                "[io_uring] unknown opcode {:#x} token={:#x}",
                unknown,
                sqe.user_data
            );
            errno::E_NOSYS
        }
    }
}

// ── CLOSE ────────────────────────────────────────────────────────────────────

/// Close a file descriptor.
///
/// Delegates to the VFS layer once that exists.  Currently a stub that
/// validates the fd range and logs.
fn handle_close(sqe: &Sqe) -> i32 {
    let fd = sqe.fd;
    if fd < 0 {
        log::warn!("[io_uring::close] invalid fd={}", fd);
        return errno::E_BADF;
    }
    log::debug!("[io_uring::close] fd={}", fd);

    // TODO: call vfs::close(fd) when VFS is implemented.
    // For now, report success so the ring machinery can be exercised end-to-end.
    0
}
