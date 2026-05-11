//! Public re-export of CqRingHdr fields for syscall.rs.
//! This is a thin shim so syscall.rs can read cq head/tail without
//! depending on the private SqRingHdr/CqRingHdr structs.

use core::sync::atomic::AtomicU32;

/// Public view of the first two fields of CqRingHdr (head, tail).
/// Used only for the GETEVENTS spin-wait in sys_io_uring_enter.
#[repr(C)]
pub struct CqRingHdrPub {
    pub head: AtomicU32,
    pub tail: AtomicU32,
}
