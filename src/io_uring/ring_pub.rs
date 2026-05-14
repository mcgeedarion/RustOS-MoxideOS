//! Public CQ-ring head/tail view used by the GETEVENTS spin-wait in
//! `sys_io_uring_enter` without pulling in the private `CqRingHdr` type.

use core::sync::atomic::AtomicU32;

/// Head + tail overlay for `CqRingHdr` (first two fields, same layout).
#[repr(C)]
#[allow(dead_code)]
pub struct CqRingHdrPub {
    pub head: AtomicU32,
    pub tail: AtomicU32,
}
