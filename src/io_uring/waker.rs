// src/io_uring/waker.rs — DELETED
//
// This file is intentionally left as a tombstone marker only so that git
// history shows the deletion cleanly.  It contains no code.
//
// WakerTable has been removed.  Wakeup is now handled by the WaitQueue
// embedded in each IoUringRing (ring.rs `cq_wq` field), driven by
// `IoUringRing::post_cqe`.
