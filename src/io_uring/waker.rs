// src/io_uring/waker.rs
//
// This file is intentionally empty.
//
// The async `core::task::Waker` table that lived here has been replaced by
// `WaitQueue` (see `ring.rs` `cq_wq` field).  Callers that previously called
// `WakerTable::register` / `WakerTable::wake` should now use:
//
//   // wake:
//   ring::with_ring(idx, |r| r.cq_wq.wake(CQ_READY));
//
//   // wait (from syscall context):
//   ring::cq_wq_for(idx).unwrap().wait(CQ_READY, cancel, deadline);
//
// The file is kept as a tombstone to avoid breaking any `mod waker;`
// declaration in mod.rs.
