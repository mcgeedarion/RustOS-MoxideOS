//! Shim so `crate::proc::scheduler::current_tgid()` is available.
//! If your scheduler already exposes `current_tgid`, delete this file
//! and adjust the `use` in `itimer.rs`.
//!
//! We derive tgid from the current PID via `tgid_of`.

// This file intentionally empty — `current_tgid` is implemented
// directly inside `itimer.rs` by calling:
//   crate::proc::thread::tgid_of(crate::proc::scheduler::current_pid())
// which resolves to the process group leader's PID (the TGID).
