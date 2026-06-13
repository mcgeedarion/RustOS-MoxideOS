//! Kernel debugging infrastructure.
//!
//! Feature gates are intentionally per-subsystem: `gdbstub` builds the remote
//! serial protocol without requiring the heavier `debug` bundle, while `trace`,
//! `ftrace`, and `oops` remain tied to their respective debug features.
//!
//! The `debug` feature additionally enables the interactive REPL (`commands`)
//! that accepts `info mem`, `info proc`, `bt`, and `dump` over the serial
//! console, as well as the QEMU debugcon port driver (`debugcon`).

#[cfg(feature = "gdbstub")]
pub mod gdbstub;

#[cfg(any(feature = "debug", feature = "trace"))]
pub mod trace;

#[cfg(feature = "trace")]
pub mod ftrace;

#[cfg(feature = "debug")]
pub mod oops;

/// REPL commands: `info mem`, `info proc`, `bt`, `dump`.
/// Requires `alloc::format` — excluded from production builds.
#[cfg(feature = "debug")]
pub mod commands;

/// QEMU debugcon port (I/O port 0xe9).
/// x86_64 only; no-ops on real hardware so always safe to call.
#[cfg(target_arch = "x86_64")]
pub mod debugcon;
