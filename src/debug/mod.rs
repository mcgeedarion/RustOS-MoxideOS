//! Kernel debugging infrastructure.
//!
//! ## Feature gate
//!
//! The entire `debug` module tree is compiled only when the **`debug`**
//! Cargo feature is enabled:
//!
//! ```sh
//! cargo build --features debug          # full debug build
//! cargo build --features debug,gdbstub  # same (gdbstub is implied by debug)
//! cargo build --features debug,trace    # with ftrace function hooks
//! cargo build --features gdbstub        # GDB stub only
//! ```
//!
//! ## Modules
//!
//! - `gdbstub`  — GDB Remote Serial Protocol (RSP) stub (requires `gdbstub` feature)
//! - `trace`    — lock-free ring buffer for syscall/IRQ/sched events
//! - `ftrace`   — LLVM `-Z instrument-functions` hooks (requires `trace` feature)
//! - `oops`     — enriched panic formatter: register dump + stack backtrace
//!
//! ## Adding new debug subsystems
//!
//! 1. Create `src/debug/<subsystem>/mod.rs`.
//! 2. Add a matching feature flag in `Cargo.toml` (optional, or imply it
//!    from `debug = ["gdbstub", "<subsystem>"]`).
//! 3. Gate the `pub mod` below with `#[cfg(feature = "<subsystem>")]`.

#[cfg(feature = "debug")]
mod debug_impl {
    // GDB Remote Serial Protocol stub.
    #[cfg(feature = "gdbstub")]
    pub mod gdbstub;
    #[cfg(feature = "gdbstub")]
    pub use gdbstub as _gdbstub_reexport;
    // Lock-free kernel trace ring buffer (syscall/IRQ/sched events).
    pub mod trace;
    // ftrace-style function entry/exit hooks via LLVM instrument-functions.
    #[cfg(feature = "trace")]
    pub mod ftrace;
    // Enriched panic handler: register dump + frame-pointer backtrace.
    pub mod oops;
}

#[cfg(feature = "debug")]
pub use debug_impl::*;
