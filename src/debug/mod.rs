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
//! cargo build --features gdbstub        # GDB stub only, no other debug helpers
//! ```
//!
//! The outer `#[cfg(feature = "debug")]` on this file's contents keeps
//! **release builds completely clean** — no dead code, no extra sections,
//! no debug-only symbols in the final binary.
//!
//! ## Modules
//!
//! - `gdbstub` — GDB Remote Serial Protocol (RSP) stub for kernel-level
//!   debugging over a serial transport. Supports both x86_64 and RISC-V
//!   register sets (`rsp.rs` / `rsp_riscv.rs`). Gated behind the additional
//!   `gdbstub` feature (implied by `debug`).
//!
//! ## Adding new debug subsystems
//!
//! 1. Create `src/debug/<subsystem>/mod.rs`.
//! 2. Add a matching feature flag in `Cargo.toml` (optional, or imply it
//!    from `debug = ["gdbstub", "<subsystem>"]`).
//! 3. Gate the `pub mod` below with `#[cfg(feature = "<subsystem>")]`.
//!    The outer `#[cfg(feature = "debug")]` on this whole block already
//!    ensures the subsystem is unreachable in release builds even if the
//!    inner flag were somehow set without `debug`.
//!
//! ## Crate-split note
//!
//! When `kernel-hal` is extracted into its own crate:
//!
//! ```toml
//! # kernel-hal/Cargo.toml
//! [features]
//! debug   = ["gdbstub"]
//! gdbstub = []
//! ```
//!
//! and the root `Cargo.toml` re-exports:
//!
//! ```toml
//! debug   = ["kernel-hal/debug"]
//! gdbstub = ["kernel-hal/gdbstub"]
//! ```

// Nothing in this file is compiled unless `--features debug` is passed.
// This single outer gate is the canonical enforcement point for keeping
// release builds free of all debugging infrastructure.
#[cfg(feature = "debug")]
mod debug_impl {
    // GDB Remote Serial Protocol stub.
    // Also requires the `gdbstub` sub-feature (implied by `debug`).
    #[cfg(feature = "gdbstub")]
    pub mod gdbstub;

    #[cfg(feature = "gdbstub")]
    pub use gdbstub as _gdbstub_reexport;
}

#[cfg(feature = "debug")]
pub use debug_impl::*;
