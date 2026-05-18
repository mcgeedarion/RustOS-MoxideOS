//! Kernel debugging infrastructure.
//!
//! ## Modules
//!
//!   `gdbstub` — GDB Remote Serial Protocol (RSP) stub for kernel-level
//!               debugging over a serial transport. Supports both x86_64
//!               and RISC-V register sets (`rsp.rs` / `rsp_riscv.rs`).
//!
//! ## Feature gate
//!
//! This entire module tree is compiled only when `--features gdbstub` is
//! passed.  The gate lives here (rather than at the call-site in `lib.rs`)
//! so that the owning module controls its own surface area.  When
//! `kernel-hal` is split into its own crate this becomes:
//!
//! ```toml
//! # kernel-hal/Cargo.toml
//! [features]
//! gdbstub = []
//! ```
//!
//! and the root `Cargo.toml` re-exports it as:
//!
//! ```toml
//! gdbstub = ["kernel-hal/gdbstub"]
//! ```

#[cfg(feature = "gdbstub")]
pub mod gdbstub;

#[cfg(feature = "gdbstub")]
pub use gdbstub as _gdbstub_reexport;
