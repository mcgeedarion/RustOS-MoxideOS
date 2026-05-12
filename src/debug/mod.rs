//! Kernel debugging infrastructure.
//!
//! ## Modules
//!
//!   `gdbstub` — GDB Remote Serial Protocol (RSP) stub for kernel-level
//!               debugging over a serial transport. Supports both x86_64
//!               and RISC-V register sets (`rsp.rs` / `rsp_riscv.rs`).

pub mod gdbstub;

pub use gdbstub as _gdbstub_reexport;
