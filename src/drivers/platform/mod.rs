//! Platform, bus, and peripheral drivers.
//!
//! ## Modules
//!   clint  — RISC-V CLINT timer
//!   gpio   — GPIO stub
//!   pcie   — PCIe ECAM enumeration
//!   plic   — RISC-V PLIC interrupt controller
//!   tty    — TTY driver shim (real impl in shell/tty.rs)

pub mod clint;
pub mod gpio;
pub mod pcie;
pub mod plic;
pub mod tty;
