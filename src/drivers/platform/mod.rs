//! Platform, bus, and peripheral drivers.
//!
//! ## Modules
//!   gpio   — GPIO stub
//!   pcie   — PCIe ECAM enumeration
//!   tty    — TTY driver shim (real impl in shell/tty.rs)
//!
//! Note: PLIC and CLINT have moved to `crate::irq::riscv64`.

pub mod gpio;
pub mod pcie;
pub mod tty;
