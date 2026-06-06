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

/// GUESS: re-export of `crate::time::clint` so legacy callers using
/// `drivers::platform::clint::*` resolve. The real CLINT MMIO lives in
/// `crate::irq::riscv64`; time/clint exposes monotonic read helpers.
pub mod clint {
    pub use crate::time::clint::*;
    /// GUESS: alias to monotonic ns reader for input drivers.
    #[inline]
    pub fn monotonic_ns() -> u64 {
        crate::time::monotonic_ns()
    }
}
