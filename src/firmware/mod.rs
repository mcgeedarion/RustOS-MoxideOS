//! Platform firmware and hardware-description interfaces.
//!
//! ## Modules
//!
//!   `acpi` — ACPI table parsing and power management (x86_64).
//!   `dt`   — Device Tree / FDT helpers (RISC-V, ARM).
//!
//! Architecture-specific boot code consumes these before the generic kernel
//! initialisation sequence in `kernel_main` runs.

pub mod acpi;
pub mod dt;

// Re-export so existing `crate::acpi` and `crate::dt` paths still compile.
pub use acpi as _acpi_reexport;
pub use dt as _dt_reexport;
