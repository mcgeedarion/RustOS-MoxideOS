//! Platform firmware and hardware-description interfaces.
//!
//! ## Modules
//!
//!   `acpi`     — ACPI table parsing and power management (x86_64 + AArch64).
//!   `dt`       — Device Tree / FDT helpers (RISC-V, ARM).
//!   `psci`     — ARM PSCI CPU_ON / SYSTEM_OFF / SYSTEM_RESET.
//!   `topology` — CPU topology (MPIDR list from MADT or DTB).
//!
//! Architecture-specific boot code consumes these before the generic kernel
//! initialisation sequence in `kernel_main` runs.

pub mod acpi;
pub mod dt;
#[cfg(target_arch = "aarch64")]
pub mod psci;
#[cfg(target_arch = "aarch64")]
pub mod topology;

// Re-export so existing `crate::acpi` and `crate::dt` paths still compile.
pub use acpi as _acpi_reexport;
pub use dt as _dt_reexport;
