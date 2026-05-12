//! Firmware and platform interface layer.
//!
//! ACPI handles x86_64 platform power/config; device tree (dt) handles
//! RISC-V and ARM platform enumeration.

pub mod acpi;
pub mod dt;
