//! ARM Generic Interrupt Controller support for ARM64.
//!
//! RustOS accepts the same ARM64 interrupt-controller baseline as ReactOS:
//! GICv2 or GICv3.  Platform discovery should fill in MMIO bases from ACPI MADT
//! or Device Tree; QEMU `virt` fallback bases live in `arch::aarch64::mem_layout`.

pub mod gic;
