//! ACPI Power Management
//!
//! Implements:
//!   * FADT parsing (SCI IRQ, PM1a/b event/control/status blocks, SMI_CMD,
//!     ACPI enable sequence, reset register)
//!   * Minimal AML bytecode interpreter covering the opcode subset required
//!     for \_S3 (suspend-to-RAM) and \_S5 (soft-off) namespace objects
//!   * S3 sleep  — writes SLP_TYP + SLP_EN to PM1 control, then HLTs
//!   * S5 shutdown — same path with \_S5 values; also clears WAK_STS
