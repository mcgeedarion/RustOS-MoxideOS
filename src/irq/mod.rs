//! IRQ / interrupt-controller subsystem.
//!
//! Organised by architecture so a future x86_64 APIC driver can live here
//! alongside the RISC-V controllers without polluting `src/drivers/`.
//!
//! These are **not** drivers — they are fundamental platform machinery that
//! the trap handler depends on during the earliest stages of kernel init.
//!
//! ## Modules
//!   riscv64  — RISC-V PLIC (external IRQs) + CLINT (timer / IPI)

#[cfg(target_arch = "riscv64")]
pub mod riscv64;
