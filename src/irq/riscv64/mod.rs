//! RISC-V interrupt controllers.
//!
//! ## Modules
//!   plic  — Platform-Level Interrupt Controller (external device IRQs)
//!   clint — Core Local INTerruptor (timer + software / IPI)

pub mod clint;
pub mod plic;
