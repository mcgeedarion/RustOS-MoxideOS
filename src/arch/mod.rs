//! Architecture module.
//!
//! ## How to use the HAL
//!
//!   ```rust
//!   use crate::arch::{Arch, api};
//!   use crate::arch::api::{Cpu, Interrupts, Paging, PageFlags};
//!
//!   // Halt until next interrupt:
//!   Arch::halt();
//!
//!   // Critical section:
//!   Interrupts::without(|| { /* ... */ });
//!
//!   // Map a page:
//!   Arch::map_page(cr3, va, pa, PageFlags::PRESENT | PageFlags::WRITE);
//!   ```
//!
//! No code outside `src/arch/` should import from `arch::x86_64` or
//! `arch::riscv64`, or `arch::aarch64` directly.  Use `arch::Arch` and `arch::api::*`.

pub mod api;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::hal;
#[cfg(target_arch = "aarch64")]
use aarch64::hal::ArchImpl;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::hal;
#[cfg(target_arch = "x86_64")]
use x86_64::hal::ArchImpl;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use riscv64::hal;
#[cfg(target_arch = "riscv64")]
use riscv64::hal::ArchImpl;

/// The concrete architecture implementation.
/// Generic code uses this type alias to access all HAL traits.
pub type Arch = ArchImpl;
