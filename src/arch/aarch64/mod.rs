//! AArch64/ARM64 architecture support.
//!
//! Baseline hardware requirement follows the ReactOS ARM64 bring-up target:
//! UEFI firmware on an Armv8-A (or newer) processor with either a GICv2 or GICv3
//! interrupt controller.

pub mod boot;
pub mod hal;
pub mod mem_layout;
pub mod paging;
pub mod uefi_entry;
