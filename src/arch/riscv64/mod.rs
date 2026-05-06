// SBI boot entry (default — OpenSBI hands off to _start).
#[cfg(not(feature = "uefi_boot"))]
pub mod boot;

// UEFI boot entry (EDK2 RISC-V Virt calls uefi_start).
// Enable with: cargo build --features uefi_boot
#[cfg(feature = "uefi_boot")]
pub mod uefi_entry;

pub mod csr;
pub mod hal;
pub mod paging;
pub mod syscall;
pub mod trap;
pub mod trampoline;
pub mod uentry;
