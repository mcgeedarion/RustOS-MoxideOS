//! ARM64 boot helpers.
//!
//! The supported firmware entry is UEFI (`uefi_entry::efi_main`).  Bare-metal
//! non-UEFI boot is intentionally not a baseline target for the ARM64 port.

#[no_mangle]
pub extern "C" fn kernel_main_aarch64() -> ! {
    crate::kernel_main::kernel_main_aarch64()
}
