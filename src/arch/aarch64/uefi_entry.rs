//! ARM64 UEFI firmware entry point.
//!
//! This path targets UEFI Arm64 machines with Armv8-A+ CPUs and a GICv2/GICv3
//! interrupt controller, matching the ReactOS ARM64 baseline hardware profile.

#![allow(dead_code)]

use core::ptr;

type EfiHandle = *mut core::ffi::c_void;
type EfiStatus = usize;

const EFI_SUCCESS: EfiStatus = 0;

#[repr(C)]
pub struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
pub struct EfiSystemTable {
    hdr: EfiTableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: EfiHandle,
    con_in: *mut core::ffi::c_void,
    console_out_handle: EfiHandle,
    con_out: *mut EfiSimpleTextOutput,
}

#[repr(C)]
pub struct EfiSimpleTextOutput {
    reset: usize,
    output_string: unsafe extern "efiapi" fn(*mut EfiSimpleTextOutput, *const u16) -> EfiStatus,
}

#[no_mangle]
pub unsafe extern "efiapi" fn efi_main(_image: EfiHandle, st: *mut EfiSystemTable) -> EfiStatus {
    if !st.is_null() {
        efi_print(
            (*st).con_out,
            "RustOS ARM64: UEFI + Armv8-A+ + GICv2/GICv3 baseline\r\n",
        );
    }
    crate::arch::aarch64::hal::init();
    crate::kernel_main::kernel_main_aarch64();
}

unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    if con_out.is_null() {
        return;
    }
    let mut buf = [0u16; 96];
    let mut i = 0usize;
    for b in s.bytes() {
        if i + 1 >= buf.len() {
            break;
        }
        buf[i] = b as u16;
        i += 1;
    }
    buf[i] = 0;
    let _ = ((*con_out).output_string)(con_out, ptr::addr_of!(buf[0]));
}
