//! RISC-V UEFI firmware entry point — `uefi_start`.
//!
//! Mirrors src/arch/x86_64/uefi_entry.rs exactly, with the only
//! arch-specific differences being:
//!   - The final stack-switch uses RISC-V inline assembly.
//!   - The entry ABI is `extern "efiapi"` (maps to standard RISC-V CC).
//!
//! ## Boot flow
//!   1. EDK2 (RISC-V Virt) loads BOOTRISCV64.EFI from the ESP and calls
//!      uefi_start(image_handle, system_table) in U-mode / S-mode with
//!      a flat 1:1-mapped identity map and interrupts disabled.
//!   2. We scan the EFI configuration table for the ACPI 2.0 RSDP.
//!   3. We call ExitBootServices to release firmware ownership.
//!   4. We switch to the kernel boot stack and tail-call kernel_main().
//!
//! ## No SBI dependency
//!   This path does not call any SBI ecalls.  Console I/O before
//!   ExitBootServices goes through the UEFI SimpleTextOutput protocol.
//!   After ExitBootServices the kernel uses its own UART driver.

use core::arch::asm;

// ─── EFI types (bare-minimum subset, arch-independent) ───────────────────────

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;

#[repr(C)]
struct EfiTableHeader {
    signature:   u64,
    revision:    u32,
    header_size: u32,
    crc32:       u32,
    _reserved:   u32,
}

#[repr(C)]
struct EfiSystemTable {
    hdr:                 EfiTableHeader,
    firmware_vendor:     *const u16,
    firmware_revision:   u32,
    _pad:                u32,
    console_in_handle:   EfiHandle,
    con_in:              *mut core::ffi::c_void,
    console_out_handle:  EfiHandle,
    con_out:             *mut EfiSimpleTextOutput,
    std_err_handle:      EfiHandle,
    std_err:             *mut core::ffi::c_void,
    runtime_services:    *mut core::ffi::c_void,
    boot_services:       *mut EfiBootServices,
    num_table_entries:   usize,
    configuration_table: *mut EfiConfigTable,
}

#[repr(C)]
struct EfiSimpleTextOutput {
    reset:         *mut core::ffi::c_void,
    output_string: unsafe extern "efiapi" fn(*mut EfiSimpleTextOutput, *const u16) -> EfiStatus,
    // remaining fields omitted
}

#[repr(C)]
struct EfiBootServices {
    hdr:            EfiTableHeader,
    _tpl_raise:     *mut core::ffi::c_void,
    _tpl_restore:   *mut core::ffi::c_void,
    _alloc_pages:   *mut core::ffi::c_void,
    _free_pages:    *mut core::ffi::c_void,
    get_memory_map: unsafe extern "efiapi" fn(
        map_size:     *mut usize,
        map:          *mut EfiMemDescriptor,
        map_key:      *mut usize,
        desc_size:    *mut usize,
        desc_version: *mut u32,
    ) -> EfiStatus,
    _alloc_pool:    *mut core::ffi::c_void,
    _free_pool:     *mut core::ffi::c_void,
    _ev:            [*mut core::ffi::c_void; 5],
    // ExitBootServices resolved by fixed offset below.
}

#[repr(C)]
struct EfiMemDescriptor {
    type_:          u32,
    _pad:           u32,
    physical_start: u64,
    virtual_start:  u64,
    num_pages:      u64,
    attribute:      u64,
}

#[repr(C)]
struct EfiConfigTable {
    guid:  [u64; 2],
    table: *mut core::ffi::c_void,
}

// ACPI 2.0 GUID: {8868e871-e4f1-11d3-bc22-0080c73c8881}
const ACPI2_GUID: [u64; 2] = [
    0x11d3_f1e4_71e8_6888,
    0x8188_3cc7_8000_22bc,
];

const EFI_SUCCESS: EfiStatus = 0;

/// Offset of ExitBootServices in EFI_BOOT_SERVICES.
/// UEFI 2.10 spec: header (24 bytes) + 47 pointer-sized fields * 8 = 400 = 0x190.
/// Identical on all 64-bit UEFI platforms.
const EXIT_BOOT_SERVICES_OFFSET: usize = 0x190;
type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

// ─── Globals set before kernel_main runs ─────────────────────────────────────

/// Physical address of the RSDP (ACPI 2.0).  0 = not found.
pub static mut RSDP_PHYS: u64 = 0;

// ─── Scratch buffer for EFI memory map (static; no heap before EBS) ──────────
static mut MAP_BUF: [u8; 4096] = [0u8; 4096];

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Called by EDK2 RISC-V Virt firmware as the EFI application entry point.
///
/// Signature mandated by the UEFI spec (identical on all arches):
///   EFI_STATUS EFIAPI EfiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
#[no_mangle]
pub unsafe extern "efiapi" fn uefi_start(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    let st = &*system_table;
    let bs = &*st.boot_services;

    // 1. Banner via UEFI console.
    efi_print(st.con_out, "RustOS (RISC-V) booting via UEFI...\r\n");

    // 2. Locate RSDP in EFI configuration table.
    let cfg = core::slice::from_raw_parts(st.configuration_table, st.num_table_entries);
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
            break;
        }
    }

    // 3. Fetch memory map + map key required for ExitBootServices.
    let mut map_size:  usize = MAP_BUF.len();
    let mut map_key:   usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver:  u32   = 0;
    let map_ptr = MAP_BUF.as_mut_ptr() as *mut EfiMemDescriptor;

    let status = (bs.get_memory_map)(
        &mut map_size, map_ptr, &mut map_key, &mut desc_size, &mut desc_ver,
    );
    // A too-small buffer returns EFI_BUFFER_TOO_SMALL but still writes map_key,
    // which is all we need for ExitBootServices on QEMU.
    let _ = status;

    // 4. Exit boot services — firmware is no longer reachable after this.
    let bs_base = st.boot_services as usize;
    let exit_fn = *((bs_base + EXIT_BOOT_SERVICES_OFFSET) as *const ExitBootServicesFn);
    let _ = exit_fn(image_handle, map_key);

    // 5. Switch to the kernel boot stack (defined in boot.rs / linker.ld)
    //    and call kernel_main.  fp = 0 terminates GDB backtraces cleanly.
    extern "C" {
        fn kernel_main() -> !;
        static BOOT_STACK_TOP: [u8; 0];
    }
    asm!(
        "la   sp, {stack_top}",
        "mv   s0, zero",        // fp = 0
        "call {km}",
        "1:  wfi",
        "j   1b",
        stack_top = sym BOOT_STACK_TOP,
        km        = sym kernel_main,
        options(noreturn),
    );
}

// ─── EFI text output helper ───────────────────────────────────────────────────

/// Print an ASCII string via UEFI SimpleTextOutput (UCS-2, max 127 chars).
unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}
