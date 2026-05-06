//! RISC-V UEFI firmware entry point — `uefi_start`.
//!
//! Mirrors src/arch/x86_64/uefi_entry.rs exactly, with the only
//! arch-specific differences being:
//!   - The final stack-switch uses RISC-V inline assembly.
//!   - The entry ABI is `extern "efiapi"` (maps to standard RISC-V CC).
//!
//! ## Boot flow
//!   1. Print banner via UEFI SimpleTextOutput.
//!   2. Capture GOP framebuffer (-> drivers::gop::GOP_INFO).
//!   3. Scan EFI configuration table for ACPI 2.0 RSDP.
//!   4. Call ExitBootServices to release firmware ownership.
//!   5. Switch to kernel boot stack and tail-call kernel_main().

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

const ACPI2_GUID: [u64; 2] = [
    0x11d3_f1e4_71e8_6888,
    0x8188_3cc7_8000_22bc,
];

const EXIT_BOOT_SERVICES_OFFSET: usize = 0x190;
type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

// ─── Globals ───────────────────────────────────────────────────────────────────
pub static mut RSDP_PHYS: u64 = 0;
static mut MAP_BUF: [u8; 4096] = [0u8; 4096];

// ─── Entry point ─────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "efiapi" fn uefi_start(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    let st = &*system_table;
    let bs = &*st.boot_services;

    // 1. Banner.
    efi_print(st.con_out, "RustOS (RISC-V) booting via UEFI...\r\n");

    // 2. Capture GOP framebuffer before ExitBootServices.
    crate::drivers::gop::capture_from_boot_services(st.boot_services as *mut core::ffi::c_void);

    // 3. Locate RSDP in EFI configuration table.
    let cfg = core::slice::from_raw_parts(st.configuration_table, st.num_table_entries);
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
            break;
        }
    }

    // 4. Get memory map + map key.
    let mut map_size:  usize = MAP_BUF.len();
    let mut map_key:   usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver:  u32   = 0;
    let map_ptr = MAP_BUF.as_mut_ptr() as *mut EfiMemDescriptor;
    let _ = (bs.get_memory_map)(
        &mut map_size, map_ptr, &mut map_key, &mut desc_size, &mut desc_ver,
    );

    // 5. ExitBootServices.
    let bs_base = st.boot_services as usize;
    let exit_fn = *((bs_base + EXIT_BOOT_SERVICES_OFFSET) as *const ExitBootServicesFn);
    let _ = exit_fn(image_handle, map_key);

    // 6. Switch to kernel boot stack (defined in boot.rs / linker.ld) and call kernel_main.
    extern "C" {
        fn kernel_main() -> !;
        static BOOT_STACK_TOP: [u8; 0];
    }
    asm!(
        "la   sp, {stack_top}",
        "mv   s0, zero",
        "call {km}",
        "1:  wfi",
        "j   1b",
        stack_top = sym BOOT_STACK_TOP,
        km        = sym kernel_main,
        options(noreturn),
    );
}

// ─── EFI text output helper ──────────────────────────────────────────────────

unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}
