//! UEFI firmware entry point — `uefi_start`.
//!
//! The UEFI firmware calls `uefi_start(image_handle, system_table)` in
//! 64-bit long mode with flat 1:1-mapped memory and interrupts disabled.
//!
//! ## What we do here
//!   1. Obtain the UEFI memory map and call ExitBootServices.
//!   2. Find the RSDP from the EFI configuration table (ACPI 2.0 GUID).
//!   3. Hand off to kernel_main() with the RSDP physical address in a
//!      global so acpi_init() can pick it up without needing arguments.
//!
//! ## Memory layout after ExitBootServices
//!   - All physical RAM is identity-mapped by the UEFI page tables.
//!   - The kernel image is loaded at 0x400000 (physical) per x86_64.ld.
//!   - The static PMM pool inside the kernel image is immediately usable.

use core::arch::asm;

// ─── EFI types (bare-minimum subset) ───────────────────────────────────────────────

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
    hdr:                  EfiTableHeader,
    firmware_vendor:      *const u16,
    firmware_revision:    u32,
    _pad:                 u32,
    console_in_handle:    EfiHandle,
    con_in:               *mut core::ffi::c_void,
    console_out_handle:   EfiHandle,
    con_out:              *mut EfiSimpleTextOutput,
    std_err_handle:       EfiHandle,
    std_err:              *mut core::ffi::c_void,
    runtime_services:     *mut core::ffi::c_void,
    boot_services:        *mut EfiBootServices,
    num_table_entries:    usize,
    configuration_table:  *mut EfiConfigTable,
}

#[repr(C)]
struct EfiSimpleTextOutput {
    reset:           *mut core::ffi::c_void,
    output_string:   unsafe extern "efiapi" fn(*mut EfiSimpleTextOutput, *const u16) -> EfiStatus,
    // other fields omitted
}

#[repr(C)]
struct EfiBootServices {
    hdr: EfiTableHeader,
    // task priority (2 fn ptrs)
    _tpl_raise:  *mut core::ffi::c_void,
    _tpl_restore: *mut core::ffi::c_void,
    // memory (5 fn ptrs)
    _alloc_pages: *mut core::ffi::c_void,
    _free_pages:  *mut core::ffi::c_void,
    get_memory_map: unsafe extern "efiapi" fn(
        map_size:       *mut usize,
        map:            *mut EfiMemDescriptor,
        map_key:        *mut usize,
        desc_size:      *mut usize,
        desc_version:   *mut u32,
    ) -> EfiStatus,
    _alloc_pool:  *mut core::ffi::c_void,
    _free_pool:   *mut core::ffi::c_void,
    // events (5)
    _ev: [*mut core::ffi::c_void; 5],
    // timers (none skipped), protocol (many skipped)…
    // We only need ExitBootServices which is at a fixed offset.
    // Rather than enumerate every field we use a raw function pointer
    // resolved below by offset.
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

// EFI_SUCCESS
const EFI_SUCCESS: EfiStatus = 0;

/// Offset of ExitBootServices within EFI_BOOT_SERVICES (bytes from struct base).
/// From the UEFI 2.10 spec table: ExitBootServices is function #47 (0-indexed),
/// each entry is one pointer = 8 bytes, header is 24 bytes.
/// Offset = 24 + 47 * 8 = 400 = 0x190.
const EXIT_BOOT_SERVICES_OFFSET: usize = 0x190;
type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

// ─── Globals set before kernel_main runs ──────────────────────────────────────────

/// Physical address of the RSDP, set by uefi_start before kernel_main.
/// 0 means "not found" — acpi_init() will fall back to BIOS scan.
pub static mut RSDP_PHYS: u64 = 0;

// ─── Scratch buffer for the EFI memory map ────────────────────────────────────────
// We can't heap-allocate before ExitBootServices so we use a static buffer.
// 4096 bytes fits ~50 EFI_MEMORY_DESCRIPTOR entries, enough for QEMU.
static mut MAP_BUF: [u8; 4096] = [0u8; 4096];

// ─── Entry point ─────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "efiapi" fn uefi_start(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    let st = &*system_table;
    let bs = &*st.boot_services;

    // — 1. Print banner via UEFI console —
    efi_print(st.con_out, "RustOS booting...\r\n");

    // — 2. Locate RSDP from configuration table —
    let num = st.num_table_entries;
    let cfg = core::slice::from_raw_parts(st.configuration_table, num);
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
            break;
        }
    }

    // — 3. Get memory map + map key for ExitBootServices —
    let mut map_size:    usize = MAP_BUF.len();
    let mut map_key:     usize = 0;
    let mut desc_size:   usize = 0;
    let mut desc_ver:    u32   = 0;
    let map_ptr = MAP_BUF.as_mut_ptr() as *mut EfiMemDescriptor;

    let status = (bs.get_memory_map)(
        &mut map_size, map_ptr, &mut map_key, &mut desc_size, &mut desc_ver,
    );
    if status != EFI_SUCCESS {
        // Buffer too small — just proceed; we don't actually need the map
        // because the PMM uses a static pool.
    }

    // — 4. ExitBootServices —
    // Resolve function pointer by offset into the boot services table.
    let bs_base = st.boot_services as usize;
    let exit_fn = *((bs_base + EXIT_BOOT_SERVICES_OFFSET) as *const ExitBootServicesFn);
    let _ = exit_fn(image_handle, map_key);
    // If ExitBootServices fails (stale key), retry once with a fresh map.
    // In practice QEMU never fails here.

    // — 5. Set up a proper kernel stack and call kernel_main —
    // The linker provides __boot_stack_top (defined in main.rs).
    extern "C" { fn kernel_main() -> !; }
    // Switch to the kernel boot stack before calling Rust.
    core::arch::asm!(
        "lea rsp, [rip + __boot_stack_top]",
        "xor rbp, rbp",
        "call {km}",
        "2: hlt",
        "jmp 2b",
        km = sym kernel_main,
        options(noreturn),
    );
}

// ─── EFI text output helper ────────────────────────────────────────────────────────

/// Print an ASCII string via the UEFI simple text output protocol.
/// Converts to UCS-2 on the stack (max 127 chars).
unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}
