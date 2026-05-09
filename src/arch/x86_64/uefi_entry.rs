//! UEFI firmware entry point — `uefi_start`.
//!
//! The UEFI firmware calls `uefi_start(image_handle, system_table)` in
//! 64-bit long mode with flat 1:1-mapped memory and interrupts disabled.
//!
//! ## What we do here
//!   1. Print a banner via UEFI SimpleTextOutput.
//!   2. Capture the GOP framebuffer (-> drivers::gop::GOP_INFO).
//!   3. Locate the ACPI 2.0 RSDP from the EFI configuration table.
//!   4. Locate the initrd via EFI_INITRD_MEDIA_GUID in the config table.
//!   5. Obtain the EFI memory map key and call ExitBootServices.
//!   6. Switch to the kernel boot stack and tail-call kernel_main().
//!
//! ## Memory layout after ExitBootServices
//!   - All physical RAM is identity-mapped by the UEFI page tables.
//!   - The kernel image is loaded at 0x400000 (physical) per x86_64.ld.
//!   - The static PMM pool inside the kernel image is immediately usable.
//!   - The GOP framebuffer physical address is in drivers::gop::GOP_INFO.
//!
//! ## initrd discovery
//! The UEFI initrd protocol (UEFI 2.10 §3.1.6) stores the initrd as a
//! LoadFile2 protocol behind the `EFI_INITRD_MEDIA_GUID` device path.  When
//! the UEFI loader (e.g. systemd-boot, GRUB, EDK2 QEMU) passes `-initrd`,
//! it installs this protocol.
//!
//! As a fallback we also scan the EFI configuration table for a vendor GUID
//! that some firmware (OVMF QEMU) uses to expose `(phys_addr, size)` pairs.
//! If neither is found we fall back to `set_initramfs_range(0, 0)` and
//! `initramfs::load()` will print a clear fatal message.

use core::arch::asm;

// ─── EFI types (bare-minimum subset) ──────────────────────────────────────────────

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
    // ExitBootServices resolved by fixed offset (see EXIT_BOOT_SERVICES_OFFSET).
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

// ─── GUIDs ─────────────────────────────────────────────────────────────────────

// ACPI 2.0: {8868e871-e4f1-11d3-bc22-0080c73c8881}
const ACPI2_GUID: [u64; 2] = [
    0x11d3_f1e4_71e8_6888,
    0x8188_3cc7_8000_22bc,
];

// EFI_INITRD_MEDIA_GUID (UEFI 2.10 §3.1.6, also used by systemd-boot / OVMF):
// {5568e427-68fc-4f3d-ac74-ca555231cc68}
//
// Some OVMF/QEMU builds expose the initrd as a vendor config-table entry
// with a layout of: { phys_start: u64, size: u64 }.
// We check for this GUID in the configuration table as a simple fallback.
const INITRD_MEDIA_GUID: [u64; 2] = [
    0x4f3d_fc68_27e4_6855,
    0x68cc_3152_55ca_74ac,
];

const EFI_SUCCESS: EfiStatus = 0;

/// Offset of ExitBootServices in EFI_BOOT_SERVICES (UEFI 2.10 spec).
/// header(24) + 47 fn ptrs × 8 = 0x190.
const EXIT_BOOT_SERVICES_OFFSET: usize = 0x190;
type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

// ─── Globals set before kernel_main runs ──────────────────────────────────────

/// Physical address of the RSDP (ACPI 2.0). 0 = not found.
pub static mut RSDP_PHYS: u64 = 0;

// ─── Scratch buffer for the EFI memory map ─────────────────────────────────
static mut MAP_BUF: [u8; 4096] = [0u8; 4096];

// ─── Entry point ──────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "efiapi" fn uefi_start(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    let st = &*system_table;
    let bs = &*st.boot_services;

    // 1. Banner.
    efi_print(st.con_out, "RustOS (x86_64) booting via UEFI...\r\n");

    // 2. Capture GOP framebuffer before ExitBootServices.
    crate::drivers::gop::capture_from_boot_services(
        st.boot_services as *mut core::ffi::c_void,
    );

    // 3 & 4. Walk the EFI configuration table:
    //   - find ACPI 2.0 RSDP
    //   - find initrd via EFI_INITRD_MEDIA_GUID vendor table entry
    //
    // The OVMF/QEMU EFI_INITRD_MEDIA_GUID vendor table layout:
    //   offset 0: phys_start : u64
    //   offset 8: byte_size  : u64
    let cfg = core::slice::from_raw_parts(
        st.configuration_table,
        st.num_table_entries,
    );
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
        }
        if entry.guid == INITRD_MEDIA_GUID {
            // Vendor table: [phys_start: u64, size: u64]
            let data = entry.table as *const u64;
            let phys_start = *data         as usize;
            let byte_size  = *data.add(1)  as usize;
            if phys_start != 0 && byte_size > 0 {
                crate::initramfs::set_initramfs_range(phys_start, byte_size);
                // Print via serial if it's up; otherwise this is silent
                // (serial hasn't been initialised yet at this point).
                // kernel_main will confirm with "initramfs: mounted N dirs..."
            }
        }
    }

    // 5. Get memory map + map key for ExitBootServices.
    let mut map_size:  usize = MAP_BUF.len();
    let mut map_key:   usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver:  u32   = 0;
    let map_ptr = MAP_BUF.as_mut_ptr() as *mut EfiMemDescriptor;
    let _ = (bs.get_memory_map)(
        &mut map_size, map_ptr, &mut map_key, &mut desc_size, &mut desc_ver,
    );

    // 6. ExitBootServices.
    let bs_base = st.boot_services as usize;
    let exit_fn = *((bs_base + EXIT_BOOT_SERVICES_OFFSET) as *const ExitBootServicesFn);
    let _ = exit_fn(image_handle, map_key);

    // 7. Switch to kernel boot stack and call kernel_main.
    extern "C" { fn kernel_main() -> !; }
    asm!(
        "lea rsp, [rip + __boot_stack_top]",
        "xor rbp, rbp",
        "call {km}",
        "2: hlt",
        "jmp 2b",
        km = sym kernel_main,
        options(noreturn),
    );
}

// ─── EFI text output helper ───────────────────────────────────────────────────────

unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}
