//! UEFI firmware entry point — `uefi_start`.
//!
//! The UEFI firmware calls `uefi_start(image_handle, system_table)` in
//! 64-bit long mode with flat 1:1-mapped memory and interrupts disabled.
//!
//! ## What we do here
//!   1. Print a banner via UEFI SimpleTextOutput.
//!   2. Capture the GOP framebuffer (graceful fallback if not available).
//!   3. Locate the ACPI 2.0 RSDP from the EFI configuration table.
//!   4. Locate the initrd:
//!        a. EFI_INITRD_MEDIA_GUID LoadFile2 protocol  (systemd-boot / GRUB2 / real HW)
//!        b. OVMF vendor config-table fallback          (QEMU -initrd flag)
//!   5. Obtain the EFI memory map dynamically and call ExitBootServices.
//!   6. Switch to the kernel boot stack and tail-call kernel_main().
//!
//! ## Memory layout after ExitBootServices
//!   - All physical RAM is identity-mapped by the UEFI page tables.
//!   - The kernel image is loaded at 0x400000 (physical) per x86_64.ld.
//!   - The static PMM pool inside the kernel image is immediately usable.
//!   - The GOP framebuffer physical address is in drivers::gop::GOP_INFO
//!     (zeroed when GOP was unavailable — serial-only mode).

use core::arch::asm;

// ─── EFI types (bare-minimum subset) ─────────────────────────────────────────

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;

const EFI_SUCCESS:     EfiStatus = 0;
const EFI_BUFFER_TOO_SMALL: EfiStatus = 0x8000_0000_0000_0005;

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

/// Subset of EFI_BOOT_SERVICES we actually call.
/// Fields are function pointers at fixed offsets per the UEFI 2.10 spec.
#[repr(C)]
struct EfiBootServices {
    hdr:              EfiTableHeader,             // 0x000
    _tpl_raise:       *mut core::ffi::c_void,     // 0x018
    _tpl_restore:     *mut core::ffi::c_void,     // 0x020
    _alloc_pages:     *mut core::ffi::c_void,     // 0x028
    _free_pages:      *mut core::ffi::c_void,     // 0x030
    get_memory_map:   unsafe extern "efiapi" fn(  // 0x038
        map_size:     *mut usize,
        map:          *mut EfiMemDescriptor,
        map_key:      *mut usize,
        desc_size:    *mut usize,
        desc_version: *mut u32,
    ) -> EfiStatus,
    allocate_pool:    unsafe extern "efiapi" fn(  // 0x040
        pool_type:    u32,
        size:         usize,
        buffer:       *mut *mut u8,
    ) -> EfiStatus,
    free_pool:        unsafe extern "efiapi" fn(  // 0x048
        buffer:       *mut u8,
    ) -> EfiStatus,
    _ev:              [*mut core::ffi::c_void; 5],// 0x050
    // locate_handle_buffer at offset 0x0B0 (resolved via fixed offset below)
    // ExitBootServices at offset 0x190 (resolved via fixed offset below)
}

// EfiMemoryType variants we care about for allocate_pool.
const EFI_LOADER_DATA: u32 = 2;

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

// ─── LoadFile2 protocol for initramfs ─────────────────────────────────────────
//
// EFI_LOAD_FILE2_PROTOCOL.LoadFile signature:
//   EFI_STATUS LoadFile(
//       EFI_LOAD_FILE2_PROTOCOL  *This,
//       EFI_DEVICE_PATH_PROTOCOL *FilePath,   // ignored for initrd
//       BOOLEAN                   BootPolicy, // must be FALSE
//       UINTN                    *BufferSize,
//       VOID                     *Buffer      // NULL to query size
//   );

#[repr(C)]
struct EfiLoadFile2Protocol {
    load_file: unsafe extern "efiapi" fn(
        this:        *mut EfiLoadFile2Protocol,
        file_path:   *mut core::ffi::c_void,
        boot_policy: u8,
        buffer_size: *mut usize,
        buffer:      *mut core::ffi::c_void,
    ) -> EfiStatus,
}

// ─── Fixed offsets into EFI_BOOT_SERVICES ─────────────────────────────────────

/// `EFI_BOOT_SERVICES.LocateHandleBuffer` at offset 0x0B0.
const LOCATE_HANDLE_BUFFER_OFFSET: usize = 0x0B0;
type LocateHandleBufferFn = unsafe extern "efiapi" fn(
    search_type: u32,
    protocol:    *const [u64; 2],
    search_key:  *mut core::ffi::c_void,
    no_handles:  *mut usize,
    buffer:      *mut *mut EfiHandle,
) -> EfiStatus;

/// Search type: ByProtocol.
const BY_PROTOCOL: u32 = 2;

/// `EFI_BOOT_SERVICES.HandleProtocol` at offset 0x098.
const HANDLE_PROTOCOL_OFFSET: usize = 0x098;
type HandleProtocolFn = unsafe extern "efiapi" fn(
    handle:    EfiHandle,
    protocol:  *const [u64; 2],
    interface: *mut *mut core::ffi::c_void,
) -> EfiStatus;

/// `EFI_BOOT_SERVICES.ExitBootServices` at offset 0x190.
const EXIT_BOOT_SERVICES_OFFSET: usize = 0x190;
type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

// ─── GUIDs ────────────────────────────────────────────────────────────────────

// ACPI 2.0: {8868e871-e4f1-11d3-bc22-0080c73c8881}
const ACPI2_GUID: [u64; 2] = [
    0x11d3_f1e4_71e8_6888,
    0x8188_3cc7_8000_22bc,
];

// EFI_INITRD_MEDIA_GUID: {5568e427-68fc-4f3d-ac74-ca555231cc68}
// Used both as the LoadFile2 protocol GUID (real HW / systemd-boot / GRUB2)
// and as the OVMF vendor config-table GUID (QEMU -initrd fallback).
const INITRD_MEDIA_GUID: [u64; 2] = [
    0x4f3d_fc68_27e4_6855,
    0x68cc_3152_55ca_74ac,
];

// ─── Globals set before kernel_main runs ──────────────────────────────────────

/// Physical address of the RSDP (ACPI 2.0). 0 = not found.
pub static mut RSDP_PHYS: u64 = 0;

// ─── Entry point ──────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "efiapi" fn uefi_start(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    let st = &*system_table;
    let bs = &*st.boot_services;
    let bs_base = st.boot_services as usize;

    // 1. Banner.
    efi_print(st.con_out, "RustOS (x86_64) booting via UEFI...\r\n");

    // 2. Capture GOP framebuffer — graceful fallback if firmware has no GOP.
    //    (headless servers, serial-only setups)
    let gop_ok = crate::drivers::gop::capture_from_boot_services(
        st.boot_services as *mut core::ffi::c_void,
    );
    if !gop_ok {
        efi_print(st.con_out, "rustos: GOP not available — serial-only mode\r\n");
    }

    // 3 & 4. Walk EFI configuration table for ACPI RSDP and OVMF initrd fallback.
    let cfg = core::slice::from_raw_parts(
        st.configuration_table,
        st.num_table_entries,
    );
    let mut ovmf_initrd_found = false;
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
        }
        // OVMF/QEMU vendor config-table initrd: [phys_start: u64, size: u64]
        if entry.guid == INITRD_MEDIA_GUID {
            let data = entry.table as *const u64;
            let phys_start = *data        as usize;
            let byte_size  = *data.add(1) as usize;
            if phys_start != 0 && byte_size > 0 {
                crate::initramfs::set_initramfs_range(phys_start, byte_size);
                ovmf_initrd_found = true;
            }
        }
    }

    // 4a. LoadFile2 protocol initramfs (real bootloaders: systemd-boot, GRUB2).
    //     Only attempted when the OVMF vendor-table path didn't fire.
    if !ovmf_initrd_found {
        load_initrd_via_loadfile2(st.boot_services as *mut core::ffi::c_void, bs_base);
    }

    // 5. Get EFI memory map with a dynamically sized buffer.
    //    First call with map_size=0 returns EFI_BUFFER_TOO_SMALL and tells us
    //    the exact number of bytes required.  We add 2 KiB headroom because
    //    AllocatePool itself can add descriptors between the two calls.
    let mut map_size:  usize = 0;
    let mut map_key:   usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver:  u32   = 0;

    // Probe for required size.
    let _ = (bs.get_memory_map)(
        &mut map_size,
        core::ptr::null_mut(),
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    // map_size now holds the required byte count; add 2 KiB headroom.
    map_size += 2048;

    // Allocate buffer from EFI pool.
    let mut map_buf: *mut u8 = core::ptr::null_mut();
    let alloc_status = (bs.allocate_pool)(EFI_LOADER_DATA, map_size, &mut map_buf);
    if alloc_status != EFI_SUCCESS || map_buf.is_null() {
        efi_print(st.con_out, "rustos: FATAL: AllocatePool for memory map failed\r\n");
        loop { asm!("hlt", options(nostack, nomem)); }
    }

    // Second call: populate the map.
    let status = (bs.get_memory_map)(
        &mut map_size,
        map_buf as *mut EfiMemDescriptor,
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    if status != EFI_SUCCESS {
        efi_print(st.con_out, "rustos: FATAL: GetMemoryMap failed\r\n");
        loop { asm!("hlt", options(nostack, nomem)); }
    }

    // 6. ExitBootServices (map_buf is no longer usable after this returns).
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

// ─── LoadFile2 initramfs (real hardware / systemd-boot / GRUB2) ───────────────

unsafe fn load_initrd_via_loadfile2(
    boot_services: *mut core::ffi::c_void,
    bs_base: usize,
) {
    let bs = &*(boot_services as *mut EfiBootServices);

    // Resolve LocateHandleBuffer and HandleProtocol from their fixed offsets.
    let locate_handle_buffer: LocateHandleBufferFn =
        *((bs_base + LOCATE_HANDLE_BUFFER_OFFSET) as *const LocateHandleBufferFn);
    let handle_protocol: HandleProtocolFn =
        *((bs_base + HANDLE_PROTOCOL_OFFSET) as *const HandleProtocolFn);

    // Find handles that support the EFI_INITRD_MEDIA_GUID LoadFile2 protocol.
    let mut num_handles: usize = 0;
    let mut handle_buf: *mut EfiHandle = core::ptr::null_mut();
    let status = locate_handle_buffer(
        BY_PROTOCOL,
        &INITRD_MEDIA_GUID,
        core::ptr::null_mut(),
        &mut num_handles,
        &mut handle_buf,
    );
    if status != EFI_SUCCESS || num_handles == 0 {
        // No LoadFile2 handle for initrd — not an error, just no initrd available.
        return;
    }

    // Use the first handle.
    let handle = *handle_buf;

    // Get the LoadFile2 protocol interface.
    let mut lf2_iface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = handle_protocol(handle, &INITRD_MEDIA_GUID, &mut lf2_iface);
    if status != EFI_SUCCESS || lf2_iface.is_null() {
        return;
    }
    let lf2 = &*(lf2_iface as *mut EfiLoadFile2Protocol);

    // First LoadFile call with buffer=NULL to query the initrd size.
    let mut initrd_size: usize = 0;
    let status = (lf2.load_file)(
        lf2_iface as *mut EfiLoadFile2Protocol,
        core::ptr::null_mut(),
        0, // BootPolicy = FALSE
        &mut initrd_size,
        core::ptr::null_mut(),
    );
    // EFI_BUFFER_TOO_SMALL is the expected success response when buffer=NULL.
    if status != EFI_BUFFER_TOO_SMALL || initrd_size == 0 {
        return;
    }

    // Allocate EfiLoaderData pages for the initrd.
    let mut initrd_buf: *mut u8 = core::ptr::null_mut();
    let alloc_status = (bs.allocate_pool)(EFI_LOADER_DATA, initrd_size, &mut initrd_buf);
    if alloc_status != EFI_SUCCESS || initrd_buf.is_null() {
        return;
    }

    // Second LoadFile call: actually read the initrd.
    let status = (lf2.load_file)(
        lf2_iface as *mut EfiLoadFile2Protocol,
        core::ptr::null_mut(),
        0,
        &mut initrd_size,
        initrd_buf as *mut core::ffi::c_void,
    );
    if status == EFI_SUCCESS {
        crate::initramfs::set_initramfs_range(initrd_buf as usize, initrd_size);
    }
    // On failure we simply leave initramfs range at (0, 0); kernel will warn.
}

// ─── EFI text output helper ───────────────────────────────────────────────────

unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}
