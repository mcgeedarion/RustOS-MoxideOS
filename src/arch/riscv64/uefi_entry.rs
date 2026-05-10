//! RISC-V UEFI firmware entry point — `uefi_start`.
//!
//! Mirrors src/arch/x86_64/uefi_entry.rs with the following differences:
//!   - Final stack-switch uses RISC-V inline assembly.
//!   - Entry ABI is `extern "efiapi"` (maps to standard RISC-V C calling convention).
//!   - GOP fallback message is omitted (RISC-V UEFI firmware often has no
//!     ConOut text output after firmware init; UART is the debug channel).
//!
//! ## Boot flow
//!   1. Print banner via UEFI SimpleTextOutput.
//!   2. Capture GOP framebuffer (graceful fallback if unavailable).
//!   3. Scan EFI configuration table for ACPI 2.0 RSDP and OVMF initrd.
//!   4. LoadFile2 initramfs protocol (real hardware / systemd-boot).
//!   5. Dynamic EFI memory map + ExitBootServices.
//!   6. Switch to kernel boot stack and tail-call kernel_main().

use core::arch::asm;

// ─── EFI types ─────────────────────────────────────────────────────────────────

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;

const EFI_SUCCESS:          EfiStatus = 0;
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
    allocate_pool:  unsafe extern "efiapi" fn(
        pool_type: u32,
        size:      usize,
        buffer:    *mut *mut u8,
    ) -> EfiStatus,
    free_pool:      unsafe extern "efiapi" fn(buffer: *mut u8) -> EfiStatus,
    _ev:            [*mut core::ffi::c_void; 5],
}

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

// ─── LoadFile2 ─────────────────────────────────────────────────────────────────

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

const LOCATE_HANDLE_BUFFER_OFFSET: usize = 0x0B0;
type LocateHandleBufferFn = unsafe extern "efiapi" fn(
    search_type: u32,
    protocol:    *const [u64; 2],
    search_key:  *mut core::ffi::c_void,
    no_handles:  *mut usize,
    buffer:      *mut *mut EfiHandle,
) -> EfiStatus;

const HANDLE_PROTOCOL_OFFSET: usize = 0x098;
type HandleProtocolFn = unsafe extern "efiapi" fn(
    handle:    EfiHandle,
    protocol:  *const [u64; 2],
    interface: *mut *mut core::ffi::c_void,
) -> EfiStatus;

const BY_PROTOCOL: u32 = 2;

const EXIT_BOOT_SERVICES_OFFSET: usize = 0x190;
type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

// ─── GUIDs ───────────────────────────────────────────────────────────────────

const ACPI2_GUID: [u64; 2] = [
    0x11d3_f1e4_71e8_6888,
    0x8188_3cc7_8000_22bc,
];

const INITRD_MEDIA_GUID: [u64; 2] = [
    0x4f3d_fc68_27e4_6855,
    0x68cc_3152_55ca_74ac,
];

// ─── Globals ──────────────────────────────────────────────────────────────────

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
    efi_print(st.con_out, "RustOS (RISC-V) booting via UEFI...\r\n");

    // 2. GOP framebuffer — graceful fallback (many RISC-V boards are serial-only).
    let _ = crate::drivers::gop::capture_from_boot_services(
        st.boot_services as *mut core::ffi::c_void,
    );

    // 3. ACPI RSDP + OVMF initrd config-table scan.
    let cfg = core::slice::from_raw_parts(st.configuration_table, st.num_table_entries);
    let mut ovmf_initrd_found = false;
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
        }
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

    // 4. LoadFile2 initramfs (real hardware / systemd-boot / GRUB2).
    if !ovmf_initrd_found {
        load_initrd_via_loadfile2(st.boot_services as *mut core::ffi::c_void, bs_base);
    }

    // 5. Dynamic EFI memory map.
    let mut map_size:  usize = 0;
    let mut map_key:   usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver:  u32   = 0;

    // Probe required size.
    let _ = (bs.get_memory_map)(
        &mut map_size,
        core::ptr::null_mut(),
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    map_size += 2048;

    let mut map_buf: *mut u8 = core::ptr::null_mut();
    let alloc_status = (bs.allocate_pool)(EFI_LOADER_DATA, map_size, &mut map_buf);
    if alloc_status != EFI_SUCCESS || map_buf.is_null() {
        // Non-recoverable — halt.
        loop { asm!("wfi", options(nostack, nomem)); }
    }

    let status = (bs.get_memory_map)(
        &mut map_size,
        map_buf as *mut EfiMemDescriptor,
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    if status != EFI_SUCCESS {
        loop { asm!("wfi", options(nostack, nomem)); }
    }

    // 6. ExitBootServices.
    let exit_fn = *((bs_base + EXIT_BOOT_SERVICES_OFFSET) as *const ExitBootServicesFn);
    let _ = exit_fn(image_handle, map_key);

    // 7. Switch to kernel boot stack and call kernel_main.
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

// ─── LoadFile2 initramfs ──────────────────────────────────────────────────────────

unsafe fn load_initrd_via_loadfile2(
    boot_services: *mut core::ffi::c_void,
    bs_base: usize,
) {
    let bs = &*(boot_services as *mut EfiBootServices);

    let locate_handle_buffer: LocateHandleBufferFn =
        *((bs_base + LOCATE_HANDLE_BUFFER_OFFSET) as *const LocateHandleBufferFn);
    let handle_protocol: HandleProtocolFn =
        *((bs_base + HANDLE_PROTOCOL_OFFSET) as *const HandleProtocolFn);

    let mut num_handles: usize = 0;
    let mut handle_buf: *mut EfiHandle = core::ptr::null_mut();
    let status = locate_handle_buffer(
        BY_PROTOCOL,
        &INITRD_MEDIA_GUID,
        core::ptr::null_mut(),
        &mut num_handles,
        &mut handle_buf,
    );
    if status != EFI_SUCCESS || num_handles == 0 { return; }

    let handle = *handle_buf;
    let mut lf2_iface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = handle_protocol(handle, &INITRD_MEDIA_GUID, &mut lf2_iface);
    if status != EFI_SUCCESS || lf2_iface.is_null() { return; }

    let lf2 = &*(lf2_iface as *mut EfiLoadFile2Protocol);

    let mut initrd_size: usize = 0;
    let status = (lf2.load_file)(
        lf2_iface as *mut EfiLoadFile2Protocol,
        core::ptr::null_mut(),
        0,
        &mut initrd_size,
        core::ptr::null_mut(),
    );
    if status != EFI_BUFFER_TOO_SMALL || initrd_size == 0 { return; }

    let mut initrd_buf: *mut u8 = core::ptr::null_mut();
    let alloc_status = (bs.allocate_pool)(EFI_LOADER_DATA, initrd_size, &mut initrd_buf);
    if alloc_status != EFI_SUCCESS || initrd_buf.is_null() { return; }

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
}

// ─── EFI text output helper ────────────────────────────────────────────────────

unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}
