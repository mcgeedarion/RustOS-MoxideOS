//! ARM64 UEFI firmware entry point — `efi_main`.
//!
//! ## Boot priority: SECONDARY (aarch64 — secondary boot target)
//!
//! The UEFI firmware calls `efi_main(image_handle, system_table)` at EL1
//! (or EL2 reduced to EL1 by firmware) with interrupts disabled and a
//! flat identity-mapped address space.
//!
//! ## What we do here
//!   1. Print a banner via UEFI SimpleTextOutput.
//!   2. Capture the GOP framebuffer (graceful fallback if not available).
//!   3. Locate the ACPI 2.0 RSDP from the EFI configuration table.
//!   4. Locate the initrd via OVMF config table or LoadFile2.
//!   5. Obtain the EFI memory map and call ExitBootServices.
//!   6. Switch to the kernel boot stack and tail-call kernel_main().

#![allow(dead_code)]

use crate::init::boot_info::{BootInfo, BootRange, EfiMemoryMapInfo};
use core::arch::asm;

type EfiHandle = *mut core::ffi::c_void;
type EfiStatus = usize;

const EFI_SUCCESS: EfiStatus = 0;
const EFI_INVALID_PARAMETER: EfiStatus = 0x8000_0000_0000_0002;
const EFI_BUFFER_TOO_SMALL: EfiStatus = 0x8000_0000_0000_0005;

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
struct EfiSystemTable {
    hdr: EfiTableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    _pad: u32,
    console_in_handle: EfiHandle,
    con_in: *mut core::ffi::c_void,
    console_out_handle: EfiHandle,
    con_out: *mut EfiSimpleTextOutput,
    std_err_handle: EfiHandle,
    std_err: *mut core::ffi::c_void,
    runtime_services: *mut core::ffi::c_void,
    boot_services: *mut EfiBootServices,
    num_table_entries: usize,
    configuration_table: *mut EfiConfigTable,
}

#[repr(C)]
struct EfiSimpleTextOutput {
    reset: *mut core::ffi::c_void,
    output_string: unsafe extern "efiapi" fn(*mut EfiSimpleTextOutput, *const u16) -> EfiStatus,
}

type LocateHandleBufferFn = unsafe extern "efiapi" fn(
    search_type: u32,
    protocol: *const [u64; 2],
    search_key: *mut core::ffi::c_void,
    no_handles: *mut usize,
    buffer: *mut *mut EfiHandle,
) -> EfiStatus;

type HandleProtocolFn = unsafe extern "efiapi" fn(
    handle: EfiHandle,
    protocol: *const [u64; 2],
    interface: *mut *mut core::ffi::c_void,
) -> EfiStatus;

type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

/// EFI_BOOT_SERVICES up to LocateHandleBuffer.
///
/// Keep this as a real repr(C) table prefix instead of hard-coded pointer
/// offsets. On 64-bit UEFI the correct offsets are:
///   - HandleProtocol:      0x098
///   - ExitBootServices:   0x0E8
///   - LocateHandleBuffer: 0x138
#[repr(C)]
struct EfiBootServices {
    hdr: EfiTableHeader,                  // 0x000
    _tpl_raise: *mut core::ffi::c_void,   // 0x018
    _tpl_restore: *mut core::ffi::c_void, // 0x020

    // Memory Services
    _allocate_pages: *mut core::ffi::c_void, // 0x028
    _free_pages: *mut core::ffi::c_void,     // 0x030
    get_memory_map: unsafe extern "efiapi" fn(
        // 0x038
        map_size: *mut usize,
        map: *mut EfiMemDescriptor,
        map_key: *mut usize,
        desc_size: *mut usize,
        desc_version: *mut u32,
    ) -> EfiStatus,
    allocate_pool: unsafe extern "efiapi" fn(
        // 0x040
        pool_type: u32,
        size: usize,
        buffer: *mut *mut u8,
    ) -> EfiStatus,
    _free_pool: unsafe extern "efiapi" fn(*mut u8) -> EfiStatus, // 0x048

    // Event & Timer Services
    _create_event: *mut core::ffi::c_void,   // 0x050
    _set_timer: *mut core::ffi::c_void,      // 0x058
    _wait_for_event: *mut core::ffi::c_void, // 0x060
    _signal_event: *mut core::ffi::c_void,   // 0x068
    _close_event: *mut core::ffi::c_void,    // 0x070
    _check_event: *mut core::ffi::c_void,    // 0x078

    // Protocol Handler Services
    _install_protocol_interface: *mut core::ffi::c_void, // 0x080
    _reinstall_protocol_interface: *mut core::ffi::c_void, // 0x088
    _uninstall_protocol_interface: *mut core::ffi::c_void, // 0x090
    handle_protocol: HandleProtocolFn,                   // 0x098
    _reserved: *mut core::ffi::c_void,                   // 0x0A0
    _register_protocol_notify: *mut core::ffi::c_void,   // 0x0A8
    _locate_handle: *mut core::ffi::c_void,              // 0x0B0
    _locate_device_path: *mut core::ffi::c_void,         // 0x0B8
    _install_configuration_table: *mut core::ffi::c_void, // 0x0C0

    // Image Services
    _load_image: *mut core::ffi::c_void,    // 0x0C8
    _start_image: *mut core::ffi::c_void,   // 0x0D0
    _exit: *mut core::ffi::c_void,          // 0x0D8
    _unload_image: *mut core::ffi::c_void,  // 0x0E0
    exit_boot_services: ExitBootServicesFn, // 0x0E8

    // Miscellaneous Services
    _get_next_monotonic_count: *mut core::ffi::c_void, // 0x0F0
    _stall: *mut core::ffi::c_void,                    // 0x0F8
    _set_watchdog_timer: *mut core::ffi::c_void,       // 0x100

    // Driver Support Services
    _connect_controller: *mut core::ffi::c_void, // 0x108
    _disconnect_controller: *mut core::ffi::c_void, // 0x110

    // Open and Close Protocol Services
    _open_protocol: *mut core::ffi::c_void,  // 0x118
    _close_protocol: *mut core::ffi::c_void, // 0x120
    _open_protocol_information: *mut core::ffi::c_void, // 0x128

    // Library Services
    _protocols_per_handle: *mut core::ffi::c_void, // 0x130
    locate_handle_buffer: LocateHandleBufferFn,    // 0x138
}

const EFI_LOADER_DATA: u32 = 2;

#[repr(C)]
struct EfiMemDescriptor {
    type_: u32,
    _pad: u32,
    physical_start: u64,
    virtual_start: u64,
    num_pages: u64,
    attribute: u64,
}

#[repr(C)]
struct EfiConfigTable {
    guid: [u64; 2],
    table: *mut core::ffi::c_void,
}

#[repr(C)]
struct EfiLoadFile2Protocol {
    load_file: unsafe extern "efiapi" fn(
        this: *mut EfiLoadFile2Protocol,
        file_path: *mut core::ffi::c_void,
        boot_policy: u8,
        buffer_size: *mut usize,
        buffer: *mut core::ffi::c_void,
    ) -> EfiStatus,
}

const BY_PROTOCOL: u32 = 2;

// ACPI 2.0 GUID: {8868e871-e4f1-11d3-bc22-0080c73c8881}
const ACPI2_GUID: [u64; 2] = [0x11d3_f1e4_71e8_6888, 0x8188_3cc7_8000_22bc];

// EFI_INITRD_MEDIA_GUID: {5568e427-68fc-4f3d-ac74-ca555231cc68}
const INITRD_MEDIA_GUID: [u64; 2] = [0x4f3d_fc68_27e4_6855, 0x68cc_3152_55ca_74ac];

/// Physical address of the ACPI 2.0 RSDP. 0 = not found (DT-only board).
pub static mut RSDP_PHYS: u64 = 0;

/// Saved EFI memory map — used by the PMM after ExitBootServices.
pub static mut EFI_MAP_PTR: usize = 0;
pub static mut EFI_MAP_SIZE: usize = 0;
pub static mut EFI_DESC_SIZE: usize = 0;

static mut BOOT_INFO: BootInfo = BootInfo::empty();

/// 32 KiB boot stack (BSS).  The linker script places BOOT_STACK_TOP
/// immediately above it so sp = BOOT_STACK_TOP is valid on entry.
#[repr(align(16))]
struct BootStackStorage([u8; 32768]);
#[link_section = ".bss"]
static mut BOOT_STACK: BootStackStorage = BootStackStorage([0u8; 32768]);
#[no_mangle]
#[link_section = ".bss"]
pub static BOOT_STACK_TOP: [u8; 0] = [];

#[no_mangle]
pub unsafe extern "efiapi" fn efi_main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    // Null-check: non-conformant firmware or misconfigured QEMU can pass NULL.
    if system_table.is_null() {
        crate::arch::aarch64::hal::init();
        kernel_main_jump(&BOOT_INFO);
    }

    let st = &*system_table;
    if st.boot_services.is_null() {
        crate::arch::aarch64::hal::init();
        kernel_main_jump(&BOOT_INFO);
    }
    let bs = &*st.boot_services;

    // 1. Banner — identifies this as the SECONDARY (aarch64) boot target.
    efi_print(
        st.con_out,
        "RustOS [SECONDARY] aarch64 booting via UEFI...\r\n",
    );

    // 2. Capture GOP framebuffer — graceful fallback if firmware has no GOP.
    let gop_ok =
        crate::drivers::gop::capture_from_boot_services(st.boot_services as *mut core::ffi::c_void);
    if !gop_ok {
        efi_print(
            st.con_out,
            "rustos: GOP not available — serial-only mode\r\n",
        );
    }

    // 3 & 4. Walk EFI configuration table for ACPI RSDP and OVMF initrd.
    let cfg = core::slice::from_raw_parts(st.configuration_table, st.num_table_entries);
    let mut ovmf_initrd_found = false;
    let mut initramfs = BootRange::empty();
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
        }
        if entry.guid == INITRD_MEDIA_GUID {
            let data = entry.table as *const u64;
            let phys_start = *data as usize;
            let byte_size = *data.add(1) as usize;
            if phys_start != 0 && byte_size > 0 {
                crate::initramfs::set_initramfs_range(phys_start, byte_size);
                initramfs = BootRange::new(phys_start, byte_size);
                ovmf_initrd_found = true;
            }
        }
    }

    // 4a. LoadFile2 protocol initramfs (systemd-boot / GRUB2 on real hardware).
    if !ovmf_initrd_found {
        if let Some(range) = load_initrd_via_loadfile2(bs) {
            initramfs = range;
        }
    }

    // 5. Get EFI memory map with a dynamically sized buffer.
    let mut map_size: usize = 0;
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver: u32 = 0;

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
        efi_print(
            st.con_out,
            "rustos: FATAL: AllocatePool for memory map failed\r\n",
        );
        halt();
    }

    let status = (bs.get_memory_map)(
        &mut map_size,
        map_buf as *mut EfiMemDescriptor,
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    if status != EFI_SUCCESS {
        efi_print(st.con_out, "rustos: FATAL: GetMemoryMap failed\r\n");
        halt();
    }

    EFI_MAP_PTR = map_buf as usize;
    EFI_MAP_SIZE = map_size;
    EFI_DESC_SIZE = desc_size;
    BOOT_INFO = BootInfo {
        rsdp_phys: RSDP_PHYS,
        efi_memory_map: EfiMemoryMapInfo::new(EFI_MAP_PTR, EFI_MAP_SIZE, EFI_DESC_SIZE),
        initramfs,
        ..BootInfo::empty()
    };

    // 5b. ExitBootServices — mandatory retry on EFI_INVALID_PARAMETER.
    let mut exit_status = (bs.exit_boot_services)(image_handle, map_key);

    if exit_status == EFI_INVALID_PARAMETER {
        let mut retry_map_size = map_size;
        let mut retry_map_key: usize = 0;
        let mut retry_desc_size: usize = desc_size;
        let mut retry_desc_ver: u32 = desc_ver;

        let remap_status = (bs.get_memory_map)(
            &mut retry_map_size,
            map_buf as *mut EfiMemDescriptor,
            &mut retry_map_key,
            &mut retry_desc_size,
            &mut retry_desc_ver,
        );
        if remap_status == EFI_SUCCESS {
            EFI_MAP_SIZE = retry_map_size;
            EFI_DESC_SIZE = retry_desc_size;
            BOOT_INFO.efi_memory_map =
                EfiMemoryMapInfo::new(EFI_MAP_PTR, EFI_MAP_SIZE, EFI_DESC_SIZE);
            exit_status = (bs.exit_boot_services)(image_handle, retry_map_key);
        }
    }

    if exit_status != EFI_SUCCESS {
        halt();
    }

    // 6. Switch to kernel boot stack and tail-call kernel_main.
    crate::arch::aarch64::hal::init();
    kernel_main_jump(&BOOT_INFO);
}

/// Switch to the static kernel boot stack, then jump to `kernel_main`.
///
/// Inlined naked-style trampoline: we load the boot stack top into sp,
/// then branch to the common entry.  We use `sym` operands so the
/// assembler emits PC-relative ADR instructions (no GOT needed).
#[inline(never)]
unsafe fn kernel_main_jump(boot_info: &'static BootInfo) -> ! {
    extern "C" {
        fn kernel_main(boot_info: &'static BootInfo) -> !;
    }
    asm!(
        "adr x9, {stack_top}",
        "mov sp, x9",
        "mov x29, xzr",   // clear frame pointer
        "mov x30, xzr",   // clear link register
        "br  {km}",
        stack_top = sym BOOT_STACK_TOP,
        km        = sym kernel_main,
        in("x0") boot_info as *const BootInfo,
        options(noreturn),
    );
}

unsafe fn load_initrd_via_loadfile2(bs: &EfiBootServices) -> Option<BootRange> {
    let mut num_handles: usize = 0;
    let mut handle_buf: *mut EfiHandle = core::ptr::null_mut();
    let status = (bs.locate_handle_buffer)(
        BY_PROTOCOL,
        &INITRD_MEDIA_GUID,
        core::ptr::null_mut(),
        &mut num_handles,
        &mut handle_buf,
    );
    if status != EFI_SUCCESS || num_handles == 0 || handle_buf.is_null() {
        return None;
    }

    let handle = *handle_buf;
    let mut lf2_iface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = (bs.handle_protocol)(handle, &INITRD_MEDIA_GUID, &mut lf2_iface);
    if status != EFI_SUCCESS || lf2_iface.is_null() {
        return None;
    }
    let lf2 = &*(lf2_iface as *mut EfiLoadFile2Protocol);

    let mut initrd_size: usize = 0;
    let status = (lf2.load_file)(
        lf2_iface as *mut EfiLoadFile2Protocol,
        core::ptr::null_mut(),
        0,
        &mut initrd_size,
        core::ptr::null_mut(),
    );
    if status != EFI_BUFFER_TOO_SMALL || initrd_size == 0 {
        return None;
    }

    let mut initrd_buf: *mut u8 = core::ptr::null_mut();
    let alloc_status = (bs.allocate_pool)(EFI_LOADER_DATA, initrd_size, &mut initrd_buf);
    if alloc_status != EFI_SUCCESS || initrd_buf.is_null() {
        return None;
    }

    let status = (lf2.load_file)(
        lf2_iface as *mut EfiLoadFile2Protocol,
        core::ptr::null_mut(),
        0,
        &mut initrd_size,
        initrd_buf as *mut core::ffi::c_void,
    );
    if status == EFI_SUCCESS {
        crate::initramfs::set_initramfs_range(initrd_buf as usize, initrd_size);
        return Some(BootRange::new(initrd_buf as usize, initrd_size));
    }
    None
}

unsafe fn efi_print(con_out: *mut EfiSimpleTextOutput, s: &str) {
    if con_out.is_null() {
        return;
    }
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}

#[inline(never)]
fn halt() -> ! {
    loop {
        unsafe {
            asm!("wfi", options(nostack, nomem));
        }
    }
}
