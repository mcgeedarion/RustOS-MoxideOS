//! RISC-V UEFI firmware entry point — `uefi_start`.
//!
//! Mirrors src/arch/x86_64/uefi_entry.rs with the following differences:
//!   - Final stack-switch uses RISC-V inline assembly.
//!   - Entry ABI is `extern "efiapi"` (maps to standard RISC-V C calling
//!     convention).
//!   - GOP fallback message is omitted (RISC-V UEFI firmware often has no
//!     ConOut text output after firmware init; UART is the debug channel).
//!
//! ## Boot flow
//!   1. Print banner via UEFI SimpleTextOutput.
//!   2. Capture GOP framebuffer (graceful fallback if unavailable).
//!   3. Scan EFI configuration table for ACPI 2.0 RSDP and OVMF initrd.
//!   4. LoadFile2 initramfs protocol (real hardware / systemd-boot).
//!   5. Dynamic EFI memory map + ExitBootServices (with mandatory retry).
//!   6. Save EFI map metadata for pmm_add_efi_map().
//!   7. Switch to kernel boot stack (BOOT_STACK_TOP) and tail-call kernel_main.
//!
//! ## ExitBootServices retry
//!   SiFive HiFive Premier P550 and StarFive VisionFive 2 firmware both
//!   observed to invalidate the map key between GetMemoryMap and
//!   ExitBootServices.  UEFI spec §7.4.6 requires callers to handle this by
//!   refreshing the key and retrying once.  If the second attempt fails we
//!   halt in a wfi loop rather than continuing with boot services active.

use crate::init::boot_info::{BootInfo, BootRange, EfiMemoryMapInfo};
use core::arch::asm;

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;

const EFI_SUCCESS: EfiStatus = 0;
const EFI_INVALID_PARAMETER: EfiStatus = 0x8000_0000_0000_0002;
const EFI_BUFFER_TOO_SMALL: EfiStatus = 0x8000_0000_0000_0005;

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    _reserved: u32,
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

#[repr(C)]
struct EfiBootServices {
    hdr: EfiTableHeader,
    _tpl_raise: *mut core::ffi::c_void,
    _tpl_restore: *mut core::ffi::c_void,
    _alloc_pages: *mut core::ffi::c_void,
    _free_pages: *mut core::ffi::c_void,
    get_memory_map: unsafe extern "efiapi" fn(
        map_size: *mut usize,
        map: *mut EfiMemDescriptor,
        map_key: *mut usize,
        desc_size: *mut usize,
        desc_version: *mut u32,
    ) -> EfiStatus,
    allocate_pool:
        unsafe extern "efiapi" fn(pool_type: u32, size: usize, buffer: *mut *mut u8) -> EfiStatus,
    free_pool: unsafe extern "efiapi" fn(buffer: *mut u8) -> EfiStatus,
    _ev: [*mut core::ffi::c_void; 5],
}

const EFI_LOADER_DATA: u32 = 2;

#[repr(C)]
pub struct EfiMemDescriptor {
    pub type_: u32,
    pub _pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub num_pages: u64,
    pub attribute: u64,
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

const LOCATE_HANDLE_BUFFER_OFFSET: usize = 0x0B0;
type LocateHandleBufferFn = unsafe extern "efiapi" fn(
    search_type: u32,
    protocol: *const [u64; 2],
    search_key: *mut core::ffi::c_void,
    no_handles: *mut usize,
    buffer: *mut *mut EfiHandle,
) -> EfiStatus;

const HANDLE_PROTOCOL_OFFSET: usize = 0x098;
type HandleProtocolFn = unsafe extern "efiapi" fn(
    handle: EfiHandle,
    protocol: *const [u64; 2],
    interface: *mut *mut core::ffi::c_void,
) -> EfiStatus;

const BY_PROTOCOL: u32 = 2;

const EXIT_BOOT_SERVICES_OFFSET: usize = 0x190;
type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

const ACPI2_GUID: [u64; 2] = [0x11d3_f1e4_71e8_6888, 0x8188_3cc7_8000_22bc];

const INITRD_MEDIA_GUID: [u64; 2] = [0x4f3d_fc68_27e4_6855, 0x68cc_3152_55ca_74ac];

/// Physical address of the ACPI 2.0 RSDP. 0 = not found.
pub static mut RSDP_PHYS: u64 = 0;

/// Saved EFI memory map metadata — consumed by pmm_add_efi_map() in
/// memmap_init().  Set before ExitBootServices; read-only thereafter.
pub static mut EFI_MAP_PTR: usize = 0;
pub static mut EFI_MAP_SIZE: usize = 0;
pub static mut EFI_DESC_SIZE: usize = 0;

static mut BOOT_INFO: BootInfo = BootInfo::empty();

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
    let _ =
        crate::drivers::gop::capture_from_boot_services(st.boot_services as *mut core::ffi::c_void);

    // 3. ACPI RSDP + OVMF initrd config-table scan.
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

    // 4. LoadFile2 initramfs (real hardware / systemd-boot / GRUB2).
    if !ovmf_initrd_found {
        if let Some(range) =
            load_initrd_via_loadfile2(st.boot_services as *mut core::ffi::c_void, bs_base)
        {
            initramfs = range;
        }
    }

    // 5. Dynamic EFI memory map — allocate buffer with headroom.
    let mut map_size: usize = 0;
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver: u32 = 0;

    // Probe required size.
    let _ = (bs.get_memory_map)(
        &mut map_size,
        core::ptr::null_mut(),
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    map_size += 2048; // headroom for AllocatePool descriptor

    let mut map_buf: *mut u8 = core::ptr::null_mut();
    let alloc_status = (bs.allocate_pool)(EFI_LOADER_DATA, map_size, &mut map_buf);
    if alloc_status != EFI_SUCCESS || map_buf.is_null() {
        loop {
            asm!("wfi", options(nostack, nomem));
        }
    }

    let status = (bs.get_memory_map)(
        &mut map_size,
        map_buf as *mut EfiMemDescriptor,
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    if status != EFI_SUCCESS {
        loop {
            asm!("wfi", options(nostack, nomem));
        }
    }

    // 6. Save map metadata for pmm_add_efi_map() (must happen before
    //    ExitBootServices because the EFI pool stays mapped afterwards).
    EFI_MAP_PTR = map_buf as usize;
    EFI_MAP_SIZE = map_size;
    EFI_DESC_SIZE = desc_size;
    BOOT_INFO = BootInfo {
        rsdp_phys: RSDP_PHYS,
        efi_memory_map: EfiMemoryMapInfo::new(EFI_MAP_PTR, EFI_MAP_SIZE, EFI_DESC_SIZE),
        initramfs,
        ..BootInfo::empty()
    };

    // 7. ExitBootServices — with mandatory retry on EFI_INVALID_PARAMETER.
    // UEFI spec §7.4.6: firmware may modify the memory map between
    // GetMemoryMap and ExitBootServices, invalidating map_key.  Observed
    // on SiFive P550 and StarFive VisionFive 2 firmware.
    let exit_fn = *((bs_base + EXIT_BOOT_SERVICES_OFFSET) as *const ExitBootServicesFn);

    let mut exit_status = exit_fn(image_handle, map_key);

    if exit_status == EFI_INVALID_PARAMETER {
        // Refresh the map key using the existing buffer.
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
            exit_status = exit_fn(image_handle, retry_map_key);
        }
    }

    if exit_status != EFI_SUCCESS {
        // Boot services still live — cannot continue safely.  Halt.
        loop {
            asm!("wfi", options(nostack, nomem));
        }
    }

    // 8. Switch to the kernel boot stack and tail-call kernel_main.
    // BOOT_STACK_TOP is immediately above BOOT_STACK in .bss (see boot.rs).
    // sp = BOOT_STACK_TOP is the correct initial stack pointer value for a
    // downward-growing RISC-V stack.
    extern "C" {
        fn kernel_main(boot_info: &'static BootInfo) -> !;
    }
    asm!(
        "la   sp, {stack_top}",
        "mv   s0, zero",   // clear frame pointer
        "la   a0, {boot_info}",
        "call {km}",
        "1:  wfi",
        "j   1b",
        stack_top = sym crate::arch::riscv64::boot::BOOT_STACK_TOP,
        boot_info = sym BOOT_INFO,
        km        = sym kernel_main,
        options(noreturn),
    );
}

unsafe fn load_initrd_via_loadfile2(
    boot_services: *mut core::ffi::c_void,
    bs_base: usize,
) -> Option<BootRange> {
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
    if status != EFI_SUCCESS || num_handles == 0 {
        return None;
    }

    let handle = *handle_buf;
    let mut lf2_iface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = handle_protocol(handle, &INITRD_MEDIA_GUID, &mut lf2_iface);
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
    let mut buf = [0u16; 128];
    let n = s.len().min(127);
    for (i, b) in s.bytes().take(n).enumerate() {
        buf[i] = b as u16;
    }
    buf[n] = 0;
    let _ = ((*con_out).output_string)(con_out, buf.as_ptr());
}
