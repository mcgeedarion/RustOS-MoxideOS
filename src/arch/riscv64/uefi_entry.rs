//! RISC-V UEFI firmware entry point.

use crate::init::boot_info::{BootInfo, BootRange, EfiMemoryMapInfo};
use core::arch::asm;

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;

const EFI_SUCCESS: EfiStatus = 0;
const EFI_INVALID_PARAMETER: EfiStatus = 0x8000_0000_0000_0002;
const EFI_BUFFER_TOO_SMALL: EfiStatus = 0x8000_0000_0000_0005;
const EFI_LOADER_DATA: u32 = 2;
const BY_PROTOCOL: u32 = 2;
const ACPI2_GUID: [u64; 2] = [0x11d3_f1e4_71e8_6888, 0x8188_3cc7_8000_22bc];
const INITRD_MEDIA_GUID: [u64; 2] = [0x4f3d_fc68_27e4_6855, 0x68cc_3152_55ca_74ac];

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

type LocateHandleBufferFn = unsafe extern "efiapi" fn(
    u32,
    *const [u64; 2],
    *mut core::ffi::c_void,
    *mut usize,
    *mut *mut EfiHandle,
) -> EfiStatus;

type HandleProtocolFn =
    unsafe extern "efiapi" fn(EfiHandle, *const [u64; 2], *mut *mut core::ffi::c_void) -> EfiStatus;

type ExitBootServicesFn = unsafe extern "efiapi" fn(EfiHandle, usize) -> EfiStatus;

#[repr(C)]
struct EfiBootServices {
    hdr: EfiTableHeader,
    _tpl_raise: *mut core::ffi::c_void,
    _tpl_restore: *mut core::ffi::c_void,
    _allocate_pages: *mut core::ffi::c_void,
    _free_pages: *mut core::ffi::c_void,
    get_memory_map: unsafe extern "efiapi" fn(
        *mut usize,
        *mut EfiMemDescriptor,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> EfiStatus,
    allocate_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut u8) -> EfiStatus,
    _free_pool: unsafe extern "efiapi" fn(*mut u8) -> EfiStatus,
    _create_event: *mut core::ffi::c_void,
    _set_timer: *mut core::ffi::c_void,
    _wait_for_event: *mut core::ffi::c_void,
    _signal_event: *mut core::ffi::c_void,
    _close_event: *mut core::ffi::c_void,
    _check_event: *mut core::ffi::c_void,
    _install_protocol_interface: *mut core::ffi::c_void,
    _reinstall_protocol_interface: *mut core::ffi::c_void,
    _uninstall_protocol_interface: *mut core::ffi::c_void,
    handle_protocol: HandleProtocolFn,
    _reserved: *mut core::ffi::c_void,
    _register_protocol_notify: *mut core::ffi::c_void,
    _locate_handle: *mut core::ffi::c_void,
    _locate_device_path: *mut core::ffi::c_void,
    _install_configuration_table: *mut core::ffi::c_void,
    _load_image: *mut core::ffi::c_void,
    _start_image: *mut core::ffi::c_void,
    _exit: *mut core::ffi::c_void,
    _unload_image: *mut core::ffi::c_void,
    exit_boot_services: ExitBootServicesFn,
    _get_next_monotonic_count: *mut core::ffi::c_void,
    _stall: *mut core::ffi::c_void,
    _set_watchdog_timer: *mut core::ffi::c_void,
    _connect_controller: *mut core::ffi::c_void,
    _disconnect_controller: *mut core::ffi::c_void,
    _open_protocol: *mut core::ffi::c_void,
    _close_protocol: *mut core::ffi::c_void,
    _open_protocol_information: *mut core::ffi::c_void,
    _protocols_per_handle: *mut core::ffi::c_void,
    locate_handle_buffer: LocateHandleBufferFn,
}

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
        *mut EfiLoadFile2Protocol,
        *mut core::ffi::c_void,
        u8,
        *mut usize,
        *mut core::ffi::c_void,
    ) -> EfiStatus,
}

pub static mut RSDP_PHYS: u64 = 0;
pub static mut EFI_MAP_PTR: usize = 0;
pub static mut EFI_MAP_SIZE: usize = 0;
pub static mut EFI_DESC_SIZE: usize = 0;

static mut BOOT_INFO: BootInfo = BootInfo::empty();

#[no_mangle]
pub unsafe extern "efiapi" fn efi_main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    uefi_start(image_handle, system_table)
}

#[no_mangle]
pub unsafe extern "efiapi" fn uefi_start(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> ! {
    if system_table.is_null() {
        halt();
    }

    let st = &*system_table;
    if st.boot_services.is_null() {
        halt();
    }
    let bs = &*st.boot_services;

    efi_print(st.con_out, "RustOS (RISC-V) booting via UEFI...\r\n");
    let _ =
        crate::drivers::gop::capture_from_boot_services(st.boot_services as *mut core::ffi::c_void);

    let cfg = core::slice::from_raw_parts(st.configuration_table, st.num_table_entries);
    let mut initramfs = BootRange::empty();
    let mut ovmf_initrd_found = false;
    for entry in cfg {
        if entry.guid == ACPI2_GUID {
            RSDP_PHYS = entry.table as u64;
        }
        if entry.guid == INITRD_MEDIA_GUID {
            let data = entry.table as *const u64;
            let start = *data as usize;
            let size = *data.add(1) as usize;
            if start != 0 && size > 0 {
                crate::initramfs::set_initramfs_range(start, size);
                initramfs = BootRange::new(start, size);
                ovmf_initrd_found = true;
            }
        }
    }

    if !ovmf_initrd_found {
        if let Some(range) = load_initrd_via_loadfile2(bs) {
            initramfs = range;
        }
    }

    let mut map_size = 0usize;
    let mut map_key = 0usize;
    let mut desc_size = 0usize;
    let mut desc_ver = 0u32;
    let _ = (bs.get_memory_map)(
        &mut map_size,
        core::ptr::null_mut(),
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    );
    map_size += 2048;

    let mut map_buf: *mut u8 = core::ptr::null_mut();
    if (bs.allocate_pool)(EFI_LOADER_DATA, map_size, &mut map_buf) != EFI_SUCCESS
        || map_buf.is_null()
    {
        halt();
    }

    if (bs.get_memory_map)(
        &mut map_size,
        map_buf as *mut EfiMemDescriptor,
        &mut map_key,
        &mut desc_size,
        &mut desc_ver,
    ) != EFI_SUCCESS
    {
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

    let mut exit_status = (bs.exit_boot_services)(image_handle, map_key);
    if exit_status == EFI_INVALID_PARAMETER {
        let mut retry_size = map_size;
        let mut retry_key = 0usize;
        let mut retry_desc_size = desc_size;
        let mut retry_desc_ver = desc_ver;
        if (bs.get_memory_map)(
            &mut retry_size,
            map_buf as *mut EfiMemDescriptor,
            &mut retry_key,
            &mut retry_desc_size,
            &mut retry_desc_ver,
        ) == EFI_SUCCESS
        {
            EFI_MAP_SIZE = retry_size;
            EFI_DESC_SIZE = retry_desc_size;
            BOOT_INFO.efi_memory_map =
                EfiMemoryMapInfo::new(EFI_MAP_PTR, EFI_MAP_SIZE, EFI_DESC_SIZE);
            exit_status = (bs.exit_boot_services)(image_handle, retry_key);
        }
    }
    if exit_status != EFI_SUCCESS {
        halt();
    }

    extern "C" {
        fn kernel_main(boot_info: &'static BootInfo) -> !;
    }
    asm!(
        "la   sp, {stack_top}",
        "mv   s0, zero",
        "la   a0, {boot_info}",
        "call {km}",
        "1:  wfi",
        "j   1b",
        stack_top = sym crate::arch::riscv64::boot::BOOT_STACK_TOP,
        boot_info = sym BOOT_INFO,
        km = sym kernel_main,
        options(noreturn),
    );
}

unsafe fn load_initrd_via_loadfile2(bs: &EfiBootServices) -> Option<BootRange> {
    let mut num_handles = 0usize;
    let mut handle_buf: *mut EfiHandle = core::ptr::null_mut();
    if (bs.locate_handle_buffer)(
        BY_PROTOCOL,
        &INITRD_MEDIA_GUID,
        core::ptr::null_mut(),
        &mut num_handles,
        &mut handle_buf,
    ) != EFI_SUCCESS
        || num_handles == 0
        || handle_buf.is_null()
    {
        return None;
    }

    let mut lf2_iface: *mut core::ffi::c_void = core::ptr::null_mut();
    if (bs.handle_protocol)(*handle_buf, &INITRD_MEDIA_GUID, &mut lf2_iface) != EFI_SUCCESS
        || lf2_iface.is_null()
    {
        return None;
    }
    let lf2 = &*(lf2_iface as *mut EfiLoadFile2Protocol);

    let mut initrd_size = 0usize;
    if (lf2.load_file)(
        lf2_iface as *mut EfiLoadFile2Protocol,
        core::ptr::null_mut(),
        0,
        &mut initrd_size,
        core::ptr::null_mut(),
    ) != EFI_BUFFER_TOO_SMALL
        || initrd_size == 0
    {
        return None;
    }

    let mut initrd_buf: *mut u8 = core::ptr::null_mut();
    if (bs.allocate_pool)(EFI_LOADER_DATA, initrd_size, &mut initrd_buf) != EFI_SUCCESS
        || initrd_buf.is_null()
    {
        return None;
    }

    if (lf2.load_file)(
        lf2_iface as *mut EfiLoadFile2Protocol,
        core::ptr::null_mut(),
        0,
        &mut initrd_size,
        initrd_buf as *mut core::ffi::c_void,
    ) == EFI_SUCCESS
    {
        crate::initramfs::set_initramfs_range(initrd_buf as usize, initrd_size);
        Some(BootRange::new(initrd_buf as usize, initrd_size))
    } else {
        None
    }
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
