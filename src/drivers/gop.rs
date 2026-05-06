//! UEFI Graphics Output Protocol (GOP) framebuffer capture.
//!
//! Called from both uefi_entry.rs implementations (x86_64 and riscv64)
//! **before** ExitBootServices while the firmware is still reachable.
//!
//! After ExitBootServices the `GOP_INFO` global holds everything the
//! kernel needs to treat the linear framebuffer as /dev/fb0:
//!   - Physical base address of the pixel data
//!   - Width, height, pixels-per-scan-line
//!   - Pixel format (RGBX or BGRX)
//!
//! ## EFI_GRAPHICS_OUTPUT_PROTOCOL layout (UEFI 2.10 §12.9)
//!
//! ```text
//!  EFI_GRAPHICS_OUTPUT_PROTOCOL {
//!    QueryMode  fn ptr
//!    SetMode    fn ptr
//!    Blt        fn ptr
//!    Mode       *EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE
//!  }
//!
//!  EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE {
//!    MaxMode              u32
//!    Mode                 u32
//!    Info                 *EFI_GRAPHICS_OUTPUT_MODE_INFORMATION
//!    SizeOfInfo           usize
//!    FrameBufferBase      u64     ← physical address
//!    FrameBufferSize      usize
//!  }
//!
//!  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION {
//!    Version              u32
//!    HorizontalResolution u32
//!    VerticalResolution   u32
//!    PixelFormat          u32  (0=RGBX, 1=BGRX, 2=BitMask, 3=BltOnly)
//!    PixelInformation     [u32; 4]
//!    PixelsPerScanLine    u32
//!  }
//! ```
//!
//! ## LocateProtocol offset
//! LocateProtocol is function #43 (0-indexed) in EFI_BOOT_SERVICES:
//!   offset = 24 (header) + 43 * 8 = 368 = 0x170

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// ── GOP GUID: {9042a9de-23dc-4a38-96fb-7aded080516a} ────────────────────────────
const GOP_GUID: [u64; 2] = [
    0x4a38_dc23_de9a_4290_u64.to_le(),
    0x6a51_80ed_adad_fb96_u64.to_le(),
];

/// Pixel encoding reported by GOP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    Rgbx,   // R at byte 0
    Bgrx,   // B at byte 0 (most common on real hardware)
    BitMask,
    BltOnly, // no linear framebuffer
}

/// Everything the kernel needs from GOP, captured before ExitBootServices.
#[derive(Clone, Copy)]
pub struct GopInfo {
    pub fb_phys:          u64,
    pub fb_size:          usize,
    pub width:            u32,
    pub height:           u32,
    pub pixels_per_line:  u32,
    pub pixel_format:     PixelFormat,
}

static GOP_VALID: AtomicBool = AtomicBool::new(false);
static GOP_INFO:  Mutex<GopInfo> = Mutex::new(GopInfo {
    fb_phys:         0,
    fb_size:         0,
    width:           0,
    height:          0,
    pixels_per_line: 0,
    pixel_format:    PixelFormat::Bgrx,
});

/// Returns the captured GOP info, or None if GOP was not found.
pub fn get() -> Option<GopInfo> {
    if GOP_VALID.load(Ordering::Acquire) {
        Some(*GOP_INFO.lock())
    } else {
        None
    }
}

/// Returns the framebuffer byte size (width * height * 4).
pub fn fb_byte_size(info: &GopInfo) -> usize {
    info.pixels_per_line as usize * info.height as usize * 4
}

// ── Raw EFI types for GOP query ──────────────────────────────────────────────────

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;
const EFI_SUCCESS: EfiStatus = 0;

/// Offset of LocateProtocol in EFI_BOOT_SERVICES: header(24) + 43*8 = 0x170.
const LOCATE_PROTOCOL_OFFSET: usize = 0x170;
type LocateProtocolFn = unsafe extern "efiapi" fn(
    protocol:     *const [u64; 2],
    registration: *mut core::ffi::c_void,
    interface:    *mut *mut core::ffi::c_void,
) -> EfiStatus;

#[repr(C)]
struct GopProtocol {
    query_mode: *mut core::ffi::c_void,
    set_mode:   *mut core::ffi::c_void,
    blt:        *mut core::ffi::c_void,
    mode:       *mut GopMode,
}

#[repr(C)]
struct GopMode {
    max_mode:        u32,
    mode:            u32,
    info:            *mut GopModeInfo,
    size_of_info:    usize,
    fb_base:         u64,
    fb_size:         usize,
}

#[repr(C)]
struct GopModeInfo {
    version:               u32,
    horizontal_resolution: u32,
    vertical_resolution:   u32,
    pixel_format:          u32,
    pixel_bitmask:         [u32; 4],
    pixels_per_scan_line:  u32,
}

/// Query GOP via LocateProtocol and store the result in `GOP_INFO`.
///
/// Must be called before ExitBootServices while boot services are live.
/// Safe to call on both x86_64 and RISC-V UEFI paths.
///
/// # Safety
/// `boot_services_ptr` must be a valid `*EFI_BOOT_SERVICES` pointer.
pub unsafe fn capture_from_boot_services(boot_services_ptr: *mut core::ffi::c_void) {
    let bs_base = boot_services_ptr as usize;
    let locate: LocateProtocolFn =
        *((bs_base + LOCATE_PROTOCOL_OFFSET) as *const LocateProtocolFn);

    let mut gop_iface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = locate(
        &GOP_GUID as *const [u64; 2],
        core::ptr::null_mut(),
        &mut gop_iface,
    );

    if status != EFI_SUCCESS || gop_iface.is_null() {
        // GOP not available (e.g. headless serial-only QEMU).
        return;
    }

    let gop = &*(gop_iface as *const GopProtocol);
    if gop.mode.is_null() { return; }
    let mode = &*gop.mode;
    if mode.info.is_null() { return; }
    let info = &*mode.info;

    if mode.fb_base == 0 { return; } // BltOnly — no linear FB

    let pixel_format = match info.pixel_format {
        0 => PixelFormat::Rgbx,
        1 => PixelFormat::Bgrx,
        2 => PixelFormat::BitMask,
        _ => PixelFormat::BltOnly,
    };

    if pixel_format == PixelFormat::BltOnly { return; }

    *GOP_INFO.lock() = GopInfo {
        fb_phys:         mode.fb_base,
        fb_size:         mode.fb_size,
        width:           info.horizontal_resolution,
        height:          info.vertical_resolution,
        pixels_per_line: info.pixels_per_scan_line,
        pixel_format,
    };
    GOP_VALID.store(true, Ordering::Release);
}
