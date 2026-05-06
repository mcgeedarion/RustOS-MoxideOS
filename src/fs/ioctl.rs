//! ioctl syscall implementation (NR 16).
//!
//! ## Implemented requests
//!   TCGETS     (0x5401) — copy Termios to user
//!   TCSETS     (0x5402) — set Termios from user (immediate)
//!   TCSETSW    (0x5403) — set Termios after drain (treated as TCSETS)
//!   TCSETSF    (0x5404) — set Termios after flush (treated as TCSETS)
//!   TIOCGWINSZ (0x5413) — return window size (80x24 hardcoded)
//!   TIOCSWINSZ (0x5414) — set window size (accepted, ignored)
//!   TIOCGPGRP  (0x540F) — get foreground process group
//!   TIOCSPGRP  (0x5410) — set foreground process group
//!   FIONREAD   (0x541B) — bytes available to read (always 0)
//!   FIOCLEX    (0x5451) — set FD_CLOEXEC
//!   FIONCLEX   (0x5450) — clear FD_CLOEXEC
//!
//!   --- Framebuffer (/dev/fb0) ---
//!   FBIOGET_VSCREENINFO (0x4600) — variable screen info (resolution, bpp, etc.)
//!   FBIOPUT_VSCREENINFO (0x4601) — set variable screen info (accepted, validated)
//!   FBIOGET_FSCREENINFO (0x4602) — fixed screen info (smem_start, line_length)
//!   FBIOBLANK           (0x4611) — blank/unblank screen (accepted, ignored)
//!
//!   --- DRM/KMS (/dev/dri/card0) ---
//!   DRM_IOCTL_VERSION          (0x6400) — driver name + version
//!   DRM_IOCTL_GET_CAP          (0x640c) — capability query
//!   DRM_IOCTL_MODE_GETRESOURCES(0x64a0) — list crtc/connector/encoder ids
//!   DRM_IOCTL_MODE_GETCRTC     (0x64a1) — current CRTC state
//!   DRM_IOCTL_MODE_GETCONNECTOR(0x64a7) — connector info + mode list
//!   DRM_IOCTL_MODE_SETCRTC     (0x64a2) — program a mode
//!   DRM_IOCTL_MODE_CREATE_DUMB (0x64b2) — allocate dumb buffer
//!   DRM_IOCTL_MODE_MAP_DUMB    (0x64b3) — get mmap offset
//!   DRM_IOCTL_MODE_DESTROY_DUMB(0x64b4) — free dumb buffer
//!   DRM_IOCTL_MODE_ADDFB       (0x64ae) — register framebuffer object
//!   DRM_IOCTL_MODE_RMFB        (0x64af) — unregister framebuffer object
//!   DRM_IOCTL_MODE_PAGE_FLIP   (0x64b0) — flip to framebuffer
//!
//! All others return -ENOTTY (-25).

use crate::shell::tty;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};
use crate::drivers::drm;
use crate::drivers::gop::PixelFormat;

extern crate alloc;

// ── TTY ioctl request codes ──────────────────────────────────────────────────
const TCGETS:     usize = 0x5401;
const TCSETS:     usize = 0x5402;
const TCSETSW:    usize = 0x5403;
const TCSETSF:    usize = 0x5404;
const TIOCGWINSZ: usize = 0x5413;
const TIOCSWINSZ: usize = 0x5414;
const TIOCGPGRP:  usize = 0x540F;
const TIOCSPGRP:  usize = 0x5410;
const FIONREAD:   usize = 0x541B;
const FIOCLEX:    usize = 0x5451;
const FIONCLEX:   usize = 0x5450;

// ── Framebuffer ioctl request codes ─────────────────────────────────────────
const FBIOGET_VSCREENINFO: usize = 0x4600;
const FBIOPUT_VSCREENINFO: usize = 0x4601;
const FBIOGET_FSCREENINFO: usize = 0x4602;
const FBIOBLANK:           usize = 0x4611;

// ── DRM ioctl request codes ──────────────────────────────────────────────────
const DRM_IOCTL_VERSION:           usize = 0x6400;
const DRM_IOCTL_GET_CAP:           usize = 0x640c;
const DRM_IOCTL_MODE_GETRESOURCES: usize = 0x64a0;
const DRM_IOCTL_MODE_GETCRTC:      usize = 0x64a1;
const DRM_IOCTL_MODE_SETCRTC:      usize = 0x64a2;
const DRM_IOCTL_MODE_GETCONNECTOR: usize = 0x64a7;
const DRM_IOCTL_MODE_ADDFB:        usize = 0x64ae;
const DRM_IOCTL_MODE_RMFB:         usize = 0x64af;
const DRM_IOCTL_MODE_PAGE_FLIP:    usize = 0x64b0;
const DRM_IOCTL_MODE_CREATE_DUMB:  usize = 0x64b2;
const DRM_IOCTL_MODE_MAP_DUMB:     usize = 0x64b3;
const DRM_IOCTL_MODE_DESTROY_DUMB: usize = 0x64b4;

// ── Struct sizes ─────────────────────────────────────────────────────────────
// fb_var_screeninfo: 160 bytes (Linux ABI)
// fb_fix_screeninfo: 68  bytes (Linux ABI)

/// Linux fb_var_screeninfo (160 bytes, subset of fields we fill).
#[repr(C)]
struct FbVarScreenInfo {
    xres:           u32,  // visible resolution
    yres:           u32,
    xres_virtual:   u32,
    yres_virtual:   u32,
    xoffset:        u32,
    yoffset:        u32,
    bits_per_pixel: u32,
    grayscale:      u32,
    // red/green/blue/transp bitfield (4 × 8 bytes = 32 bytes)
    red_offset:     u32, red_length:   u32, red_msb_right:   u32, _r: u32,
    green_offset:   u32, green_length: u32, green_msb_right: u32, _g: u32,
    blue_offset:    u32, blue_length:  u32, blue_msb_right:  u32, _b: u32,
    transp_offset:  u32, transp_length:u32, transp_msb_right:u32, _t: u32,
    nonstd:         u32,
    activate:       u32,
    height_mm:      u32,
    width_mm:       u32,
    accel_flags:    u32,
    pixclock:       u32,
    left_margin:    u32,
    right_margin:   u32,
    upper_margin:   u32,
    lower_margin:   u32,
    hsync_len:      u32,
    vsync_len:      u32,
    sync:           u32,
    vmode:          u32,
    rotate:         u32,
    colorspace:     u32,
    reserved:       [u32; 4],
}

/// Linux fb_fix_screeninfo (68 bytes).
#[repr(C)]
struct FbFixScreenInfo {
    id:           [u8; 16],
    smem_start:   usize,   // physical start of framebuffer
    smem_len:     u32,     // length in bytes
    type_:        u32,     // FB_TYPE_PACKED_PIXELS = 0
    type_aux:     u32,
    visual:       u32,     // FB_VISUAL_TRUECOLOR = 2
    xpanstep:     u16,
    ypanstep:     u16,
    ywrapstep:    u16,
    _pad:         u16,
    line_length:  u32,     // bytes per scan line
    mmio_start:   usize,
    mmio_len:     u32,
    accel:        u32,
    capabilities: u16,
    reserved:     [u16; 2],
}

// ── winsize ───────────────────────────────────────────────────────────────────
#[repr(C)]
struct Winsize { ws_row: u16, ws_col: u16, ws_xpixel: u16, ws_ypixel: u16 }

// ── DRM structs (minimal Linux ABI subset) ───────────────────────────────────

#[repr(C)]
struct DrmVersion {
    version_major:      i32,
    version_minor:      i32,
    version_patchlevel: i32,
    name_len:           usize,
    name:               usize, // user pointer
    date_len:           usize,
    date:               usize,
    desc_len:           usize,
    desc:               usize,
}

#[repr(C)]
struct DrmModeCardRes {
    fb_id_ptr:        usize,
    crtc_id_ptr:      usize,
    connector_id_ptr: usize,
    encoder_id_ptr:   usize,
    count_fbs:        u32,
    count_crtcs:      u32,
    count_connectors: u32,
    count_encoders:   u32,
    min_width:        u32,
    max_width:        u32,
    min_height:       u32,
    max_height:       u32,
}

#[repr(C)]
struct DrmModeCrtc {
    set_connectors_ptr: usize,
    count_connectors:   u32,
    crtc_id:            u32,
    fb_id:              u32,
    x: u32, y: u32,
    gamma_size:         u32,
    mode_valid:         u32,
    mode:               DrmModeInfoRaw,
}

/// Raw drm_mode_modeinfo (44 bytes, Linux ABI).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DrmModeInfoRaw {
    clock:    u32,
    hdisplay: u16, hsync_start: u16, hsync_end: u16, htotal: u16, hskew: u16,
    vdisplay: u16, vsync_start: u16, vsync_end: u16, vtotal: u16, vscan: u16,
    vrefresh: u32,
    flags:    u32,
    type_:    u32,
    name:     [u8; 32],
}

#[repr(C)]
struct DrmModeGetConnector {
    encoders_ptr:       usize,
    modes_ptr:          usize,
    props_ptr:          usize,
    prop_values_ptr:    usize,
    count_modes:        u32,
    count_props:        u32,
    count_encoders:     u32,
    encoder_id:         u32,
    connector_id:       u32,
    connector_type:     u32,
    connector_type_id:  u32,
    connection:         u32,  // 1 = connected
    mm_width:           u32,
    mm_height:          u32,
    subpixel:           u32,
    pad:                u32,
}

#[repr(C)]
struct DrmModeCreateDumb {
    height: u32,
    width:  u32,
    bpp:    u32,
    flags:  u32,
    handle: u32,
    pitch:  u32,
    size:   u64,
}

#[repr(C)]
struct DrmModeMapDumb {
    handle: u32,
    pad:    u32,
    offset: u64,
}

#[repr(C)]
struct DrmModeDestroyDumb {
    handle: u32,
}

#[repr(C)]
struct DrmModeAddFb {
    width:  u32,
    height: u32,
    pitch:  u32,
    bpp:    u32,
    depth:  u32,
    handle: u32,
    fb_id:  u32,
}

#[repr(C)]
struct DrmModePageFlip {
    crtc_id:   u32,
    fb_id:     u32,
    flags:     u32,
    reserved:  u32,
    user_data: u64,
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// sys_ioctl(fd, request, arg) [NR 16]
pub fn sys_ioctl(fd: usize, request: usize, arg: usize) -> isize {
    let is_tty = fd <= 2
        || crate::fs::devfs::get_dev_fd(fd)
            .map_or(false, |k| k == crate::fs::devfs::DevKind::Tty);
    let is_fb  = crate::fs::devfs::is_framebuffer(fd);

    // ── Framebuffer ioctls ─────────────────────────────────────────────────
    if is_fb {
        return fb_ioctl(request, arg);
    }

    // ── DRM ioctls (fd path /dev/dri/card0 identified by request range) ───
    if request >= 0x6400 && request <= 0x64ff {
        return drm_ioctl(request, arg);
    }

    // ── TTY ioctls ─────────────────────────────────────────────────────────
    match request {
        TCGETS => {
            let sz = core::mem::size_of::<tty::Termios>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let t = tty::get_termios();
            let bytes = unsafe {
                core::slice::from_raw_parts(&t as *const tty::Termios as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            let sz = core::mem::size_of::<tty::Termios>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut buf = alloc::vec![0u8; sz];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let t = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const tty::Termios) };
            tty::set_termios(t);
            0
        }
        TIOCGWINSZ => {
            if !validate_user_ptr(arg, 8) { return -14; }
            // If we have a framebuffer, report pixel dimensions too.
            let (xpixel, ypixel) = drm::gop_info()
                .map(|g| (g.width as u16, g.height as u16))
                .unwrap_or((0, 0));
            let ws = Winsize { ws_row: 24, ws_col: 80, ws_xpixel: xpixel, ws_ypixel: ypixel };
            let bytes = unsafe {
                core::slice::from_raw_parts(&ws as *const Winsize as *const u8, 8)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }
        TIOCSWINSZ => 0,
        TIOCGPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let pid = tty::foreground_pid() as u32;
            if copy_to_user(arg, &pid.to_le_bytes()).is_err() { return -14; }
            0
        }
        TIOCSPGRP => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut buf = [0u8; 4];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let pid = u32::from_le_bytes(buf) as usize;
            tty::set_foreground_pid(pid);
            0
        }
        FIONREAD => {
            if !validate_user_ptr(arg, 4) { return -14; }
            if copy_to_user(arg, &0u32.to_le_bytes()).is_err() { return -14; }
            0
        }
        FIOCLEX  => { crate::fs::fcntl::set_cloexec(fd, true);  0 }
        FIONCLEX => { crate::fs::fcntl::set_cloexec(fd, false); 0 }
        _ => -25, // ENOTTY
    }
}

// ── Framebuffer ioctl handler ─────────────────────────────────────────────────

fn fb_ioctl(request: usize, arg: usize) -> isize {
    match request {
        FBIOGET_VSCREENINFO => {
            let sz = core::mem::size_of::<FbVarScreenInfo>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let info = match drm::gop_info() { Some(i) => i, None => return -19 };
            let (ro, go, bo) = pixel_offsets(info.pixel_format);
            let var = FbVarScreenInfo {
                xres:           info.width,
                yres:           info.height,
                xres_virtual:   info.pixels_per_line,
                yres_virtual:   info.height,
                xoffset: 0, yoffset: 0,
                bits_per_pixel: 32,
                grayscale: 0,
                red_offset:   ro, red_length:   8, red_msb_right:   0, _r: 0,
                green_offset: go, green_length: 8, green_msb_right: 0, _g: 0,
                blue_offset:  bo, blue_length:  8, blue_msb_right:  0, _b: 0,
                transp_offset: 24, transp_length: 0, transp_msb_right: 0, _t: 0,
                nonstd: 0, activate: 0,
                height_mm: 0, width_mm: 0,
                accel_flags: 0, pixclock: 0,
                left_margin: 0, right_margin: 0, upper_margin: 0, lower_margin: 0,
                hsync_len: 0, vsync_len: 0, sync: 0, vmode: 0, rotate: 0,
                colorspace: 0, reserved: [0; 4],
            };
            let bytes = unsafe {
                core::slice::from_raw_parts(&var as *const FbVarScreenInfo as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }
        FBIOPUT_VSCREENINFO => {
            // Accept any write that matches our actual resolution; reject others.
            let sz = core::mem::size_of::<FbVarScreenInfo>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut buf = alloc::vec![0u8; sz];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let var = unsafe {
                core::ptr::read_unaligned(buf.as_ptr() as *const FbVarScreenInfo)
            };
            let info = match drm::gop_info() { Some(i) => i, None => return -19 };
            if var.xres != info.width || var.yres != info.height
                || var.bits_per_pixel != 32 {
                return -22; // EINVAL
            }
            0
        }
        FBIOGET_FSCREENINFO => {
            let sz = core::mem::size_of::<FbFixScreenInfo>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let info = match drm::gop_info() { Some(i) => i, None => return -19 };
            let mut id = [0u8; 16];
            let name = b"rustos_gop_fb";
            id[..name.len()].copy_from_slice(name);
            let fix = FbFixScreenInfo {
                id,
                smem_start:  info.fb_phys as usize,
                smem_len:    crate::drivers::gop::fb_byte_size(&info) as u32,
                type_:       0,   // FB_TYPE_PACKED_PIXELS
                type_aux:    0,
                visual:      2,   // FB_VISUAL_TRUECOLOR
                xpanstep:    0, ypanstep: 0, ywrapstep: 0, _pad: 0,
                line_length: info.pixels_per_line * 4,
                mmio_start:  0, mmio_len: 0,
                accel:       0,
                capabilities: 0,
                reserved:    [0; 2],
            };
            let bytes = unsafe {
                core::slice::from_raw_parts(&fix as *const FbFixScreenInfo as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }
        FBIOBLANK => 0, // ignored
        _ => -25,
    }
}

/// Return (red_offset, green_offset, blue_offset) in bits for a given pixel format.
fn pixel_offsets(fmt: PixelFormat) -> (u32, u32, u32) {
    match fmt {
        PixelFormat::Rgbx    => (0,  8,  16),
        PixelFormat::Bgrx    => (16, 8,  0),
        PixelFormat::BitMask => (0,  8,  16),
        PixelFormat::BltOnly => (0,  8,  16),
    }
}

// ── DRM ioctl handler ─────────────────────────────────────────────────────────

fn drm_ioctl(request: usize, arg: usize) -> isize {
    match request {

        DRM_IOCTL_VERSION => {
            let sz = core::mem::size_of::<DrmVersion>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut ver: DrmVersion = unsafe { core::mem::zeroed() };
            ver.version_major      = drm::driver_version().0;
            ver.version_minor      = drm::driver_version().1;
            ver.version_patchlevel = drm::driver_version().2;
            // Write driver name into user buffer if name pointer is set.
            let name_bytes = drm::driver_name().as_bytes();
            if ver.name != 0 && validate_user_ptr(ver.name, name_bytes.len()) {
                let _ = copy_to_user(ver.name, name_bytes);
            }
            ver.name_len = name_bytes.len();
            let bytes = unsafe {
                core::slice::from_raw_parts(&ver as *const DrmVersion as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }

        DRM_IOCTL_GET_CAP => {
            // Struct: { capability: u64, value: u64 }
            if !validate_user_ptr(arg, 16) { return -14; }
            let mut buf = [0u8; 16];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let cap = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            // DRM_CAP_DUMB_BUFFER = 1
            let val: u64 = if cap == 1 { 1 } else { 0 };
            buf[8..16].copy_from_slice(&val.to_le_bytes());
            if copy_to_user(arg, &buf).is_err() { return -14; }
            0
        }

        DRM_IOCTL_MODE_GETRESOURCES => {
            let sz = core::mem::size_of::<DrmModeCardRes>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut res: DrmModeCardRes = unsafe { core::mem::zeroed() };
            res.count_crtcs      = 1;
            res.count_connectors = 1;
            res.count_encoders   = 1;
            res.count_fbs        = 0;
            // Write CRTC id list if pointer is provided.
            if res.crtc_id_ptr != 0 && validate_user_ptr(res.crtc_id_ptr, 4) {
                let _ = copy_to_user(res.crtc_id_ptr, &drm::CRTC_ID.to_le_bytes());
            }
            if res.connector_id_ptr != 0 && validate_user_ptr(res.connector_id_ptr, 4) {
                let _ = copy_to_user(res.connector_id_ptr, &drm::CONNECTOR_ID.to_le_bytes());
            }
            if res.encoder_id_ptr != 0 && validate_user_ptr(res.encoder_id_ptr, 4) {
                let _ = copy_to_user(res.encoder_id_ptr, &drm::ENCODER_ID.to_le_bytes());
            }
            let bytes = unsafe {
                core::slice::from_raw_parts(&res as *const DrmModeCardRes as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }

        DRM_IOCTL_MODE_GETCRTC => {
            let sz = core::mem::size_of::<DrmModeCrtc>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut crtc: DrmModeCrtc = unsafe { core::mem::zeroed() };
            crtc.crtc_id = drm::CRTC_ID;
            if let Some(mode) = drm::current_mode() {
                crtc.mode_valid = 1;
                crtc.mode = DrmModeInfoRaw {
                    clock:    mode.clock,
                    hdisplay: mode.hdisplay,
                    vdisplay: mode.vdisplay,
                    vrefresh: mode.vrefresh,
                    name:     mode.name,
                    ..Default::default()
                };
            }
            let bytes = unsafe {
                core::slice::from_raw_parts(&crtc as *const DrmModeCrtc as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }

        DRM_IOCTL_MODE_GETCONNECTOR => {
            let sz = core::mem::size_of::<DrmModeGetConnector>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut conn: DrmModeGetConnector = unsafe { core::mem::zeroed() };
            conn.connector_id   = drm::CONNECTOR_ID;
            conn.encoder_id     = drm::ENCODER_ID;
            conn.connector_type = 14; // DRM_MODE_CONNECTOR_VIRTUAL
            conn.connection     = 1;  // connected
            conn.count_modes    = if drm::current_mode().is_some() { 1 } else { 0 };
            // Write mode list if pointer provided and count matches.
            if conn.modes_ptr != 0 && conn.count_modes == 1 {
                if let Some(mode) = drm::current_mode() {
                    let raw = DrmModeInfoRaw {
                        clock:    mode.clock,
                        hdisplay: mode.hdisplay,
                        vdisplay: mode.vdisplay,
                        vrefresh: mode.vrefresh,
                        name:     mode.name,
                        ..Default::default()
                    };
                    let mode_sz = core::mem::size_of::<DrmModeInfoRaw>();
                    if validate_user_ptr(conn.modes_ptr, mode_sz) {
                        let bytes = unsafe {
                            core::slice::from_raw_parts(
                                &raw as *const DrmModeInfoRaw as *const u8,
                                mode_sz,
                            )
                        };
                        let _ = copy_to_user(conn.modes_ptr, bytes);
                    }
                }
            }
            let bytes = unsafe {
                core::slice::from_raw_parts(&conn as *const DrmModeGetConnector as *const u8, sz)
            };
            if copy_to_user(arg, bytes).is_err() { return -14; }
            0
        }

        DRM_IOCTL_MODE_SETCRTC => {
            // Read the fb_id from the SetCrtc struct (offset 12).
            if !validate_user_ptr(arg, 16) { return -14; }
            let mut buf = [0u8; 16];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let fb_id = u32::from_le_bytes(buf[8..12].try_into().unwrap());
            drm::set_crtc(fb_id).map(|_| 0isize).unwrap_or(-22)
        }

        DRM_IOCTL_MODE_CREATE_DUMB => {
            let sz = core::mem::size_of::<DrmModeCreateDumb>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut buf = alloc::vec![0u8; sz];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let req = unsafe {
                core::ptr::read_unaligned(buf.as_ptr() as *const DrmModeCreateDumb)
            };
            match drm::create_dumb(req.width, req.height, req.bpp) {
                Ok((handle, pitch, size)) => {
                    let resp = DrmModeCreateDumb {
                        handle, pitch, size,
                        width: req.width, height: req.height, bpp: req.bpp, flags: 0,
                    };
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            &resp as *const DrmModeCreateDumb as *const u8, sz)
                    };
                    if copy_to_user(arg, bytes).is_err() { return -14; }
                    0
                }
                Err(e) => e,
            }
        }

        DRM_IOCTL_MODE_MAP_DUMB => {
            let sz = core::mem::size_of::<DrmModeMapDumb>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut buf = alloc::vec![0u8; sz];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let req = unsafe {
                core::ptr::read_unaligned(buf.as_ptr() as *const DrmModeMapDumb)
            };
            match drm::map_dumb(req.handle) {
                Ok(phys) => {
                    // Return the physical address as the mmap offset.
                    // Userspace will mmap(offset) and get the framebuffer.
                    let resp = DrmModeMapDumb { handle: req.handle, pad: 0, offset: phys };
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            &resp as *const DrmModeMapDumb as *const u8, sz)
                    };
                    if copy_to_user(arg, bytes).is_err() { return -14; }
                    0
                }
                Err(e) => e,
            }
        }

        DRM_IOCTL_MODE_DESTROY_DUMB => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut buf = [0u8; 4];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let handle = u32::from_le_bytes(buf);
            drm::destroy_dumb(handle).map(|_| 0isize).unwrap_or(-9)
        }

        DRM_IOCTL_MODE_ADDFB => {
            let sz = core::mem::size_of::<DrmModeAddFb>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut buf = alloc::vec![0u8; sz];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let req = unsafe {
                core::ptr::read_unaligned(buf.as_ptr() as *const DrmModeAddFb)
            };
            match drm::add_fb(req.handle, req.width, req.height, req.pitch, req.bpp) {
                Ok(fb_id) => {
                    // Write back fb_id at offset 24 in the struct.
                    if copy_to_user(arg + 24, &fb_id.to_le_bytes()).is_err() { return -14; }
                    0
                }
                Err(e) => e,
            }
        }

        DRM_IOCTL_MODE_RMFB => {
            if !validate_user_ptr(arg, 4) { return -14; }
            let mut buf = [0u8; 4];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let fb_id = u32::from_le_bytes(buf);
            drm::rm_fb(fb_id).map(|_| 0isize).unwrap_or(-9)
        }

        DRM_IOCTL_MODE_PAGE_FLIP => {
            let sz = core::mem::size_of::<DrmModePageFlip>();
            if !validate_user_ptr(arg, sz) { return -14; }
            let mut buf = alloc::vec![0u8; sz];
            if copy_from_user(&mut buf, arg).is_err() { return -14; }
            let req = unsafe {
                core::ptr::read_unaligned(buf.as_ptr() as *const DrmModePageFlip)
            };
            drm::page_flip(req.fb_id).map(|_| 0isize).unwrap_or(-22)
        }

        _ => -25, // ENOTTY
    }
}
