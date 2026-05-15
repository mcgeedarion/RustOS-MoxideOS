//! GPU hardware abstraction layer.
//!
//! This module sits between the concrete GPU backends (virtio-gpu, GOP,
//! amdgpu-GEM) and every kernel subsystem that needs to allocate pixel
//! buffers, perform scanout, or manage GPU fences.
//!
//! ## Architecture
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────────────┐
//!  │                     Kernel consumers                           │
//!  │   drm.rs · framebuffer.rs · compositor · userspace ioctls     │
//!  └───────────────────────┬────────────────────────────────────────┘
//!                          │  gpu::GpuDevice  (this file)
//!  ┌───────────────────────▼────────────────────────────────────────┐
//!  │                   gpu::REGISTRY                                │
//!  │  [ VirtioGpuBackend | GopBackend | AmdGpuBackend | Null ]      │
//!  └──────┬──────────────────┬──────────────────┬───────────────────┘
//!         │                  │                  │
//!  virtio_gpu.rs        gop.rs            amdgpu_gem.rs
//! ```
//!
//! ## Quick start
//!
//! ```rust
//! // Allocate a 1920×1080 BGRX framebuffer.
//! let buf = gpu::alloc_buffer(1920, 1080, gpu::PixelFormat::Bgrx32)?;
//! // Write pixels into buf.phys …
//! gpu::flush(&buf, 0, 0, 1920, 1080);
//! // When done:
//! gpu::free_buffer(buf);
//! ```
//!
//! ## Backend priority
//!
//! Backends are tried in the order they were registered.  The first one
//! that reports `is_available()` wins for each operation.  Virtio-GPU is
//! registered before GOP at init time so it is preferred in QEMU.
//!
//! ## Fence / sync model
//!
//! Each `flush` call returns a monotonically-increasing `FenceId`.  Callers
//! can pass a `FenceId` to `wait_fence` to block (spin) until the GPU has
//! finished the corresponding transfer.  The virtio-gpu backend signals
//! fences after the used-ring entry is consumed; the GOP backend signals
//! them immediately (memory-mapped VRAM is always coherent).

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// Re-exports used by callers that previously imported from framebuffer / drm
// ─────────────────────────────────────────────────────────────────────────────

pub use crate::drivers::drm::{
    add_fb, atomic_commit, create_dumb, crtc_id, destroy_dumb, get_resources, head_info, map_dumb,
    num_heads, page_flip_for, plane_id, rm_fb, set_crtc_for, vblank_count_head, vblank_tick_head,
    wait_vblank_head, AtomicProp, DrmModeInfo, HeadInfo, KmsResources, MAX_HEADS,
};

// ─────────────────────────────────────────────────────────────────────────────
// Pixel formats
// ─────────────────────────────────────────────────────────────────────────────

/// Pixel-format descriptor understood by every backend.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PixelFormat {
    /// B8 G8 R8 X8 — 4 bytes per pixel, byte 3 unused. Default for KMS.
    Bgrx32,
    /// B8 G8 R8 A8 — premultiplied alpha.
    Bgra32,
    /// R8 G8 B8 X8 — byte 3 unused.
    Rgbx32,
    /// R8 G8 B8 A8 — premultiplied alpha.
    Rgba32,
    /// 8-bit grey.
    Grey8,
}

impl PixelFormat {
    /// Bytes per pixel.
    #[inline]
    pub const fn bpp(self) -> u32 {
        match self {
            PixelFormat::Grey8 => 1,
            _ => 4,
        }
    }
    /// DRM four-cc code for this format.
    pub const fn fourcc(self) -> u32 {
        match self {
            PixelFormat::Bgrx32 => fourcc(b'X', b'R', b'2', b'4'), // XR24
            PixelFormat::Bgra32 => fourcc(b'A', b'R', b'2', b'4'), // AR24
            PixelFormat::Rgbx32 => fourcc(b'X', b'B', b'2', b'4'), // XB24
            PixelFormat::Rgba32 => fourcc(b'A', b'B', b'2', b'4'), // AB24
            PixelFormat::Grey8 => fourcc(b'R', b'8', b' ', b' '),  // R8
        }
    }
}

#[inline]
const fn fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    a as u32 | (b as u32) << 8 | (c as u32) << 16 | (d as u32) << 24
}

// ─────────────────────────────────────────────────────────────────────────────
// GpuBuffer — a contiguous physical memory region owned by one backend
// ─────────────────────────────────────────────────────────────────────────────

/// A hardware-backed pixel buffer.
///
/// Returned by `alloc_buffer`.  Callers write directly into `phys` (which is
/// identity-mapped for the kernel), then call `flush` to synchronise with the
/// display hardware.
#[derive(Clone, Copy, Debug)]
pub struct GpuBuffer {
    /// Guest-physical (= kernel-virtual for identity pages) base address.
    pub phys: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row.  Always `width * format.bpp()` unless the backend
    /// requires alignment padding.
    pub stride: u32,
    /// Pixel format of the buffer.
    pub format: PixelFormat,
    /// Opaque backend handle (GEM handle, BAR offset, etc.).
    /// Zero if unused by the backing driver.
    pub handle: u64,
    /// Which backend owns this buffer (index into `REGISTRY`).
    pub backend: u8,
}

impl GpuBuffer {
    /// Safe pixel-slice view (immutable).
    ///
    /// # Safety
    /// Callers must ensure no concurrent mutable access through the hardware.
    #[inline]
    pub unsafe fn pixels(&self) -> &[u32] {
        let n = (self.stride as usize / 4) * self.height as usize;
        core::slice::from_raw_parts(self.phys as *const u32, n)
    }

    /// Safe pixel-slice view (mutable).
    ///
    /// # Safety
    /// Callers must ensure no concurrent access by the GPU.
    #[inline]
    pub unsafe fn pixels_mut(&mut self) -> &mut [u32] {
        let n = (self.stride as usize / 4) * self.height as usize;
        core::slice::from_raw_parts_mut(self.phys as *mut u32, n)
    }

    /// Total byte size of the backing store.
    #[inline]
    pub fn byte_len(&self) -> usize {
        self.stride as usize * self.height as usize
    }

    /// Write a single pixel (BGRX / BGRA u32 value).  Bounds-checked.
    #[inline]
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let off = (y * (self.stride / 4) + x) as usize;
        unsafe {
            (self.phys as *mut u32).add(off).write_volatile(color);
        }
    }

    /// Fill entire buffer with a constant colour.
    pub fn fill(&mut self, color: u32) {
        let words = (self.stride as usize / 4) * self.height as usize;
        let base = self.phys as *mut u32;
        for i in 0..words {
            unsafe {
                base.add(i).write_volatile(color);
            }
        }
    }

    /// Copy a row-major BGRX/BGRA slice into the buffer at `(dx, dy)`.
    pub fn blit(&mut self, dx: u32, dy: u32, src_w: u32, src_h: u32, src: &[u32]) {
        for row in 0..src_h {
            if dy + row >= self.height {
                break;
            }
            for col in 0..src_w {
                if dx + col >= self.width {
                    continue;
                }
                let si = (row * src_w + col) as usize;
                if si < src.len() {
                    self.put_pixel(dx + col, dy + row, src[si]);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fence — lightweight GPU synchronisation primitive
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque fence identifier returned by `flush`.
///
/// A `FenceId` of **0** means "already signalled" and `wait_fence` returns
/// immediately.  Fence IDs are monotonically increasing per-backend.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FenceId(pub u64);

impl FenceId {
    pub const SIGNALLED: Self = FenceId(0);
}

// ─────────────────────────────────────────────────────────────────────────────
// GpuDevice trait — the contract every backend must fulfil
// ─────────────────────────────────────────────────────────────────────────────

/// Trait implemented by every GPU / display backend.
///
/// All methods have default no-op / error implementations so backends only
/// need to override what they support.
pub trait GpuDevice: Send + Sync {
    // ── Identity ────────────────────────────────────────────────────────

    /// Short ASCII name for logging (e.g. `"virtio-gpu"`, `"gop"`, `"amdgpu"`).
    fn name(&self) -> &'static str;

    /// `true` if this backend has been successfully initialised and the
    /// hardware is present.
    fn is_available(&self) -> bool;

    // ── Display geometry ────────────────────────────────────────────────

    /// Number of independent display outputs (scanouts / CRTCs).
    fn num_outputs(&self) -> usize {
        1
    }

    /// Resolution of output `idx`.  Returns `None` if `idx` is out of range.
    fn output_size(&self, idx: usize) -> Option<(u32, u32)>;

    /// Physical base address of the framebuffer backing output `idx`.
    /// The kernel identity-maps all physical pages so this is also the
    /// kernel-virtual address.
    fn output_fb_phys(&self, idx: usize) -> Option<u64>;

    // ── Buffer lifecycle ────────────────────────────────────────────────

    /// Allocate a pixel buffer of `(w × h)` pixels in `format`.
    ///
    /// The returned `GpuBuffer::phys` is immediately writable by the CPU.
    /// Returns `Err(-12)` (ENOMEM) on allocation failure.
    fn alloc(&self, w: u32, h: u32, fmt: PixelFormat) -> Result<GpuBuffer, isize>;

    /// Release a buffer previously returned by `alloc`.
    fn free(&self, buf: GpuBuffer);

    // ── Scanout / flush ─────────────────────────────────────────────────

    /// Make `buf` the current scanout for `output_idx`.
    ///
    /// This maps the buffer's physical memory to the display; the buffer must
    /// have dimensions matching the output.  Returns `-22` (EINVAL) if the
    /// dimensions do not match.
    fn set_scanout(&self, output_idx: usize, buf: &GpuBuffer) -> Result<(), isize> {
        let _ = (output_idx, buf);
        Err(-38) // ENOSYS
    }

    /// Flush a dirty rectangle of `buf` to the physical display.
    ///
    /// Returns a `FenceId` that will be signalled once the GPU transfer is
    /// complete.  For memory-coherent backends (GOP) this is always
    /// `FenceId::SIGNALLED`.
    fn flush(&self, buf: &GpuBuffer, x: u32, y: u32, w: u32, h: u32) -> FenceId;

    /// Flush the entire buffer.
    fn flush_all(&self, buf: &GpuBuffer) -> FenceId {
        self.flush(buf, 0, 0, buf.width, buf.height)
    }

    // ── Fence synchronisation ───────────────────────────────────────────

    /// Spin-wait until `fence` is signalled by this backend.
    ///
    /// The default implementation is a no-op (correct for GOP / coherent
    /// backends that always return `FenceId::SIGNALLED`).
    fn wait_fence(&self, fence: FenceId) {
        let _ = fence;
    }

    // ── Cursor ──────────────────────────────────────────────────────────

    /// Upload a 64×64 ARGB cursor bitmap to `output_idx` at `(x, y)`.
    fn cursor_update(&self, output_idx: usize, pixels: &[u32], x: i32, y: i32) {
        let _ = (output_idx, pixels, x, y);
    }

    /// Move the cursor on `output_idx` without re-uploading the bitmap.
    fn cursor_move(&self, output_idx: usize, x: i32, y: i32, visible: bool) {
        let _ = (output_idx, x, y, visible);
    }

    // ── Mode setting (optional) ──────────────────────────────────────────

    /// Perform a hardware mode-set.  Backends that do not support runtime
    /// mode changes return `Err(-38)` (ENOSYS).
    fn set_mode(
        &self,
        output_idx: usize,
        width: u32,
        height: u32,
        refresh_hz: u32,
    ) -> Result<(), isize> {
        let _ = (output_idx, width, height, refresh_hz);
        Err(-38)
    }

    // ── GEM / buffer object sharing (optional) ───────────────────────────

    /// Import a dma-buf file-descriptor.  Returns a backend-specific handle
    /// and the physical address of the buffer.
    fn import_dmabuf(&self, fd: i32) -> Result<(u64, u64), isize> {
        let _ = fd;
        Err(-38)
    }

    /// Export a buffer as a dma-buf file-descriptor.
    fn export_dmabuf(&self, buf: &GpuBuffer) -> Result<i32, isize> {
        let _ = buf;
        Err(-38)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Concrete backends
// ─────────────────────────────────────────────────────────────────────────────

// ── virtio-gpu ───────────────────────────────────────────────────────────────

pub struct VirtioGpuBackend;

static VIRTIO_FENCE_CTR: AtomicU64 = AtomicU64::new(1);

impl GpuDevice for VirtioGpuBackend {
    fn name(&self) -> &'static str {
        "virtio-gpu"
    }
    fn is_available(&self) -> bool {
        crate::drivers::virtio_gpu::is_present()
    }

    fn num_outputs(&self) -> usize {
        crate::drivers::virtio_gpu::num_scanouts()
    }

    fn output_size(&self, idx: usize) -> Option<(u32, u32)> {
        crate::drivers::virtio_gpu::scanout_info(idx).map(|(w, h, _)| (w, h))
    }

    fn output_fb_phys(&self, idx: usize) -> Option<u64> {
        crate::drivers::virtio_gpu::scanout_info(idx).map(|(_, _, p)| p)
    }

    fn alloc(&self, w: u32, h: u32, fmt: PixelFormat) -> Result<GpuBuffer, isize> {
        // For virtio-gpu we reuse the per-scanout framebuffer if dimensions
        // match; otherwise we allocate from the PMM and wire a new resource.
        // For the HAL we take the simpler path: allocate physical pages and
        // return a buffer backed by them.  The caller is responsible for
        // calling set_scanout before flush.
        let pages = size_pages(w as usize * h as usize * fmt.bpp() as usize);
        let phys = crate::mm::pmm::alloc_pages(pages)
            .map(|p| p.as_ptr() as u64)
            .ok_or(-12isize)?; // ENOMEM
        let stride = w * fmt.bpp();
        Ok(GpuBuffer {
            phys,
            width: w,
            height: h,
            stride,
            format: fmt,
            handle: 0,
            backend: 0,
        })
    }

    fn free(&self, buf: GpuBuffer) {
        let pages = size_pages(buf.byte_len());
        unsafe {
            crate::mm::pmm::free_pages(
                core::ptr::NonNull::new_unchecked(buf.phys as *mut u8),
                pages,
            );
        }
    }

    fn set_scanout(&self, output_idx: usize, buf: &GpuBuffer) -> Result<(), isize> {
        // Verify dimensions match the scanout.
        match crate::drivers::virtio_gpu::scanout_info(output_idx) {
            Some((w, h, _)) if w == buf.width && h == buf.height => Ok(()),
            Some(_) => Err(-22), // EINVAL
            None => Err(-6),     // ENXIO
        }
    }

    fn flush(&self, buf: &GpuBuffer, x: u32, y: u32, w: u32, h: u32) -> FenceId {
        // Issue TRANSFER + FLUSH for every scanout whose fb_phys matches.
        let n = crate::drivers::virtio_gpu::num_scanouts();
        for i in 0..n {
            if let Some((_, _, phys)) = crate::drivers::virtio_gpu::scanout_info(i) {
                if phys == buf.phys {
                    crate::drivers::virtio_gpu::flush_scanout(i);
                }
            }
        }
        // Also cover the case where the buffer is the primary framebuffer
        // returned at boot (fb_phys from scanout 0).
        if n == 0 {
            crate::drivers::virtio_gpu::flush_all();
        }
        let _ = (x, y, w, h); // rect-granular flush: virtio_gpu always full-surface
        FenceId(VIRTIO_FENCE_CTR.fetch_add(1, Ordering::Relaxed))
    }

    // Virtio-gpu flush is synchronous (poll_used spins until completion),
    // so the fence is already signalled by the time flush() returns.
    fn wait_fence(&self, _fence: FenceId) {}

    fn cursor_update(&self, idx: usize, pixels: &[u32], x: i32, y: i32) {
        crate::drivers::virtio_gpu::cursor_update_scanout(idx, pixels, x, y);
    }
    fn cursor_move(&self, idx: usize, x: i32, y: i32, visible: bool) {
        crate::drivers::virtio_gpu::cursor_move_scanout(idx, x, y, visible);
    }
}

// ── UEFI GOP backend ─────────────────────────────────────────────────────────

pub struct GopBackend;

impl GpuDevice for GopBackend {
    fn name(&self) -> &'static str {
        "gop"
    }
    fn is_available(&self) -> bool {
        crate::drivers::gop::get().is_some()
    }

    fn num_outputs(&self) -> usize {
        if self.is_available() {
            1
        } else {
            0
        }
    }

    fn output_size(&self, idx: usize) -> Option<(u32, u32)> {
        if idx != 0 {
            return None;
        }
        crate::drivers::gop::get().map(|g| (g.width, g.height))
    }

    fn output_fb_phys(&self, idx: usize) -> Option<u64> {
        if idx != 0 {
            return None;
        }
        crate::drivers::gop::get().map(|g| g.fb_phys)
    }

    fn alloc(&self, w: u32, h: u32, fmt: PixelFormat) -> Result<GpuBuffer, isize> {
        // For GOP the only writable surface is the UEFI linear framebuffer.
        // Return it directly for requests that match its dimensions; otherwise
        // allocate from PMM (off-screen buffer, not displayed until blitted).
        if let Some(g) = crate::drivers::gop::get() {
            if w == g.width && h == g.height {
                return Ok(GpuBuffer {
                    phys: g.fb_phys,
                    width: w,
                    height: h,
                    stride: g.pixels_per_line * 4,
                    format: fmt,
                    handle: 0,
                    backend: 1,
                });
            }
        }
        // Off-screen allocation.
        let pages = size_pages(w as usize * h as usize * fmt.bpp() as usize);
        let phys = crate::mm::pmm::alloc_pages(pages)
            .map(|p| p.as_ptr() as u64)
            .ok_or(-12isize)?;
        Ok(GpuBuffer {
            phys,
            width: w,
            height: h,
            stride: w * fmt.bpp(),
            format: fmt,
            handle: 0,
            backend: 1,
        })
    }

    fn free(&self, buf: GpuBuffer) {
        // If the buffer points to the GOP linear fb don't free it.
        let is_gop = crate::drivers::gop::get().map_or(false, |g| g.fb_phys == buf.phys);
        if !is_gop {
            let pages = size_pages(buf.byte_len());
            unsafe {
                crate::mm::pmm::free_pages(
                    core::ptr::NonNull::new_unchecked(buf.phys as *mut u8),
                    pages,
                );
            }
        }
    }

    /// GOP writes go directly to VRAM — flush is a no-op, fence is immediate.
    fn flush(&self, _buf: &GpuBuffer, _x: u32, _y: u32, _w: u32, _h: u32) -> FenceId {
        FenceId::SIGNALLED
    }
}

// ── AMD GEM backend (amdgpu_gem.rs) ─────────────────────────────────────────

pub struct AmdGpuBackend;

static AMD_FENCE_CTR: AtomicU64 = AtomicU64::new(1);

impl GpuDevice for AmdGpuBackend {
    fn name(&self) -> &'static str {
        "amdgpu"
    }
    fn is_available(&self) -> bool {
        crate::drivers::amdgpu_gem::is_present()
    }

    fn num_outputs(&self) -> usize {
        crate::drivers::amdgpu_gem::num_crtcs()
    }

    fn output_size(&self, idx: usize) -> Option<(u32, u32)> {
        crate::drivers::amdgpu_gem::crtc_size(idx)
    }
    fn output_fb_phys(&self, idx: usize) -> Option<u64> {
        crate::drivers::amdgpu_gem::crtc_fb_phys(idx)
    }

    fn alloc(&self, w: u32, h: u32, fmt: PixelFormat) -> Result<GpuBuffer, isize> {
        let (handle, phys, stride) =
            crate::drivers::amdgpu_gem::gem_alloc(w, h, fmt.bpp()).map_err(|_| -12isize)?;
        Ok(GpuBuffer {
            phys,
            width: w,
            height: h,
            stride,
            format: fmt,
            handle: handle as u64,
            backend: 2,
        })
    }

    fn free(&self, buf: GpuBuffer) {
        crate::drivers::amdgpu_gem::gem_free(buf.handle as u32);
    }

    fn set_scanout(&self, output_idx: usize, buf: &GpuBuffer) -> Result<(), isize> {
        crate::drivers::amdgpu_gem::set_scanout(output_idx, buf.handle as u32)
    }

    fn flush(&self, buf: &GpuBuffer, x: u32, y: u32, w: u32, h: u32) -> FenceId {
        crate::drivers::amdgpu_gem::gem_flush(buf.handle as u32, x, y, w, h);
        FenceId(AMD_FENCE_CTR.fetch_add(1, Ordering::Relaxed))
    }

    fn cursor_update(&self, idx: usize, pixels: &[u32], x: i32, y: i32) {
        crate::drivers::amdgpu_gem::cursor_update(idx, pixels, x, y);
    }
    fn cursor_move(&self, idx: usize, x: i32, y: i32, visible: bool) {
        crate::drivers::amdgpu_gem::cursor_move(idx, x, y, visible);
    }
    fn set_mode(
        &self,
        output_idx: usize,
        width: u32,
        height: u32,
        refresh_hz: u32,
    ) -> Result<(), isize> {
        crate::drivers::amdgpu_gem::set_mode(output_idx, width, height, refresh_hz)
    }
    fn import_dmabuf(&self, fd: i32) -> Result<(u64, u64), isize> {
        crate::drivers::amdgpu_gem::import_dmabuf(fd)
    }
    fn export_dmabuf(&self, buf: &GpuBuffer) -> Result<i32, isize> {
        crate::drivers::amdgpu_gem::export_dmabuf(buf.handle as u32)
    }
}

// ── Null / fallback backend ──────────────────────────────────────────────────

/// A null backend that is always last in the registry.  It allocates from
/// the PMM and simulates a 1024×768 display in RAM (useful for headless tests).
pub struct NullBackend;

const NULL_W: u32 = 1024;
const NULL_H: u32 = 768;
static NULL_FB: Mutex<Option<u64>> = Mutex::new(None);

impl GpuDevice for NullBackend {
    fn name(&self) -> &'static str {
        "null"
    }
    fn is_available(&self) -> bool {
        true
    } // always available as last resort

    fn output_size(&self, idx: usize) -> Option<(u32, u32)> {
        if idx == 0 {
            Some((NULL_W, NULL_H))
        } else {
            None
        }
    }

    fn output_fb_phys(&self, idx: usize) -> Option<u64> {
        if idx != 0 {
            return None;
        }
        let mut guard = NULL_FB.lock();
        if let Some(p) = *guard {
            return Some(p);
        }
        let pages = size_pages(NULL_W as usize * NULL_H as usize * 4);
        let phys = crate::mm::pmm::alloc_pages(pages)?.as_ptr() as u64;
        *guard = Some(phys);
        Some(phys)
    }

    fn alloc(&self, w: u32, h: u32, fmt: PixelFormat) -> Result<GpuBuffer, isize> {
        let pages = size_pages(w as usize * h as usize * fmt.bpp() as usize);
        let phys = crate::mm::pmm::alloc_pages(pages)
            .map(|p| p.as_ptr() as u64)
            .ok_or(-12isize)?;
        Ok(GpuBuffer {
            phys,
            width: w,
            height: h,
            stride: w * fmt.bpp(),
            format: fmt,
            handle: 0,
            backend: 3,
        })
    }

    fn free(&self, buf: GpuBuffer) {
        let pages = size_pages(buf.byte_len());
        unsafe {
            crate::mm::pmm::free_pages(
                core::ptr::NonNull::new_unchecked(buf.phys as *mut u8),
                pages,
            );
        }
    }

    fn flush(&self, _buf: &GpuBuffer, _x: u32, _y: u32, _w: u32, _h: u32) -> FenceId {
        FenceId::SIGNALLED // no hardware to notify
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend registry
// ─────────────────────────────────────────────────────────────────────────────

/// Registered backends in priority order.
///
/// Stored as `&'static dyn GpuDevice` so no heap allocation is needed for
/// the registry itself.  Each backend struct is a zero-sized type (ZST)
/// placed in `.rodata`.
static BACKENDS: &[&'static dyn GpuDevice] =
    &[&VirtioGpuBackend, &AmdGpuBackend, &GopBackend, &NullBackend];

/// Iterate registered backends.  Exposed for diagnostics.
pub fn backends() -> impl Iterator<Item = &'static dyn GpuDevice> {
    BACKENDS.iter().copied()
}

/// Return the first available backend, or the NullBackend.
fn primary() -> &'static dyn GpuDevice {
    for b in BACKENDS {
        if b.is_available() {
            return *b;
        }
    }
    &NullBackend
}

/// Return the backend best suited for `output_idx` on any backend.
fn backend_for_output(output_idx: usize) -> Option<(&'static dyn GpuDevice, usize)> {
    // Backends expose outputs 0..num_outputs().  Map a global output index
    // across all registered backends.
    let mut remaining = output_idx;
    for b in BACKENDS {
        if !b.is_available() {
            continue;
        }
        let n = b.num_outputs();
        if remaining < n {
            return Some((*b, remaining));
        }
        remaining -= n;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level public API  (delegates to the registry)
// ─────────────────────────────────────────────────────────────────────────────

/// Total number of display outputs across all backends.
pub fn total_outputs() -> usize {
    BACKENDS
        .iter()
        .filter(|b| b.is_available())
        .map(|b| b.num_outputs())
        .sum()
}

/// Resolution of global output `idx`.
/// Returns `None` if `idx` is out of range or no GPU is present.
pub fn output_size(idx: usize) -> Option<(u32, u32)> {
    let (b, local) = backend_for_output(idx)?;
    b.output_size(local)
}

/// Physical framebuffer address of global output `idx`.
pub fn output_fb_phys(idx: usize) -> Option<u64> {
    let (b, local) = backend_for_output(idx)?;
    b.output_fb_phys(local)
}

/// Allocate a pixel buffer using the primary (highest-priority available) backend.
///
/// Returns `Err(-19)` (ENODEV) if no backend is available.
pub fn alloc_buffer(w: u32, h: u32, fmt: PixelFormat) -> Result<GpuBuffer, isize> {
    primary().alloc(w, h, fmt)
}

/// Allocate a pixel buffer using whichever backend owns global `output_idx`.
pub fn alloc_for_output(output_idx: usize, fmt: PixelFormat) -> Result<GpuBuffer, isize> {
    let (b, local) = backend_for_output(output_idx).ok_or(-19isize)?;
    let (w, h) = b.output_size(local).ok_or(-6isize)?;
    b.alloc(w, h, fmt)
}

/// Free a buffer returned by `alloc_buffer` or `alloc_for_output`.
pub fn free_buffer(buf: GpuBuffer) {
    let b = BACKENDS
        .get(buf.backend as usize)
        .copied()
        .unwrap_or(&NullBackend);
    b.free(buf);
}

/// Flush `buf` dirty rect `(x, y, w, h)` to the physical display.
/// Returns a fence that can be passed to `wait_fence`.
pub fn flush(buf: &GpuBuffer, x: u32, y: u32, w: u32, h: u32) -> FenceId {
    let b = BACKENDS
        .get(buf.backend as usize)
        .copied()
        .unwrap_or(&NullBackend);
    b.flush(buf, x, y, w, h)
}

/// Flush the whole buffer.
pub fn flush_all(buf: &GpuBuffer) -> FenceId {
    flush(buf, 0, 0, buf.width, buf.height)
}

/// Spin-wait for a fence returned by `flush`.
pub fn wait_fence(buf: &GpuBuffer, fence: FenceId) {
    let b = BACKENDS
        .get(buf.backend as usize)
        .copied()
        .unwrap_or(&NullBackend);
    b.wait_fence(fence);
}

/// Make `buf` the active scanout on global `output_idx`.
pub fn set_scanout(output_idx: usize, buf: &GpuBuffer) -> Result<(), isize> {
    let (b, local) = backend_for_output(output_idx).ok_or(-6isize)?;
    b.set_scanout(local, buf)
}

/// Upload cursor bitmap to global output `output_idx`.
pub fn cursor_update(output_idx: usize, pixels: &[u32], x: i32, y: i32) {
    if let Some((b, local)) = backend_for_output(output_idx) {
        b.cursor_update(local, pixels, x, y);
    }
}

/// Move / hide cursor on global output `output_idx`.
pub fn cursor_move(output_idx: usize, x: i32, y: i32, visible: bool) {
    if let Some((b, local)) = backend_for_output(output_idx) {
        b.cursor_move(local, x, y, visible);
    }
}

/// Request a mode change.  Only supported by hardware KMS backends.
pub fn set_mode(output_idx: usize, width: u32, height: u32, refresh_hz: u32) -> Result<(), isize> {
    let (b, local) = backend_for_output(output_idx).ok_or(-6isize)?;
    b.set_mode(local, width, height, refresh_hz)
}

/// Import a dma-buf FD using the backend that owns `output_idx`.
pub fn import_dmabuf(output_idx: usize, fd: i32) -> Result<(u64, u64), isize> {
    let (b, _) = backend_for_output(output_idx).ok_or(-6isize)?;
    b.import_dmabuf(fd)
}

/// Export a buffer as a dma-buf FD.
pub fn export_dmabuf(buf: &GpuBuffer) -> Result<i32, isize> {
    let b = BACKENDS
        .get(buf.backend as usize)
        .copied()
        .unwrap_or(&NullBackend);
    b.export_dmabuf(buf)
}

/// Print a one-line status string for each registered backend.
/// Intended for the kernel boot log and /proc/gpu.
pub fn print_backends() {
    for (i, b) in BACKENDS.iter().enumerate() {
        let state = if b.is_available() {
            let n = b.num_outputs();
            if n == 1 {
                if let Some((w, h)) = b.output_size(0) {
                    // format: "[0] virtio-gpu  1 output  1920×1080"
                    log_backend(i, b.name(), n, w, h);
                    continue;
                }
            }
            // Multi-output or unknown size.
            log_backend_n(i, b.name(), n);
        } else {
            log_backend_absent(i, b.name());
        };
        let _ = state;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging helpers (no_std — no format! available without alloc)
// ─────────────────────────────────────────────────────────────────────────────

fn log_backend(idx: usize, name: &str, _n: usize, w: u32, h: u32) {
    crate::log::kprint("[gpu] ");
    crate::log::kprint_usize(idx);
    crate::log::kprint(" ");
    crate::log::kprint(name);
    crate::log::kprint("  ");
    crate::log::kprint_u32(w);
    crate::log::kprint("x");
    crate::log::kprint_u32(h);
    crate::log::kprint("\n");
}

fn log_backend_n(idx: usize, name: &str, n: usize) {
    crate::log::kprint("[gpu] ");
    crate::log::kprint_usize(idx);
    crate::log::kprint(" ");
    crate::log::kprint(name);
    crate::log::kprint("  ");
    crate::log::kprint_usize(n);
    crate::log::kprint(" outputs\n");
}

fn log_backend_absent(idx: usize, name: &str) {
    crate::log::kprint("[gpu] ");
    crate::log::kprint_usize(idx);
    crate::log::kprint(" ");
    crate::log::kprint(name);
    crate::log::kprint("  (not present)\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn size_pages(bytes: usize) -> usize {
    (bytes + 0xFFF) / 0x1000
}
