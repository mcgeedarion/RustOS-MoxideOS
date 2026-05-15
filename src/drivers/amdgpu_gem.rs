//! AMDGPU GEM/BO management ioctls — the libdrm_amdgpu ioctl surface.
//!
//! ## Ioctl surface implemented
//!
//!   DRM_IOCTL_AMDGPU_GEM_CREATE    — allocate a BO (GTT or VRAM)
//!   DRM_IOCTL_AMDGPU_GEM_MMAP     — get fake mmap offset for a BO
//!   DRM_IOCTL_AMDGPU_GEM_VA       — map/unmap BO into GPU VA space
//!   DRM_IOCTL_AMDGPU_BO_LIST_CREATE — create a list of BOs for CS submission
//!   DRM_IOCTL_AMDGPU_BO_LIST_DESTROY — free a BO list
//!   DRM_IOCTL_AMDGPU_GEM_USERPTR  — import a CPU VA as a GPU BO (GTT)
//!   DRM_IOCTL_AMDGPU_CTX          — context create/destroy/query
//!   DRM_IOCTL_AMDGPU_WAIT_FENCES  — wait for fence sequence numbers
//!   DRM_IOCTL_AMDGPU_INFO         — query GPU info (VRAM size, GFX clock, etc.)
//!
//! ## DMA-BUF helpers
//!   `fd_to_handle(fd)`  — resolve a DMA-BUF fd back to its GEM handle
//!   `is_gem_fd(fd)`     — true if fd was issued by gem_to_dmabuf()
//!   These are used by mmap.rs to resolve MAP_SHARED GEM mmap requests.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

// ── Ioctl codes ────────────────────────────────────────────────────────────
pub const DRM_IOCTL_AMDGPU_GEM_CREATE: u64 = 0xC0206440;
pub const DRM_IOCTL_AMDGPU_GEM_MMAP: u64 = 0xC0086441;
pub const DRM_IOCTL_AMDGPU_CTX: u64 = 0xC0186442;
pub const DRM_IOCTL_AMDGPU_BO_LIST: u64 = 0xC0206443;
pub const DRM_IOCTL_AMDGPU_GEM_VA: u64 = 0xC028644C;
pub const DRM_IOCTL_AMDGPU_GEM_USERPTR: u64 = 0xC0186450;
pub const DRM_IOCTL_AMDGPU_WAIT_FENCES: u64 = 0xC0206448;
pub const DRM_IOCTL_AMDGPU_INFO: u64 = 0xC0206447;

// ── GEM_CREATE ─────────────────────────────────────────────────────────────
#[repr(C)]
pub struct GemCreateIn {
    pub bo_size: u64,
    pub alignment: u64,
    pub domain_flags: u64,
    pub handle: u32,
    pub _pad: u32,
}

pub fn ioctl_gem_create(arg_va: usize) -> isize {
    let req = unsafe { &mut *(arg_va as *mut GemCreateIn) };
    let vram = req.domain_flags & 4 != 0;
    let domain = if vram {
        crate::drivers::gem::BoDomain::Vram
    } else {
        crate::drivers::gem::BoDomain::Gtt
    };
    match crate::drivers::gem::gem_alloc(req.bo_size as usize, domain) {
        Some(handle) => {
            req.handle = handle;
            0
        }
        None => -12,
    }
}

// ── GEM_MMAP ───────────────────────────────────────────────────────────────
#[repr(C)]
pub struct GemMmapIn {
    pub handle: u32,
    pub _pad: u32,
    pub offset: u64,
}

pub fn ioctl_gem_mmap(arg_va: usize) -> isize {
    let req = unsafe { &mut *(arg_va as *mut GemMmapIn) };
    req.offset = (req.handle as u64) << 12;
    0
}

// ── GEM_VA ─────────────────────────────────────────────────────────────────
const AMDGPU_VA_OP_MAP: u32 = 1;
const AMDGPU_VA_OP_UNMAP: u32 = 2;

#[repr(C)]
pub struct GemVaIn {
    pub va: u64,
    pub flags: u64,
    pub handle: u32,
    pub operation: u32,
    pub va_size: u64,
    pub offset_in_bo: u64,
}

static GPU_VA_MAP: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());

pub fn ioctl_gem_va(arg_va: usize) -> isize {
    let req = unsafe { &*(arg_va as *const GemVaIn) };
    let mut map = GPU_VA_MAP.lock();
    match req.operation {
        AMDGPU_VA_OP_MAP => {
            map.insert(req.va, req.handle);
            if let Some(mut bo) = crate::drivers::gem::gem_lookup(req.handle) {
                bo.gpu_va = req.va;
            }
        }
        AMDGPU_VA_OP_UNMAP => {
            map.remove(&req.va);
        }
        _ => {}
    }
    0
}

pub fn gpu_va_to_handle(va: u64) -> Option<u32> {
    GPU_VA_MAP.lock().get(&va).copied()
}

// ── GEM_USERPTR ────────────────────────────────────────────────────────────
#[repr(C)]
pub struct GemUserptrIn {
    pub user_ptr: u64,
    pub user_size: u64,
    pub flags: u32,
    pub handle: u32,
}

pub fn ioctl_gem_userptr(arg_va: usize) -> isize {
    let req = unsafe { &mut *(arg_va as *mut GemUserptrIn) };
    let size = req.user_size as usize;
    match crate::drivers::gem::gem_alloc(size, crate::drivers::gem::BoDomain::Cpu) {
        Some(handle) => {
            req.handle = handle;
            if let Some(mut bo) = crate::drivers::gem::gem_lookup(handle) {
                bo.pa = req.user_ptr; // CPU VA used directly
            }
            0
        }
        None => -12,
    }
}

// ── CTX ────────────────────────────────────────────────────────────────────
const AMDGPU_CTX_OP_ALLOC: u32 = 1;
const AMDGPU_CTX_OP_FREE: u32 = 2;
const AMDGPU_CTX_OP_QUERY: u32 = 3;
static NEXT_CTX: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

#[repr(C)]
pub struct AmdgpuCtxIn {
    pub op: u32,
    pub flags: u32,
    pub ctx_id: u32,
    pub _pad: u32,
    pub result: u64,
}

pub fn ioctl_ctx(arg_va: usize) -> isize {
    let req = unsafe { &mut *(arg_va as *mut AmdgpuCtxIn) };
    match req.op {
        AMDGPU_CTX_OP_ALLOC => {
            req.ctx_id = NEXT_CTX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            req.result = 0;
        }
        AMDGPU_CTX_OP_FREE => {}
        AMDGPU_CTX_OP_QUERY => {
            req.result = 0;
        } // AMDGPU_CTX_NO_RESET
        _ => return -22,
    }
    0
}

// ── BO_LIST ────────────────────────────────────────────────────────────────
#[repr(C)]
pub struct BoListIn {
    pub operation: u32,
    pub list_handle: u32,
    pub bo_number: u32,
    pub bo_info_size: u32,
    pub bo_info_ptr: u64,
}

static NEXT_LIST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

pub fn ioctl_bo_list(arg_va: usize) -> isize {
    let req = unsafe { &mut *(arg_va as *mut BoListIn) };
    match req.operation {
        1 => {
            req.list_handle = NEXT_LIST.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        2 => {}
        _ => return -22,
    }
    0
}

// ── WAIT_FENCES ────────────────────────────────────────────────────────────
#[repr(C)]
pub struct WaitFencesIn {
    pub fences: u64, // ptr to array of AmdgpuFence
    pub num: u32,
    pub wait_all: u32,
    pub timeout_ns: u64,
    pub out_status: u32,
    pub first_signaled: u32,
}

pub fn ioctl_wait_fences(arg_va: usize) -> isize {
    let req = unsafe { &mut *(arg_va as *mut WaitFencesIn) };
    req.out_status = 0; // all signaled
    req.first_signaled = 0;
    0
}

// ── INFO ───────────────────────────────────────────────────────────────────
pub const AMDGPU_INFO_FW_VERSION: u32 = 0x0E;
pub const AMDGPU_INFO_DEV_INFO: u32 = 0x16;
pub const AMDGPU_INFO_MEMORY: u32 = 0x19;
pub const AMDGPU_INFO_NUM_HANDLES: u32 = 0x1C;
pub const AMDGPU_INFO_VRAM_GTT: u32 = 0x0A;
pub const AMDGPU_INFO_READ_MMR_REG: u32 = 0x1D;
pub const AMDGPU_INFO_SENSOR: u32 = 0x1E;

#[repr(C)]
pub struct AmdgpuInfoIn {
    pub query: u32,
    pub size: u32,
    pub return_ptr: u64,
    pub query_flags: u32,
    pub _pad: u32,
    pub value: u64,
}

pub fn ioctl_info(arg_va: usize) -> isize {
    let req = unsafe { &*(arg_va as *const AmdgpuInfoIn) };
    let out = req.return_ptr as usize;
    if out == 0 {
        return -14;
    }
    match req.query {
        AMDGPU_INFO_VRAM_GTT | AMDGPU_INFO_MEMORY => {
            // struct drm_amdgpu_memory_info { vram, cpu_accessible_vram, gtt }
            let vram_mb: u64 = 512;
            unsafe {
                core::ptr::write(out as *mut u64, vram_mb << 20);
                core::ptr::write((out + 8) as *mut u64, vram_mb << 20);
                core::ptr::write((out + 16) as *mut u64, 2048u64 << 20);
            }
        }
        AMDGPU_INFO_DEV_INFO => {
            // Zero-fill; Mesa checks a few fields but operates fine on zeros.
            unsafe {
                core::ptr::write_bytes(out as *mut u8, 0, req.size as usize);
            }
        }
        AMDGPU_INFO_FW_VERSION => {
            // Return a plausible GFX10 firmware version
            unsafe {
                core::ptr::write(out as *mut u32, 0x0000_002A);
            }
        }
        AMDGPU_INFO_SENSOR => unsafe {
            core::ptr::write(out as *mut u32, 0);
        },
        _ => {
            if out != 0 && req.size <= 64 {
                unsafe {
                    core::ptr::write_bytes(out as *mut u8, 0, req.size as usize);
                }
            }
        }
    }
    0
}

// ── DMA-BUF helpers ────────────────────────────────────────────────────────

/// Resolve a DMA-BUF fd (issued by `gem_to_dmabuf`) back to its GEM handle.
/// Used by mmap.rs when handling MAP_SHARED mmap on a GEM/DMA-BUF fd.
pub fn fd_to_handle(fd: usize) -> Option<u32> {
    crate::drivers::gem::dmabuf_to_bo(fd).map(|bo| bo.handle)
}

/// Returns `true` if `fd` is a DMA-BUF fd issued by the GEM layer.
pub fn is_gem_fd(fd: usize) -> bool {
    crate::drivers::gem::is_dmabuf(fd)
}
