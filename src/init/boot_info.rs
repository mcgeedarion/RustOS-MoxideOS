//! Boot handoff data shared by every firmware and bare-metal entry path.
//!
//! The architecture stubs fill this structure with the immutable facts they
//! learned from firmware before jumping into the common `kernel_main` symbol.

/// Physical address/length pair for blobs handed to the kernel by firmware.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootRange {
    pub start: usize,
    pub len: usize,
}

impl BootRange {
    pub const fn empty() -> Self {
        Self { start: 0, len: 0 }
    }

    pub const fn new(start: usize, len: usize) -> Self {
        Self { start, len }
    }

    pub const fn is_empty(&self) -> bool {
        self.start == 0 || self.len == 0
    }
}

/// EFI memory-map metadata saved before `ExitBootServices`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EfiMemoryMapInfo {
    pub ptr: usize,
    pub size: usize,
    pub desc_size: usize,
}

impl EfiMemoryMapInfo {
    pub const fn empty() -> Self {
        Self {
            ptr: 0,
            size: 0,
            desc_size: 0,
        }
    }

    pub const fn new(ptr: usize, size: usize, desc_size: usize) -> Self {
        Self {
            ptr,
            size,
            desc_size,
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.ptr == 0 || self.size == 0 || self.desc_size == 0
    }
}

/// Optional framebuffer discovered by firmware.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferInfo {
    pub base: usize,
    pub size: usize,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}

impl FramebufferInfo {
    pub const fn none() -> Self {
        Self {
            base: 0,
            size: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: 0,
        }
    }
}

/// Firmware/bare-metal payload passed to the single common kernel entry point.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootInfo {
    pub rsdp_phys: u64,
    pub efi_memory_map: EfiMemoryMapInfo,
    pub framebuffer: FramebufferInfo,
    pub initramfs: BootRange,
    pub cmdline: BootRange,
    pub fdt: BootRange,
    pub boot_hart_id: usize,
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            rsdp_phys: 0,
            efi_memory_map: EfiMemoryMapInfo::empty(),
            framebuffer: FramebufferInfo::none(),
            initramfs: BootRange::empty(),
            cmdline: BootRange::empty(),
            fdt: BootRange::empty(),
            boot_hart_id: 0,
        }
    }
}
