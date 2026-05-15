//! GEM (Graphics Execution Manager) buffer object management.
//!
//! GEM provides a unified API for allocating and sharing GPU-accessible
//! memory buffers between the kernel, drivers, and userspace.

use super::DrmError;

/// A GEM buffer object backed by physical memory.
pub struct GemObject {
    pub handle: u32,
    pub size: usize,
    /// Physical base address of the allocation.
    pub paddr: u64,
    /// Reference count.
    ref_count: u32,
}

impl GemObject {
    pub fn new(handle: u32, size: usize, paddr: u64) -> Result<Self, DrmError> {
        if size == 0 {
            return Err(DrmError::HardwareError("GEM: zero-size allocation"));
        }
        Ok(Self {
            handle,
            size,
            paddr,
            ref_count: 1,
        })
    }

    pub fn get(&mut self) {
        self.ref_count += 1;
    }

    pub fn put(&mut self) -> bool {
        self.ref_count -= 1;
        self.ref_count == 0
    }
}
