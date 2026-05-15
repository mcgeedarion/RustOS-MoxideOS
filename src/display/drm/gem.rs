//! GEM (Graphics Execution Manager) object management.
//!
//! GEM objects are the backing store for GPU buffers. They can be
//! allocated, mapped, and shared between processes via handles.

pub struct GemObject {
    pub handle: u32,
    pub size: usize,
    /// Physical address of the backing memory, if pinned.
    pub phys_addr: Option<u64>,
}

impl GemObject {
    pub fn new(handle: u32, size: usize) -> Self {
        Self {
            handle,
            size,
            phys_addr: None,
        }
    }

    pub fn pin(&mut self, phys_addr: u64) {
        self.phys_addr = Some(phys_addr);
    }

    pub fn unpin(&mut self) {
        self.phys_addr = None;
    }

    pub fn is_pinned(&self) -> bool {
        self.phys_addr.is_some()
    }
}
