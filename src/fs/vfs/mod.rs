//! Virtual filesystem core.

pub mod fd;
pub mod ops;
pub mod uring;

// Preserve the historical `crate::fs::vfs::*` facade after moving the
pub use fd::*;

/// Compatibility helper for older callers that create and populate a file in
/// one step.
pub fn create_file(path: &str, data: &[u8]) -> Result<(), isize> {
    match ops::create(path) {
        Ok(()) | Err(-17) => {},
        Err(e) => return Err(e),
    }
    ops::write_all(path, data)
}

/// Placeholder VFS scheme adapter. Path-based VFS syscalls remain available;
/// URL scheme dispatch returns `NoSuchScheme` until the adapter is completed.
pub struct VfsScheme;

impl VfsScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for VfsScheme {
    fn open(
        &self,
        _path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        Err(scheme_api::SchemeError::NoSuchScheme)
    }

    fn close(&self, _fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        Ok(())
    }
}
