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
