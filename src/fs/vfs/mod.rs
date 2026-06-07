//! Virtual filesystem core.
//!

pub mod fd;
pub mod ops;
pub mod uring;

// Preserve the historical `crate::fs::vfs::*` facade after moving the
pub use fd::*;
