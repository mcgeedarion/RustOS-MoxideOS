//! Virtual filesystem core.
//!
//! This module groups the VFS facade, path-dispatch operations, and
//! io_uring-specific helpers under one subsystem directory.

pub mod fd;
pub mod ops;
pub mod uring;

// Preserve the historical `crate::fs::vfs::*` facade after moving the
// implementation into `fd.rs`.
pub use fd::*;
