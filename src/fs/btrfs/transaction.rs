//! Btrfs copy-on-write write path.
//! Full CoW tree modification is implemented in fs_ops.rs / tree_impl.rs.
//! This module is a re-export shim for clarity.

pub use super::superblock::BtrfsFs;
