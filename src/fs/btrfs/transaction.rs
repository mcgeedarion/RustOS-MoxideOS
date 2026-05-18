//! Btrfs copy-on-write write path.
//! Full CoW tree modification is handled inside BtrfsFs methods in tree.rs.
//! This module re-exports the write entry points for clarity.

pub use super::tree::BtrfsFs;
