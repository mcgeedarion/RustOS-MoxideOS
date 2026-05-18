//! Btrfs logical space allocator.
//! The alloc_cursor inside BtrfsFs provides a simple bump allocator
//! for CoW block allocation. See BtrfsFs::alloc_logical in tree.rs.

pub use super::tree::BtrfsFs;
