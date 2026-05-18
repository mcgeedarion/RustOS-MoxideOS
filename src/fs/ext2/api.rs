//! Public VFS entry-points for ext2.
//! Source lines 1035–end of the original ext2.rs monolith.
extern crate alloc;
use alloc::{vec::Vec, string::String};
use super::structs::{Ext2Stat, Ext2DirEntry, Ext2Statfs};
