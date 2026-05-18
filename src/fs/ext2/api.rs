//! Public VFS entry-points: mount(), sys_stat(), read_file() …
//! Source lines 1035–end of the original ext2.rs monolith.
extern crate alloc;
use alloc::{vec::Vec, string::String};
use super::structs::{Ext2Stat, Ext2DirEntry, Ext2Statfs};
