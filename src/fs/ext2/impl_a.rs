//! impl Ext2Fs — block/inode low-level I/O, bitmap allocation.
//! Source lines 258–640 of the original ext2.rs monolith.
extern crate alloc;
use alloc::{vec, vec::Vec, string::{String, ToString}, collections::BTreeMap};
use super::structs::*;
