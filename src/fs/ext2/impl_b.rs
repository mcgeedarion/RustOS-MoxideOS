//! impl Ext2Fs — path resolution, directory operations, metadata.
//! Source lines 641–1034 of the original ext2.rs monolith.
extern crate alloc;
use alloc::{vec, vec::Vec, string::{String, ToString}, collections::BTreeMap};
use super::structs::*;
