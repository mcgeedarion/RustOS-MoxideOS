//! Upper impl BtrfsFs: readdir, create, mkdir, unlink, rename, link, symlink …
//! Source lines 912–1239 of the original btrfs.rs monolith.
extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use super::superblock::*;
