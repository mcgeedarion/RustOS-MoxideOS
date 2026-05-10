//! This module has been merged into `eth.rs`.
//!
//! `MacAddr` and all Ethernet framing logic now live in `crate::net::eth`.
//! This file is kept as a one-line re-export so any out-of-tree code that
//! still references `crate::net::ethernet` compiles without changes.

pub use crate::net::eth::MacAddr;
