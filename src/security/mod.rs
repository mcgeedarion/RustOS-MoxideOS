//! Security subsystem: capabilities, ASLR, stack canaries, PTI,
//! SMEP/SMAP, seccomp, namespaces, LSM/MAC framework.
//!
//! ## Feature-gated sub-modules
//!
//! `cgroups` — cgroups v2 hierarchy + cgroupfs VFS mount.
//!             Compiled only when `--features cgroups` is passed.
//!             When `kernel-security` is split into its own crate this
//!             becomes a native feature of that crate, re-exported from
//!             the root as:
//!
//! ```toml
//! cgroups = ["kernel-security/cgroups"]
//! ```

pub mod aslr;
pub mod canary;
pub mod capset;
// GUESS: callers use crate::security::CapSet; canonical is capset::CapSet.
pub use capset::{cap, CapSet};

/// Compatibility constants for call sites that use named capability fields.
pub struct Cap;

impl Cap {
    pub const IpcLock: u8 = cap::IPC_LOCK;
    pub const SysNice: u8 = cap::SYS_NICE;
}
pub mod dac;
pub mod lsm;
pub mod ns;
pub mod pti;
pub mod seccomp;
pub mod smep_smap;

#[cfg(feature = "cgroups")]
pub mod cgroups;
