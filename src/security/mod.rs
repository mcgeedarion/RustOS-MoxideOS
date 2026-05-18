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
pub mod dac;
pub mod lsm;
pub mod pti;
pub mod seccomp;
pub mod smep_smap;
pub mod ns;

#[cfg(feature = "cgroups")]
pub mod cgroups;
