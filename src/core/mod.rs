//! `core` — the zero-dependency kernel foundation.
//!
//! Every other subsystem **may** import from here; nothing here imports
//! from any other kernel subsystem.  Keep it that way.
//!
//! Sub-modules
//! -----------
//! * [`error`]       — [`KernelError`] enum and [`KResult`] alias
//! * [`panic`]       — kernel panic handler
//! * [`cpu_local`]   — per-CPU variable accessor
//! * [`collections`] — intrusive linked-list and ring-buffer

#![allow(dead_code)]

pub mod collections;
pub mod cpu_local;
pub mod error;
pub mod panic;

pub use error::{KernelError, KResult};
