//! Core kernel utilities with no single subsystem home.
//!
//! ## Modules
//!
//!   `panic`   — Kernel panic handler: prints a backtrace and halts all CPUs.
//!   `rand`    — Cryptographically-seeded PRNG (ChaCha20); used by ASLR and
//!               stack-canary generation in `crate::security`.
//!   `uaccess` — Safe helpers for copying data between kernel and user space
//!               (`copy_from_user`, `copy_to_user`, `get_user`, `put_user`).
//!   `utils`   — Small cross-cutting helpers (alignment, bit ops, etc.).
//!   `architecture` — Hybrid-kernel architecture contract and diagnostics.

pub mod architecture;
pub mod panic;
pub mod rand;
pub mod uaccess;
pub mod utils;
