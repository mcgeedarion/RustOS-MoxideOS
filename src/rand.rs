// Legacy shim — code has moved to src/kernel/rand.rs
// This file is retained so that `crate::rand` continues to compile.
// Update callers to use `crate::kernel::rand` and remove this file.
pub use crate::kernel::rand::*;
