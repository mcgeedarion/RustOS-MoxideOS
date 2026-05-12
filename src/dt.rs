// Legacy shim — code has moved to src/firmware/dt.rs
// This file is retained so that `crate::dt` continues to compile.
// Update callers to use `crate::firmware::dt` and remove this file.
pub use crate::firmware::dt::*;
