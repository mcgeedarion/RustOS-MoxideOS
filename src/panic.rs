// Legacy shim — code has moved to src/kernel/panic.rs
// This file is retained so that `crate::panic` continues to compile.
// Update callers to use `crate::kernel::panic` and remove this file.
pub use crate::kernel::panic::*;
