// Legacy shim — code has moved to src/kernel/uaccess.rs
// This file is retained so that `crate::uaccess` continues to compile.
// Update callers to use `crate::kernel::uaccess` and remove this file.
pub use crate::kernel::uaccess::*;
