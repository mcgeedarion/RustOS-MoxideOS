// Legacy shim — code has moved to src/exec/elf.rs
// This file is retained so that `crate::elf` continues to compile.
// Update callers to use `crate::exec::elf` and remove this file.
pub use crate::exec::elf::*;
