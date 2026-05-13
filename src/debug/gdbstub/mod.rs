// GDB stub — canonical implementation lives here.
// src/debug/gdbstub/ re-exports from this module via `pub use crate::gdbstub::*`
// in the shim at src/debug/gdbstub/mod.rs (which is kept for backward compat).

pub mod target;
pub mod rsp;
pub mod rsp_riscv;
pub mod serial;
