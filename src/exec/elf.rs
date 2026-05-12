// Exec: ELF parser — re-exported from the canonical location.
// All code lives in `src/elf.rs`; this shim lets `crate::exec::elf` work.
pub use crate::elf::*;
