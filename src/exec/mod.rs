//! Executable format parsing and binary loading.
//!
//! ## Modules
//!
//!   `elf` — ELF-64 parser: headers, program headers, section headers,
//!           dynamic linking metadata, and symbol table access.
//!           Used by `crate::proc::exec` to map user binaries into
//!           a new address space at `execve` time.

pub mod elf;
