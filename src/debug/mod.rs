//! Kernel debugging infrastructure.
//!
//! Contains the GDB Remote Serial Protocol (RSP) stub for source-level
//! debugging via QEMU's -s flag or a hardware JTAG probe.

pub mod gdbstub;
