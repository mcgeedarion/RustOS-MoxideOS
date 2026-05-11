//! io_uring subsystem.
//!
//! Modules:
//!   ring    — ring buffer allocation and access
//!   ops     — SQE opcode dispatch
//!   syscall — NR 425/426/427 entry points

pub mod ring;
pub mod ops;
pub mod syscall;

/// Called once from kernel_main after the physical memory allocator is up.
/// Initialises the global ring table.
pub fn init() {
    ring::init();
}
