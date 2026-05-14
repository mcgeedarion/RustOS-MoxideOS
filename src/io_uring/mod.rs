//! io_uring subsystem.
//!
//! | Module    | Role                                      |
//! |-----------|-------------------------------------------|
//! | `ops`     | SQE opcode dispatch                       |
//! | `ring`    | Ring-buffer allocation and access         |
//! | `syscall` | NR 425 / 426 / 427 entry points           |

pub mod ops;
pub mod ring;
pub mod ring_pub;
pub mod syscall;

/// Called once from `kernel_main` after the physical memory allocator is up.
/// Initialises the global ring table.
pub fn init() {
    ring::init();
}
