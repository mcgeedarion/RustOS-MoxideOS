//! Allocator sub-modules.
//!
//! * `buddy`           — binary buddy allocator (power-of-two blocks, 4 KiB–16 MiB)
//! * `fixed_size_block` — segregated free-list allocator with buddy fallback

pub mod buddy;
pub mod fixed_size_block;
