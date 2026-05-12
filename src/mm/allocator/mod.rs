// MM: heap allocator — re-exported from the canonical location.
// All code lives in `src/allocator/` and `src/allocator.rs`.
pub use crate::allocator::*;

pub mod buddy {
    pub use crate::allocator::buddy::*;
}

pub mod fixed_size_block {
    pub use crate::allocator::fixed_size_block::*;
}

pub mod stats {
    pub use crate::allocator::stats::*;
}
