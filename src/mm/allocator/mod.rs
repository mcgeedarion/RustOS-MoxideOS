//! MM allocator compatibility surface.
//!
//! The concrete allocator implementation lives in `crate::mm::heap`.  These
//! re-exports keep the legacy submodule paths addressable while downstream code
//! migrates to `crate::mm::heap` directly.

pub use crate::mm::heap::*;

pub mod buddy {
    pub use crate::mm::heap::*;
}

pub mod fixed_size_block {
    pub use crate::mm::heap::*;
}

pub mod stats {
    pub use crate::mm::heap::*;
}