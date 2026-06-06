// MM allocator surface.
//
// Historically this re-exported a `crate::allocator::*` tree that has
// since been folded into `crate::mm::heap`. The re-exports below keep
// the legacy submodule paths (`mm::allocator::{buddy,fixed_size_block,stats}`)
// addressable; downstream callers should migrate to `crate::mm::heap`.

pub use crate::mm::heap::*;

pub mod buddy {
    // GUESS: empty placeholder. Real buddy allocator lives in mm::heap;
    // re-add concrete re-exports here once that module exposes a
    // `buddy::*` submodule.
}

pub mod fixed_size_block {
    // GUESS: empty placeholder; see `buddy`.
}

pub mod stats {
    // GUESS: empty placeholder; see `buddy`.
}
