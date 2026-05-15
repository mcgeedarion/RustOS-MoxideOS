//! Allocator diagnostics.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocatorStats {
    pub capacity: usize,
    pub used: usize,
}
