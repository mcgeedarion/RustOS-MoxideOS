//! Binary buddy allocator.
//!
//! ## Design
//!
//! Memory is divided into *buddy pairs*: a block at order `n` is exactly
//! `PAGE_SIZE << n` bytes, naturally aligned to that size.  When a block
//! is freed the allocator looks up its buddy address with a simple XOR;
//! if the buddy is also free the two are coalesced into an order-`n+1`
//! block, and the process recurses upward to `MAX_ORDER`.
