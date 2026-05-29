//! Kernel test suites.
//!
//! Add a new suite by creating a submodule here and wiring it below.
//! Each submodule annotates its test functions with `#[kernel_test]`.
//!
//! Suites are only compiled when the `kmtest` feature is active:
//!   cargo build --features kmtest --target x86_64-unknown-none

pub mod smoke;
