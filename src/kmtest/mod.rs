//! Kernel test suites — compiled only when `feature = "kmtest"`.
//!
//! Each sub-module exposes a `pub fn register()` that calls
//! `kmtest::register!(name, fn)` for every test it owns.  The top-level
//! `init()` function here calls all of them in order; it is invoked once
//! from `kernel_main` before the scheduler starts.
//!
//! ## Adding a new suite
//! 1. Create `src/kmtest/<suite>.rs`.
//! 2. Add `pub mod <suite>;` below.
//! 3. Call `<suite>::register()` inside `init()`.

pub mod mm;
pub mod proc;
pub mod fs;
pub mod sync;
pub mod ipc;

/// Register all suites with the kmtest harness.
/// Called once from kernel_main when `feature = "kmtest"` is active.
pub fn init() {
    mm::register();
    proc::register();
    fs::register();
    sync::register();
    ipc::register();
}
