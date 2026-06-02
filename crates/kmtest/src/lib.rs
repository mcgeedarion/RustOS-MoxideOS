//! RustOS kernel test harness.
//!
//! # Usage
//!
//! ```rust,ignore
//! use kmtest::{km_assert, km_assert_eq, KmTestResult};
//! use kmtest_macros::kernel_test;
//!
//! #[kernel_test]
//! fn test_basic_arithmetic() -> KmTestResult {
//!     km_assert_eq!(2 + 2, 4);
//!     Ok(())
//! }
//! ```
//!
//! Then somewhere during kernel init (behind `#[cfg(feature = "kmtest")]`):
//!
//! ```rust,ignore
//! let summary = kmtest::run_all();
//! log::info!("kmtest: {}", summary);
//! ```

#![no_std]

// Re-export the proc-macro so callers only need `kmtest` in Cargo.toml.
pub use kmtest_macros::kernel_test;

/// A short, static description of a test failure.
pub type KmTestError = &'static str;

/// Return type every kernel test function must use.
///
/// `Ok(())` — test passed.  
/// `Err(msg)` — test failed; `msg` is a static string shown in the summary.
pub type KmTestResult = Result<(), KmTestError>;

/// One entry in the test registry, stored in `.kmtest_registry`.
///
/// The `#[kernel_test]` macro emits one of these per annotated function.
/// Do not construct manually.
#[repr(C)]
pub struct KmTestEntry {
    /// Human-readable name (the function's identifier as a string literal).
    pub name: &'static str,
    /// Pointer to the test function.
    pub run: fn() -> KmTestResult,
}

// SAFETY: KmTestEntry only holds &'static str + fn pointer — both Send+Sync.
unsafe impl Sync for KmTestEntry {}

// The linker script must place `.kmtest_registry` between the two symbols
// below. The extern symbols are declared below; `run_all` derives a slice
// from them.

extern "C" {
    static __kmtest_start: KmTestEntry;
    static __kmtest_end: KmTestEntry;
}

/// Return a slice over every registered `KmTestEntry`.
///
/// # Safety
/// Caller must ensure the linker has placed `__kmtest_start` / `__kmtest_end`
/// correctly (i.e., the linker script includes the `.kmtest_registry` section).
unsafe fn registry() -> &'static [KmTestEntry] {
    let start = core::ptr::addr_of!(__kmtest_start);
    let end   = core::ptr::addr_of!(__kmtest_end);
    let len   = (end as usize - start as usize) / core::mem::size_of::<KmTestEntry>();
    core::slice::from_raw_parts(start, len)
}

/// Aggregate result returned by `run_all()`.
#[derive(Copy, Clone)]
pub struct KmTestSummary {
    pub total:  usize,
    pub passed: usize,
    pub failed: usize,
}

impl KmTestSummary {
    /// Returns `true` if every test passed.
    #[inline]
    pub fn all_passed(self) -> bool {
        self.failed == 0
    }
}

// Manual Display-like formatting without std.
impl core::fmt::Display for KmTestSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "kmtest: {}/{} passed, {} failed",
            self.passed, self.total, self.failed
        )
    }
}

/// Run every registered kernel test and return a summary.
///
/// Results for individual tests are emitted via the `report` callback so the
/// caller decides how to surface them (serial, in-memory buffer, etc.).
///
/// ```rust,ignore
/// let summary = kmtest::run_all(|name, result| {
///     match result {
///         Ok(())   => serial_println!("  PASS  {}", name),
///         Err(msg) => serial_println!("  FAIL  {} — {}", name, msg),
///     }
/// });
/// if !summary.all_passed() {
///     panic!("kernel self-tests failed");
/// }
/// ```
pub fn run_all(mut report: impl FnMut(&'static str, KmTestResult)) -> KmTestSummary {
    // SAFETY: relies on correct linker script placement; see `registry()` docs.
    let tests = unsafe { registry() };

    let mut summary = KmTestSummary { total: tests.len(), passed: 0, failed: 0 };

    for entry in tests {
        let result = (entry.run)();
        match &result {
            Ok(())   => summary.passed += 1,
            Err(_)   => summary.failed += 1,
        }
        report(entry.name, result);
    }

    summary
}
