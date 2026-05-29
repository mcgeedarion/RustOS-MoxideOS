//! Smoke tests: trivially simple cases that verify the harness itself works.
//! If these fail something is wrong with the test infrastructure, not the kernel.

use crate::{km_assert, km_assert_eq, km_assert_ne, KmTestResult};
use kmtest_macros::kernel_test;

#[kernel_test]
fn smoke_assert_true() -> KmTestResult {
    km_assert!(true);
    Ok(())
}

#[kernel_test]
fn smoke_assert_eq() -> KmTestResult {
    km_assert_eq!(1 + 1, 2);
    Ok(())
}

#[kernel_test]
fn smoke_assert_ne() -> KmTestResult {
    km_assert_ne!(1, 2);
    Ok(())
}

/// Verify KmTestSummary arithmetic.
#[kernel_test]
fn smoke_summary_fields() -> KmTestResult {
    let s = crate::KmTestSummary { total: 3, passed: 3, failed: 0 };
    km_assert!(s.all_passed());
    km_assert_eq!(s.total, 3);
    Ok(())
}
