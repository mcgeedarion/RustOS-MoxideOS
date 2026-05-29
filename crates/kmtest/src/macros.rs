//! Assertion macros for kernel tests.
//!
//! These are thin wrappers that return `Err(&'static str)` on failure instead
//! of panicking, keeping the test runner alive even when a case fails.

/// Assert a boolean condition inside a kernel test.
///
/// Returns `Err("assertion failed: <expr>")` on failure.
///
/// # Example
/// ```rust,ignore
/// km_assert!(ptr != core::ptr::null_mut());
/// ```
#[macro_export]
macro_rules! km_assert {
    ($cond:expr) => {{
        if !$cond {
            return Err(concat!("assertion failed: ", stringify!($cond)));
        }
    }};
}

/// Assert equality inside a kernel test.
///
/// Returns `Err("assertion failed: left == right")` on failure.
/// Does *not* print the actual values (no alloc / format).
///
/// # Example
/// ```rust,ignore
/// km_assert_eq!(page_size(), 4096);
/// ```
#[macro_export]
macro_rules! km_assert_eq {
    ($left:expr, $right:expr) => {{
        if $left != $right {
            return Err(concat!(
                "assertion failed: ",
                stringify!($left),
                " == ",
                stringify!($right),
            ));
        }
    }};
}

/// Assert inequality inside a kernel test.
#[macro_export]
macro_rules! km_assert_ne {
    ($left:expr, $right:expr) => {{
        if $left == $right {
            return Err(concat!(
                "assertion failed: ",
                stringify!($left),
                " != ",
                stringify!($right),
            ));
        }
    }};
}
