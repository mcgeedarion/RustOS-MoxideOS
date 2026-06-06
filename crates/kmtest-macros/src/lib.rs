//! Proc-macro crate for the RustOS kernel test harness.
//!
//! Exposes a single attribute macro:
//!
//! ```rust,ignore
//! #[kernel_test]
//! fn test_something() -> kmtest::KmTestResult {
//!     km_assert_eq!(1 + 1, 2);
//!     Ok(())
//! }
//! ```
//!
//! The macro wraps the function and appends a linker-section entry so that
//! `kmtest::run_all()` can discover it at runtime without any explicit
//! registration.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Ident, ItemFn};

/// Mark a function as a kernel test.
///
/// The annotated function must have the signature `fn() ->
/// kmtest::KmTestResult`. The macro generates a companion `static` placed in
/// the `.kmtest_registry` linker section; `kmtest::run_all()` iterates that
/// section at runtime.
#[proc_macro_attribute]
pub fn kernel_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let fn_name = &input.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Unique static name derived from the function identifier.
    let static_name = Ident::new(
        &format!("__KMTEST_{}", fn_name_str.to_uppercase()),
        Span::call_site(),
    );

    let expanded = quote! {
        // Keep the original function unchanged.
        #input

        // Emit a KmTestEntry into the dedicated linker section.
        // `used` + `link_section` mirrors how Rust's own `#[test]` works
        // via the test harness, but without requiring the std test runner.
        #[used]
        #[link_section = ".kmtest_registry"]
        static #static_name: ::kmtest::KmTestEntry = ::kmtest::KmTestEntry {
            name: #fn_name_str,
            run:  #fn_name,
        };
    };

    TokenStream::from(expanded)
}
