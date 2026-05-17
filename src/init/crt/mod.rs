//! C runtime stubs for the RustOS kernel.
//!
//! The C source files live at `src/init/crt/` and are compiled into a static
//! archive by `build.rs` (the `compile_crt` function).  The resulting object
//! code is linked into the kernel binary automatically via
//! `cargo:rustc-link-lib=static=rustos_crt`.
//!
//! ## Files
//!
//! | File             | Purpose                                                  |
//! |------------------|----------------------------------------------------------|
//! | `crt0.c`         | Stack-protector + C++ ABI stubs (`__stack_chk_fail`,     |
//! |                  | `__cxa_atexit`, `__cxa_pure_virtual`, `run_init_array`). |
//! | `compiler_rt.c`  | Fortified mem-intrinsic wrappers (`__memcpy_chk`, etc.). |
//! | `memcpy.c`       | Byte-loop `memcpy` (no libc dependency).                 |
//! | `memmove.c`      | Overlap-safe `memmove`.                                  |
//! | `memset.c`       | Byte-loop `memset`.                                      |
