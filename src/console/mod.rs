//! Console subsystem — printk-style output to serial (and optionally VGA).
//!
//! ## Usage
//!
//! ```rust
//! use crate::console;
//! console::print("hello\n");
//! console::println("world");
//! crate::kprintln!("formatted {}", 42);
//! ```
//!
//! ## Backends
//!
//! | Architecture | Backend                           |
//! |--------------|-----------------------------------|
//! | x86\_64      | `arch::x86_64::serial` (UART 16550)|
//! | riscv64      | SBI console putchar extension     |

pub mod console;

pub use console::{print, print_fmt, println};

/// Kernel print macro — works like `print!` in std.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        $crate::console::print_fmt(format_args!($($arg)*));
    }};
}

/// Kernel println macro.
#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($fmt:expr) => ($crate::kprint!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::kprint!(concat!($fmt, "\n"), $($arg)*));
}
