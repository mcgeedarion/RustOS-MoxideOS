//! Kernel console (writes to serial + VGA if available).
extern crate alloc;
use alloc::string::String;

pub fn print(s: &str) {
    #[cfg(target_arch="x86_64")]
    for b in s.bytes() { crate::arch::x86_64::serial::write_byte(b); }
}

#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        use alloc::format;
        crate::console::console::print(&format!($($arg)*));
        crate::console::console::print("\n");
    }}
}
