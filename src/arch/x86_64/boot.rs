//! x86_64 bootstrap assembly shim.

core::arch::global_asm!(include_str!("boot.s"));
