//! x86_64 application-processor boot shim.

core::arch::global_asm!(include_str!("ap_boot.s"));
