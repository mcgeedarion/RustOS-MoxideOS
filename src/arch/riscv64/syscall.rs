//! RISC-V supervisor-mode syscall notes.
//!
//! The actual trap entry stub lives in `trap.rs` as `riscv_trap_entry`.
//! Syscalls arrive through the ecall (environment call) exception (scause = 8)
//! and are dispatched by `handle_exception` in `trap.rs`.
//!
//! RISC-V Linux syscall ABI:
//!   a7 = NR,  a0–a5 = args,  a0 = return value.
//!   sepc is advanced by 4 (ecall instruction size) before returning.
