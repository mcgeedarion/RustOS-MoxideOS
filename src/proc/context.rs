//! CPU context saved and restored on voluntary context switches.
//!
//! Only callee-saved registers + RSP + RIP + FS.base are stored here.
//! Caller-saved registers live in the SyscallFrame on the kernel stack.
//!
//! NOTE: This struct and switch_to() are x86-64 specific.
//! On RISC-V the equivalent lives in arch/riscv64/hal.rs
//! (ContextSwitch::switch_to), and proc/context.rs would be replaced
//! by a thin newtype wrapper around TrapFrame.  For now this file
//! serves x86-64 only; RISC-V support is a follow-up.

/// Kernel-side saved context for a sleeping task.
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct Context {
    pub r15:     usize,  // offset 0x00
    pub r14:     usize,  // offset 0x08
    pub r13:     usize,  // offset 0x10
    pub r12:     usize,  // offset 0x18
    pub rbp:     usize,  // offset 0x20
    pub rbx:     usize,  // offset 0x28
    pub rsp:     usize,  // offset 0x30
    pub rip:     usize,  // offset 0x38
    /// FS segment base for TLS (IA32_FS_BASE MSR = 0xC000_0100).
    pub fs_base: usize,  // offset 0x40
}

impl Context {
    pub const fn zero() -> Self {
        Self { r15:0, r14:0, r13:0, r12:0, rbp:0, rbx:0, rsp:0, rip:0, fs_base:0 }
    }
}

/// Save the current task into `old` and switch execution to `new`.
///
/// Called with the scheduler lock held.
///
/// # Safety
/// Both pointers must be valid, non-null, 8-byte-aligned `Context`s.
#[naked]
pub unsafe extern "C" fn switch_to(old: *mut Context, new: *const Context) {
    core::arch::asm!(
        "mov [rdi + 0x00], r15",
        "mov [rdi + 0x08], r14",
        "mov [rdi + 0x10], r13",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], rbp",
        "mov [rdi + 0x28], rbx",
        "mov [rdi + 0x30], rsp",
        "mov rax, [rsp]",
        "mov [rdi + 0x38], rax",
        "mov rcx, 0xC0000100",
        "rdmsr",
        "shl rdx, 32",
        "or  rax, rdx",
        "mov [rdi + 0x40], rax",
        "mov r15, [rsi + 0x00]",
        "mov r14, [rsi + 0x08]",
        "mov r13, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov rbp, [rsi + 0x20]",
        "mov rbx, [rsi + 0x28]",
        "mov rsp, [rsi + 0x30]",
        "mov rax, [rsi + 0x40]",
        "mov rdx, rax",
        "shr rdx, 32",
        "mov rcx, 0xC0000100",
        "wrmsr",
        "jmp qword ptr [rsi + 0x38]",
        options(noreturn)
    );
}
