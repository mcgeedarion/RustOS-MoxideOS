//! CPU context saved and restored on voluntary context switches.
//!
//! Only callee-saved registers + RSP + RIP + FS.base are stored.
//! Caller-saved registers live in the SyscallFrame on the kernel stack.

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
    /// Set by CLONE_SETTLS / set_thread_area; saved/restored on every switch.
    pub fs_base: usize,  // offset 0x40
}

impl Context {
    pub const fn zero() -> Self {
        Self { r15:0, r14:0, r13:0, r12:0, rbp:0, rbx:0, rsp:0, rip:0, fs_base:0 }
    }
}

/// Save the current task into `old` and switch execution to `new`.
///
/// Called with the scheduler lock held. `switch_to` does not return
/// to the caller directly; it returns to `old.rip` the next time
/// the old task is scheduled.
///
/// # Safety
/// Both pointers must be valid, non-null, 8-byte-aligned `Context`s.
#[naked]
pub unsafe extern "C" fn switch_to(old: *mut Context, new: *const Context) {
    // rdi = old, rsi = new
    core::arch::asm!(
        // Save callee-saved registers of the outgoing task
        "mov [rdi + 0x00], r15",
        "mov [rdi + 0x08], r14",
        "mov [rdi + 0x10], r13",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], rbp",
        "mov [rdi + 0x28], rbx",
        "mov [rdi + 0x30], rsp",
        // RIP: read the return address that `call switch_to` pushed
        "mov rax, [rsp]",
        "mov [rdi + 0x38], rax",
        // FS.base: RDMSR(IA32_FS_BASE = 0xC000_0100)
        "mov rcx, 0xC0000100",
        "rdmsr",
        "shl rdx, 32",
        "or  rax, rdx",
        "mov [rdi + 0x40], rax",
        // Restore incoming task
        "mov r15, [rsi + 0x00]",
        "mov r14, [rsi + 0x08]",
        "mov r13, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov rbp, [rsi + 0x20]",
        "mov rbx, [rsi + 0x28]",
        "mov rsp, [rsi + 0x30]",
        // FS.base: WRMSR(IA32_FS_BASE)
        "mov rax, [rsi + 0x40]",
        "mov rdx, rax",
        "shr rdx, 32",
        "mov rcx, 0xC0000100",
        "wrmsr",
        // Jump (not call) to new RIP to avoid a duplicate return address
        "jmp qword ptr [rsi + 0x38]",
        options(noreturn)
    );
}
