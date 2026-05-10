//! CPU context saved and restored on voluntary context switches.
//!
//! Only callee-saved registers are stored here.  Caller-saved registers and
//! the full user-mode register file live in the `TrapFrame` / `SyscallFrame`
//! on the kernel stack.
//!
//! ## x86_64 layout  (`Context`, 72 bytes)
//!
//! | Offset | Field    | Notes                          |
//! |--------|----------|--------------------------------|
//! | 0x00   | r15      |                                |
//! | 0x08   | r14      |                                |
//! | 0x10   | r13      |                                |
//! | 0x18   | r12      |                                |
//! | 0x20   | rbp      |                                |
//! | 0x28   | rbx      |                                |
//! | 0x30   | rsp      | kernel stack pointer           |
//! | 0x38   | rip      | return address / next PC       |
//! | 0x40   | fs_base  | TLS base (IA32_FS_BASE MSR)    |
//!
//! ## RISC-V layout  (`Context`, 112 bytes)
//!
//! | Offset | Field | ABI name | Notes                              |
//! |--------|-------|----------|------------------------------------||
//! | 0x00   | ra    | x1       | return address (resume point)      |
//! | 0x08   | sp    | x2       | kernel stack pointer               |
//! | 0x10   | s0    | x8/fp    | callee-saved / frame pointer       |
//! | 0x18   | s1    | x9       |                                    |
//! | 0x20   | s2    | x18      |                                    |
//! | 0x28   | s3    | x19      |                                    |
//! | 0x30   | s4    | x20      |                                    |
//! | 0x38   | s5    | x21      |                                    |
//! | 0x40   | s6    | x22      |                                    |
//! | 0x48   | s7    | x23      |                                    |
//! | 0x50   | s8    | x24      |                                    |
//! | 0x58   | s9    | x25      |                                    |
//! | 0x60   | s10   | x26      |                                    |
//! | 0x68   | s11   | x27      |                                    |
//!
//! `tp` is NOT saved here — `percpu::init` owns it and it never changes
//! after initialisation.  `gp` (x3) is a link-time constant and is also
//! not saved.
//!
//! ## switch / restore API
//!
//! ```ignore
//! // Called from scheduler::schedule() — interrupts disabled by the
//! // trap-handler prologue or the timer ISR.
//! unsafe { context::switch(prev_task, next_task); }
//! unsafe { context::restore(next_task); }  // first-time entry, no prev
//! ```
//!
//! Both functions resolve the `Context` from `task.ctx` inside `Pcb`
//! (accessed via `Task::pcb_ctx_offset()`) and delegate to the
//! arch-specific naked helper.

// ── x86_64 context ────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct Context {
    pub r15:     usize,  // 0x00
    pub r14:     usize,  // 0x08
    pub r13:     usize,  // 0x10
    pub r12:     usize,  // 0x18
    pub rbp:     usize,  // 0x20
    pub rbx:     usize,  // 0x28
    pub rsp:     usize,  // 0x30
    pub rip:     usize,  // 0x38
    /// TLS base stored in IA32_FS_BASE MSR (0xC000_0100).
    pub fs_base: usize,  // 0x40
}

#[cfg(target_arch = "x86_64")]
impl Context {
    pub const fn zero() -> Self {
        Self { r15:0, r14:0, r13:0, r12:0, rbp:0, rbx:0, rsp:0, rip:0, fs_base:0 }
    }
}

// ── RISC-V context ────────────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct Context {
    pub ra:  usize,  // 0x00  — resume address after switch
    pub sp:  usize,  // 0x08  — kernel stack pointer
    pub s0:  usize,  // 0x10  — fp / callee-saved
    pub s1:  usize,  // 0x18
    pub s2:  usize,  // 0x20
    pub s3:  usize,  // 0x28
    pub s4:  usize,  // 0x30
    pub s5:  usize,  // 0x38
    pub s6:  usize,  // 0x40
    pub s7:  usize,  // 0x48
    pub s8:  usize,  // 0x50
    pub s9:  usize,  // 0x58
    pub s10: usize,  // 0x60
    pub s11: usize,  // 0x68
}

#[cfg(target_arch = "riscv64")]
impl Context {
    pub const fn zero() -> Self {
        Self { ra:0, sp:0, s0:0, s1:0, s2:0, s3:0,
               s4:0, s5:0, s6:0, s7:0, s8:0, s9:0, s10:0, s11:0 }
    }
}

// ── x86_64 naked switch ───────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
/// Save the current task into `old` and switch execution to `new`.
///
/// Called with interrupts disabled (IF clear).
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
        // Save FS.base (TLS)
        "mov rcx, 0xC0000100",
        "rdmsr",
        "shl rdx, 32",
        "or  rax, rdx",
        "mov [rdi + 0x40], rax",
        // Restore next
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

// ── RISC-V naked switch ───────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
/// Save current hart's callee-saved registers into `old` and load from `new`.
///
/// On entry:  a0 = *mut Context (old)   a1 = *const Context (new)
/// Execution resumes in `new` at the `ra` saved in `new.ra` — which is
/// always the return address that was live when `switch_riscv` was last
/// called on that task (or `task_entry_trampoline` for a brand-new task).
///
/// `tp` is deliberately NOT touched — percpu::init writes it once and it
/// must remain pointing at the `PercpuBlock` forever.
///
/// # Safety
/// Both pointers must be valid, non-null, 8-byte-aligned `Context`s.
/// Must be called with supervisor interrupts disabled (sstatus.SIE = 0).
#[naked]
pub unsafe extern "C" fn switch_riscv(old: *mut Context, new: *const Context) {
    core::arch::asm!(
        // Save old context
        "sd  ra,  0x00(a0)",
        "sd  sp,  0x08(a0)",
        "sd  s0,  0x10(a0)",
        "sd  s1,  0x18(a0)",
        "sd  s2,  0x20(a0)",
        "sd  s3,  0x28(a0)",
        "sd  s4,  0x30(a0)",
        "sd  s5,  0x38(a0)",
        "sd  s6,  0x40(a0)",
        "sd  s7,  0x48(a0)",
        "sd  s8,  0x50(a0)",
        "sd  s9,  0x58(a0)",
        "sd  s10, 0x60(a0)",
        "sd  s11, 0x68(a0)",
        // Load new context
        "ld  ra,  0x00(a1)",
        "ld  sp,  0x08(a1)",
        "ld  s0,  0x10(a1)",
        "ld  s1,  0x18(a1)",
        "ld  s2,  0x20(a1)",
        "ld  s3,  0x28(a1)",
        "ld  s4,  0x30(a1)",
        "ld  s5,  0x38(a1)",
        "ld  s6,  0x40(a1)",
        "ld  s7,  0x48(a1)",
        "ld  s8,  0x50(a1)",
        "ld  s9,  0x58(a1)",
        "ld  s10, 0x60(a1)",
        "ld  s11, 0x68(a1)",
        // Jump to ra — resuming next task at its saved return address.
        // 'ret' is the canonical way; it does jalr x0, 0(ra).
        "ret",
        options(noreturn)
    );
}

/// First-time entry point for every newly created task on RISC-V.
///
/// When `clone` / `fork` initialises a new `Context`, it sets:
///   `ctx.ra = task_entry_trampoline as usize`
///   `ctx.sp = kstack_top - size_of::<TrapFrame>()`
///   `ctx.s0 = 0`   (clean frame pointer chain)
///
/// `switch_riscv` restores those values, then `ret` jumps here.
/// This function restores the `TrapFrame` at the top of the kernel stack
/// and executes `sret` to enter user mode for the first time.
///
/// The layout matches `riscv_trap_entry`'s save sequence so that
/// `trap_return` can be reused directly.
#[cfg(target_arch = "riscv64")]
#[naked]
pub unsafe extern "C" fn task_entry_trampoline() {
    core::arch::asm!(
        // sp already points at the TrapFrame; call the arch return path.
        "j    trap_return",
        options(noreturn)
    );
}

// ── Arch-independent trampolines ──────────────────────────────────────────────
//
// `scheduler::schedule()` calls these with `*mut Task` so it doesn't need
// to know the Task struct layout.  Both functions resolve `task.pcb.ctx`
// through the Task → Pcb pointer and call the arch naked helper.

use crate::proc::process::Pcb;

/// Switch from `prev` to `next`.  Saves prev's context, restores next's.
///
/// # Safety
/// Both task pointers must be valid.  Interrupts must be disabled.
#[inline]
pub unsafe fn switch(
    prev: *mut crate::proc::task_types::Task,
    next: *mut crate::proc::task_types::Task,
) {
    let prev_ctx = task_ctx_ptr(prev);
    let next_ctx = task_ctx_ptr(next) as *const Context;
    #[cfg(target_arch = "x86_64")]
    switch_to(prev_ctx, next_ctx);
    #[cfg(target_arch = "riscv64")]
    switch_riscv(prev_ctx, next_ctx);
}

/// Restore (first-time enter) `task` without saving any previous context.
///
/// # Safety
/// Task pointer must be valid.  Interrupts must be disabled.
#[inline]
pub unsafe fn restore(task: *mut crate::proc::task_types::Task) {
    // We need a dummy old-context buffer to satisfy switch_riscv's calling
    // convention.  We allocate it on the current stack; it will be
    // immediately abandoned when we jump into the new task.
    let mut dummy = Context::zero();
    let next_ctx = task_ctx_ptr(task) as *const Context;
    #[cfg(target_arch = "x86_64")]
    switch_to(&mut dummy as *mut Context, next_ctx);
    #[cfg(target_arch = "riscv64")]
    switch_riscv(&mut dummy as *mut Context, next_ctx);
}

/// Extract a `*mut Context` from a `*mut Task` by following `task.ctx`.
///
/// `Task` stores the `Pcb` pointer which owns the `ctx` field.  This function
/// is the single place that knows the Task → Pcb → Context path so the
/// scheduler stays decoupled from the exact struct layout.
#[inline]
unsafe fn task_ctx_ptr(task: *mut crate::proc::task_types::Task) -> *mut Context {
    // Task.pcb is a *mut Pcb at offset 0 in Task (see task_types.rs).
    let pcb: *mut Pcb = (*task).pcb;
    &mut (*pcb).ctx as *mut Context
}
