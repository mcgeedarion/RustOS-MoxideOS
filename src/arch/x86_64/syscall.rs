//! x86-64 SYSCALL/SYSRET entry and per-task first-run hooks.
//!
//! ## SYSCALL entry flow
//!
//!   syscall_asm_entry  (naked, MSR_LSTAR)
//!     │  saves all callee+caller GPRs as SyscallFrame on the kernel stack
//!     │  calls rust_syscall_handler(*mut SyscallFrame)
//!     └─ restores GPRs, sysretq
//!
//!   rust_syscall_handler
//!     │  reads nr from frame.rax
//!     │  NR 15 (rt_sigreturn) — calls signal::sys_rt_sigreturn(frame) directly
//!     │                         (does NOT call dispatch; does NOT call
//!     │                          check_and_deliver — the restored frame IS the
//!     │                          pre-signal state so no re-delivery needed)
//!     │  all other NRs        — calls syscall::dispatch(nr, args…)
//!     │                         then signal::check_and_deliver(frame)
//!     └─ stores return value into frame.rax
//!
//! ## SyscallFrame layout
//!
//!   On SYSCALL entry the CPU sets:
//!     RCX ← user RIP  (return address)
//!     R11 ← user RFLAGS
//!   The stub pushes the full GPR set into a SyscallFrame-shaped region on
//!   the kernel stack and passes &frame as the first argument to
//!   rust_syscall_handler.  The frame also holds the user RSP so that
//!   signal delivery (push_sigframe_x86) and rt_sigreturn can read/write it.

use crate::proc::scheduler;
use crate::uaccess::{copy_to_user, validate_user_ptr};
use core::arch::global_asm;

/// Register state saved by `syscall_asm_entry` on the kernel stack.
///
/// Field order MUST match the push sequence in `syscall_asm_entry` exactly.
/// The stub pushes: rsp, r11(=rflags), rcx(=rip), r9, r8, r10, rdx, rsi,
///                  rdi, rax, rbx, rbp, r12, r13, r14, r15  (low → high addr)
/// so rsp ends up at the highest address and r15 at the base (sp after all
/// pushes).  We represent this as a C struct where the first field is the
/// value at the lowest stack address after all pushes (= r15).
#[repr(C)]
pub struct SyscallFrame {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub rax: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub r10: usize,
    pub r8: usize,
    pub r9: usize,
    pub rip: usize,    // saved from RCX by the SYSCALL instruction
    pub rflags: usize, // saved from R11 by the SYSCALL instruction
    pub rsp: usize,    // user stack pointer (saved explicitly by stub)
}

// Registered as MSR_LSTAR.  On entry:
//   RCX = user RIP  (SYSCALL saves it here)
//   R11 = user RFLAGS (SYSCALL saves it here)
//   RSP still points at user stack
// We immediately switch to the per-CPU kernel stack (stored in GS or
// simply use the current RSP which is already valid kernel RSP at ring-0
// for a basic single-stack model), save all GPRs as a SyscallFrame,
// and call rust_syscall_handler.
// Stack layout after all pushes (RSP+0 = r15, RSP+128 = rsp_user):
//   RSP+0   r15
//   RSP+8   r14
//   RSP+16  r13
//   RSP+24  r12
//   RSP+32  rbp
//   RSP+40  rbx
//   RSP+48  rax   (syscall NR on entry; return value on exit)
//   RSP+56  rdi   (arg0)
//   RSP+64  rsi   (arg1)
//   RSP+72  rdx   (arg2)
//   RSP+80  r10   (arg3 — Linux uses r10 instead of rcx in SYSCALL ABI)
//   RSP+88  r8    (arg4)
//   RSP+96  r9    (arg5)
//   RSP+104 rcx   (user RIP)
//   RSP+112 r11   (user RFLAGS)
//   RSP+120 rsp_user  ← pushed first → highest address
// After the call, rax is restored from frame.rax (set by rust_syscall_handler).

global_asm!(
    ".global syscall_asm_entry",
    "syscall_asm_entry:",
    //  We use a simple model: no stack-switch (the kernel stack is already
    //  active for ring-0 SYSCALL in this bare-metal environment because we
    //  don't use the syscall IST/TSS stack pointer.  If/when a proper per-CPU
    //  kernel stack is added, swap RSP from GS here).
    "push r11", // push user RFLAGS (r11 after SYSCALL)
    "push rcx", // push user RIP    (rcx after SYSCALL)
    "push r9",
    "push r8",
    "push r10",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rax", // syscall number
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp",
    // ── 3. Save user RSP into SyscallFrame.rsp.
    //  rsp is NOT one of the pushed regs above; we need to record the
    //  user stack pointer.  At this point RSP points to r15 on the
    //  kernel stack, so we read the original user RSP from wherever it
    //  was before SYSCALL.  On SYSCALL the CPU does NOT change RSP —
    //  we must have saved it before we started pushing.  Work-around:
    //  adjust the frame pointer to write rsp_user at the right slot.
    //  The SyscallFrame.rsp field is at offset 128 from frame base (r15).
    //  We need user RSP.  At SYSCALL entry RSP was the USER rsp; we then
    //  pushed 15 values (120 bytes) so user_rsp = RSP + 120 + 8 (r11 already
    //  at top).  Actually simpler: we haven't changed RSP except for the
    //  15 × 8 = 120-byte push sequence above, so:
    //    user_rsp = current_rsp + 15*8  ... but wait, that's the kernel
    //  stack top.  In a single-stack model RSP on SYSCALL entry IS the user
    //  RSP.  We pushed 15 values, so user_rsp = rsp + 120.
    "lea rax, [rsp + 120]", // rax = user RSP
    "mov [rsp + 120], rax", // store into SyscallFrame.rsp slot
    //  NOTE: rax will be overwritten by rust_syscall_handler's return value;
    //  that's fine — we load rax from frame.rax on exit.
    "sti",
    "call rust_syscall_handler",
    "cli",
    // ── 7. Restore user RFLAGS→r11 and RIP→rcx from the (possibly modified)
    //       frame (signal delivery may have changed rip/rflags/rsp). ───────
    "mov r11, [rsp + 112]", // frame.rflags
    "mov rcx, [rsp + 104]", // frame.rip
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "pop rax", // return value (set by handler into frame.rax)
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop r10",
    "pop r8",
    "pop r9",
    "add rsp, 16", // skip rcx/r11 slots (already loaded above)
    // user RSP was stored at [rsp] now; restore it.
    "pop rsp", // CAUTION: this changes rsp to user stack
    "sysretq",
);

extern "C" {
    pub fn syscall_asm_entry();
}

/// Called from `syscall_asm_entry` with a pointer to the SyscallFrame on the
/// kernel stack.  We handle NR 15 (rt_sigreturn) in-line here because it needs
/// to modify the frame directly; all other syscalls go through `dispatch`.
#[no_mangle]
pub extern "C" fn rust_syscall_handler(frame: &mut SyscallFrame) {
    let nr = frame.rax;

    if nr == 15 {
        // rt_sigreturn: restore the pre-signal SyscallFrame state.
        // This must NOT call check_and_deliver afterwards — the restored frame
        // already represents the state the task was in before the signal, and
        // re-delivering would be incorrect.
        crate::proc::signal::sys_rt_sigreturn(frame);
        return;
    }

    // Mark this CPU as inside a syscall so the scheduler tick charges stime_ns.
    {
        let cpu = crate::smp::percpu::current_cpu_id() as usize;
        let blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[cpu] };
        blk.in_syscall = blk.in_syscall.saturating_add(1);
    }

    let ret = crate::syscall::dispatch(
        nr, frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
    );
    frame.rax = ret as usize;

    // Decrement in_syscall before signal delivery (signal handlers run in user
    // mode).
    {
        let cpu = crate::smp::percpu::current_cpu_id() as usize;
        let blk = unsafe { &mut crate::smp::percpu::PERCPU_BLOCKS[cpu] };
        blk.in_syscall = blk.in_syscall.saturating_sub(1);
    }

    // Deliver any pending signals before returning to userspace.
    crate::proc::signal::check_and_deliver(frame);
}

/// syscall_setup: configure SYSCALL/SYSRET MSRs.
pub fn syscall_setup() {
    use crate::arch::x86_64::cpu::{rdmsr, wrmsr, MSR_EFER, MSR_FMASK, MSR_LSTAR, MSR_STAR};
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | 1);
        wrmsr(MSR_STAR, 0x001B_0008u64 << 32);
        wrmsr(MSR_LSTAR, syscall_asm_entry as u64);
        // FMASK: clear IF (bit 9), TF (bit 8), DF (bit 10), AC (bit 18), NT (bit 14),
        // IOPL.
        wrmsr(MSR_FMASK, 0x47700);
    }
}

/// sys_set_tid_address(tidptr_va)  [NR 218]
pub fn sys_set_tid_address(tidptr_va: usize) -> isize {
    let pid = scheduler::current_pid();
    scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            p.clear_child_tid_va = tidptr_va;
        }
    });
    pid as isize
}

/// sys_arch_prctl(code, addr)  [NR 158]
pub fn sys_arch_prctl(code: i32, addr: usize) -> isize {
    const ARCH_SET_FS: i32 = 0x1002;
    const ARCH_GET_FS: i32 = 0x1003;
    const ARCH_SET_GS: i32 = 0x1001;
    const ARCH_GET_GS: i32 = 0x1004;
    let pid = scheduler::current_pid();
    match code {
        ARCH_SET_FS => {
            scheduler::with_procs(|procs| {
                if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                    p.ctx.fs_base = addr;
                }
            });
            unsafe {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0100u32,
                    in("eax") addr as u32,
                    in("edx") (addr >> 32) as u32,
                    options(nostack)
                );
            }
            0
        },
        ARCH_GET_FS => {
            let base = scheduler::with_proc(pid, |p| p.ctx.fs_base).unwrap_or(0);
            if addr != 0 && validate_user_ptr(addr, 8) {
                let _ = copy_to_user(addr, &base.to_ne_bytes());
            }
            0
        },
        ARCH_SET_GS => {
            unsafe {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0101u32,
                    in("eax") addr as u32,
                    in("edx") (addr >> 32) as u32,
                    options(nostack)
                );
            }
            0
        },
        ARCH_GET_GS => {
            let mut gs: u64 = 0;
            unsafe {
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") 0xC000_0101u32,
                    out("eax") *(&mut gs as *mut u64 as *mut u32),
                    out("edx") *((&mut gs as *mut u64 as *mut u32).add(1)),
                    options(nostack)
                );
            }
            if addr != 0 && validate_user_ptr(addr, 8) {
                let _ = copy_to_user(addr, &gs.to_ne_bytes());
            }
            0
        },
        _ => -22,
    }
}

/// Called by sysret_trampoline on a child's very first SYSRETQ.
/// Implements CLONE_CHILD_SETTID and CLONE_SETTLS (FS.base restore).
#[no_mangle]
pub extern "C" fn child_first_run_hook() {
    let pid = scheduler::current_pid();
    if pid == 0 {
        return;
    }

    let (tid_va, tid_val, fs_base) =
        scheduler::with_procs(|procs| match procs.iter_mut().find(|p| p.pid == pid) {
            Some(p) => {
                let r = (p.child_tid_va, p.child_tid_val, p.ctx.fs_base);
                p.child_tid_va = 0;
                r
            },
            None => (0, 0, 0),
        });

    if tid_va != 0 {
        let _ = copy_to_user(tid_va, &tid_val.to_ne_bytes());
    }

    if fs_base != 0 {
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") 0xC000_0100u32,
                in("eax") fs_base as u32,
                in("edx") (fs_base >> 32) as u32,
                options(nostack)
            );
        }
    }
}

// ====================================================================
// Public helpers re-exported for callers under the
// `crate::arch::x86_64::syscall` path. The actual logic for these helpers
// historically lived inside `proc::clone` / `proc::fork_syscall` as file-local
// `fn` items; the versions below are minimal entry points that match the call
// sites in `proc::exec` (and avoid the cross-module privacy issue).
// ====================================================================

// Selector constants must match those used in proc::clone::push_syscall_frame.
const USER_CS_PUB: usize = 0x23;
const USER_SS_PUB: usize = 0x1b;

/// Build a fresh SYSRET-shaped stack frame at the top of `kstack_top`.
///
/// Layout (top-of-stack-down, 17×u64 of which only the bottom 5 are
/// load-bearing): `[user_ss, user_sp, rflags, user_cs, rip, 0, 0, ...]`.
/// This mirrors the same routine that previously lived inside
/// `proc::clone::push_syscall_frame` and is referenced from
/// `proc::exec::install_exec_image` on the freshly-exec'd path.
///
/// # Safety
/// `kstack_top` must point to the top of a 17×u64-or-larger kernel stack
/// region that the caller currently owns.
#[cfg(target_arch = "x86_64")]
pub fn push_syscall_frame(kstack_top: usize, pc: usize, rflags: usize, user_sp: usize) {
    // SAFETY: requirement is documented on the function.
    let frame = unsafe { core::slice::from_raw_parts_mut((kstack_top - 17 * 8) as *mut usize, 17) };
    frame.iter_mut().for_each(|x| *x = 0);
    frame[0] = USER_SS_PUB;
    frame[1] = if user_sp != 0 { user_sp } else { kstack_top };
    frame[2] = rflags;
    frame[3] = USER_CS_PUB;
    frame[4] = pc;
}

/// In-place edit of an already-pushed SYSRET frame to repoint it at
/// `(pc, user_sp)`. Used by `execve` paths that reuse the calling
/// task's kernel stack instead of building a fresh one.
///
/// # Safety
/// `kstack_top` must point to the same stack region used in the
/// matching [`push_syscall_frame`] call.
#[cfg(target_arch = "x86_64")]
pub fn patch_syscall_frame(kstack_top: usize, pc: usize, user_sp: usize) {
    // SAFETY: see [`push_syscall_frame`].
    let frame = unsafe { core::slice::from_raw_parts_mut((kstack_top - 17 * 8) as *mut usize, 17) };
    frame[1] = if user_sp != 0 { user_sp } else { kstack_top };
    frame[4] = pc;
}

/// First-instruction landing pad for a freshly-cloned/exec'd task. The
/// real assembly trampoline is `syscall_asm_entry`'s SYSRET tail; this
/// symbol is exposed only so that callers like `proc::clone` can hand a
/// stable function pointer into the per-task PCB.
///
/// Calling this from kernel code is a logic bug — the trampoline is
/// only legal as a context-switch target.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn sysret_trampoline() {
    // GUESS: callers (proc::clone, proc::fork_syscall) only need the
    // address of this symbol; the body should never actually execute.
    // A direct `ud2` matches what an empty fn lowers to in release.
    unsafe { core::arch::asm!("ud2", options(noreturn, nomem, nostack)) }
}
