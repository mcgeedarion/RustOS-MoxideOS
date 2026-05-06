//! x86_64 userspace entry via SYSRET.
//!
//! `sysret_to_user()` performs the final transition from ring-0 kernel
//! code into ring-3 user code.  It is called once per exec, after
//! elf64::load() has mapped the ELF segments and write_initial_stack()
//! has built the initial stack frame.
//!
//! ## Register contract on SYSRET (64-bit form)
//!   RCX ← user RIP  (entry point)
//!   R11 ← RFLAGS    (IF=1, IOPL=0, rest cleared)
//!   RSP ← user RSP  (initial stack pointer, argc slot)
//!   All other GPRs  zeroed for a clean ABI start state
//!
//! ## Segment selectors (from GDT / STAR MSR — see gdt.rs)
//!   CS  ← 0x1B  (GDT[3] | RPL3 — 64-bit user code)
//!   SS  ← 0x23  (GDT[4] | RPL3 — user data / stack)
//!
//! ## Safety
//! The caller must ensure:
//!   - CR3 has been loaded with the process page table.
//!   - `user_rsp` points to a mapped, writable user stack page.
//!   - `entry` is a valid mapped user virtual address.
//!   - Interrupts are disabled on entry (sti happens via RFLAGS.IF in R11).
//!   - This function never returns to the caller.

use core::arch::asm;
use crate::mm::pmm;

/// Size of the user stack allocated for init (16 KiB).
const USER_STACK_PAGES: usize = 4;
const PAGE: usize = 4096;

/// Allocate `USER_STACK_PAGES` contiguous physical pages for the user stack,
/// map them into `cr3` at `USER_STACK_TOP - size`, and return the user-space
/// virtual address of the stack top.
///
/// Stack virtual address range: [USER_STACK_TOP - size, USER_STACK_TOP)
pub fn alloc_user_stack(cr3: usize) -> Option<usize> {
    use crate::arch::x86_64::paging;

    // Place user stack just below the 128 TiB user space ceiling.
    const USER_STACK_TOP: usize = 0x0000_7FFF_FFFF_F000;
    let size = USER_STACK_PAGES * PAGE;
    let stack_virt_base = USER_STACK_TOP - size;

    for i in 0..USER_STACK_PAGES {
        let pa = pmm::alloc_page()?;
        // Zero the page.
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE); }
        let va = stack_virt_base + i * PAGE;
        let flags = paging::PTE_PRESENT | paging::PTE_WRITABLE
                  | paging::PTE_USER    | paging::PTE_NX;
        unsafe { paging::map_page(cr3, va, pa, flags); }
    }

    // Stack top = highest mapped VA (stacks grow down).
    Some(USER_STACK_TOP)
}

/// Switch to user mode via SYSRET.
///
/// Loads `cr3`, sets RSP to `user_rsp`, RCX to `entry`, R11 to RFLAGS
/// (IF=1), then executes `sysretq`.  Never returns.
///
/// # Safety
/// All preconditions listed in the module doc must hold.
#[inline(never)]
pub unsafe fn sysret_to_user(cr3: usize, entry: usize, user_rsp: usize) -> ! {
    asm!(
        // Load the process page table.
        "mov cr3, {cr3}",

        // Zero all GPRs that musl/libc may inspect on startup
        // (prevents leaking kernel pointers into userspace).
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rdx, rdx",
        "xor rdi, rdi",
        "xor rsi, rsi",
        "xor r8,  r8",
        "xor r9,  r9",
        "xor r10, r10",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",
        "xor rbp, rbp",

        // RFLAGS for user: IF=1 (enable interrupts), everything else 0.
        "mov r11, 0x200",

        // RCX = user RIP, RSP = user stack.
        "mov rcx, {entry}",
        "mov rsp, {rsp}",

        // sysretq: CS←0x1B, SS←0x23, CPL←3, RIP←RCX, RFLAGS←R11.
        "sysretq",

        cr3   = in(reg) cr3,
        entry = in(reg) entry,
        rsp   = in(reg) user_rsp,
        options(noreturn),
    );
}
