//! execve implementation.
//!
//! ## do_execve flow
//!
//!   1.  vfs::open(path) → fd; read entire file → Vec<u8>; vfs::close
//!   2.  elf::parse_elf_header + elf::parse_phdrs_with_hdr
//!   3.  alloc fresh address space (new_cr3) — old space untouched until step 8
//!   4.  elf::load_elf_into(new_cr3, data, &hdr, &phdrs) → entry VA
//!   5.  elf::end_of_bss(phdrs, bias) → set_brk_base_compute
//!   6.  If PT_INTERP present: load_interpreter → interp_entry
//!   7.  Alloc user stack pages into new_cr3
//!   8.  clear_vmas / free_old_address_space / load_cr3(new_cr3)
//!   9.  build_initial_stack → initial_rsp
//!  10.  PCB update: user_satp/pc/sp/signal_handlers/vfork_parent/exe_path
//!       signal_handlers: SIG_IGN dispositions survive; user VAs reset to SIG_DFL.
//!       pending signals and sigmask are cleared (they don't survive exec).
//!  11.  wake_pid(vfork_parent) if set
//!  12.  Patch SyscallFrame (x86_64) OR rebuild TrapFrame on kstack (riscv64)
//!
//! ## TaskRunState after exec
//!
//!   `exec` replaces the address space of a `Live` task.  The existing
//!   `Pcb::ctx` becomes stale (it encodes the kernel-stack return address from
//!   the *old* binary's syscall entry).  Both `do_execve` and `do_execve_riscv`
//!   now reset `task.run_state` to `TaskRunState::Cold { pc, sp }` after
//!   rebuilding the kernel-stack TrapFrame / SyscallFrame.  This ensures that
//!   the next `schedule()` invocation enters via `context::restore()` rather
//!   than `context::switch()`, which would chase the stale ctx and fault.
//!
//! ## RISC-V in-place exec (do_execve_riscv)
//!
//!   On RISC-V execve arrives through the ecall/trap path. By the time
//!   `sys_execve_noframe` is called the current task's TrapFrame is already
//!   at `kstack_top - TRAP_FRAME_SIZE`. We overwrite it in-place via
//!   `rebuild_trap_frame_riscv`, then update the Context so that the next
//!   context switch (or the eventual trap_return at the end of this trap
//!   handler invocation) enters the new program correctly.
//!
//! ## Post-S2 locking
//!
//!   Both `do_execve` and `do_execve_riscv` update the PCB through
//!   `with_proc_mut(pid, |p, _pl| { … })`. Neither changes `p.state`
//!   so `_pl` is unused.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

use crate::elf;
use crate::fs::vfs;
use crate::mm::{mmap, pmm};
use crate::mm::mmap::{Vma, VmaKind, MAP_ANON, MAP_GROWSDOWN, PROT_READ, PROT_WRITE, PAGE};
use crate::proc::{scheduler, thread};
use crate::proc::fork::SignalHandlers;
use crate::proc::rlimit::RLIM_INFINITY;
use crate::security::CapSet;
use crate::mm::kstack::alloc_kstack;
use crate::uaccess::copy_from_user;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::SyscallFrame;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::update_rsp0;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::paging;

const STACK_TOP:          usize = 0x0000_7FFF_FF00_0000;
const INTERP_BASE:        usize = 0x0060_0000;
const STACK_MAX:          usize = 64 * 1024 * 1024;
const STACK_MIN:          usize = PAGE;
c