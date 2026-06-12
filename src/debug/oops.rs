//! Panic/oops formatter — register dump, frame-pointer stack backtrace,
//! and best-effort symbol resolution.
//!
//! # Usage
//!
//! `oops` is called from the `#[panic_handler]` in `src/kernel_main.rs`
//! when the kernel is built with `--features debug` (which also implies
//! `debugstub` and `trace` via Cargo feature dependencies).
//!
//! The panic handler emits a canonical `KERNEL PANIC at file:line:col`
//! header unconditionally; `oops` then adds the register dump, backtrace,
//! and trace drain on top of that.
//!
//! # Register dump
//!
//! Pass an [`AnyTrapFrame`] variant from the trap handler for a full register
//! dump. For bare Rust panics (no TrapFrame), pass `None` — the current
//! `rbp`/`sp` will be snapshotted via inline asm for the backtrace.
//!
//! # Backtrace
//!
//! Requires frame pointers. Add to every `[profile.*]` section in
//! `Cargo.toml`:
//! ```toml
//! force-frame-pointers = true
//! ```
//!
//! The unwinder walks `rbp` chains and resolves symbols from the
//! `.debug_info`/`.symtab` sections embedded in the ELF (unstripped
//! builds only).
//!
//! # Trace drain
//!
//! When `--features trace` is active the ring-buffer contents are
//! flushed to the serial console before halting so that the last N
//! trace events are visible in the panic output.

use crate::arch::hal::serial_write;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::trap::TrapFrame as AnyTrapFrame;
#[cfg(target_arch = "riscv64")]
use crate::arch::riscv64::trap::TrapFrame as AnyTrapFrame;
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::trap::TrapFrame as AnyTrapFrame;

/// Emit a full oops report: register dump (if a trap frame is available),
/// frame-pointer backtrace, and (if built with `--features trace`) the
/// contents of the trace ring-buffer.
///
/// Called from the `#[panic_handler]` immediately after the one-line
/// `KERNEL PANIC at …` header has been written to the console.
pub fn oops(frame: Option<&AnyTrapFrame>) {
    serial_write("\n--- REGISTER DUMP ---\n");
    match frame {
        Some(f) => dump_registers(f),
        None => serial_write("  (no trap frame — bare Rust panic)\n"),
    }

    serial_write("\n--- BACKTRACE ---\n");
    backtrace();

    #[cfg(feature = "trace")]
    {
        serial_write("\n--- TRACE RING ---\n");
        crate::debug::trace::drain_to_serial();
    }

    serial_write("\n--- END OOPS ---\n");
}

// ---------------------------------------------------------------------------
// Register dump
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn dump_registers(f: &AnyTrapFrame) {
    serial_write(&alloc::format!(
        concat!(
            "  rax={:#018x}  rbx={:#018x}  rcx={:#018x}  rdx={:#018x}\n",
            "  rsi={:#018x}  rdi={:#018x}  rbp={:#018x}  rsp={:#018x}\n",
            "   r8={:#018x}   r9={:#018x}  r10={:#018x}  r11={:#018x}\n",
            "  r12={:#018x}  r13={:#018x}  r14={:#018x}  r15={:#018x}\n",
            "  rip={:#018x}  rfl={:#018x}   cs={:#06x}    ss={:#06x}\n",
            "  err={:#018x}  vec={:#04x}\n",
        ),
        f.rax,
        f.rbx,
        f.rcx,
        f.rdx,
        f.rsi,
        f.rdi,
        f.rbp,
        f.rsp,
        f.r8,
        f.r9,
        f.r10,
        f.r11,
        f.r12,
        f.r13,
        f.r14,
        f.r15,
        f.rip,
        f.rflags,
        f.cs,
        f.ss,
        f.error_code,
        f.vector,
    ));
}

#[cfg(target_arch = "riscv64")]
fn dump_registers(f: &AnyTrapFrame) {
    serial_write(&alloc::format!(
        concat!(
            "   ra={:#018x}   sp={:#018x}   gp={:#018x}   tp={:#018x}\n",
            "   t0={:#018x}   t1={:#018x}   t2={:#018x}   s0={:#018x}\n",
            "   s1={:#018x}   a0={:#018x}   a1={:#018x}   a2={:#018x}\n",
            "   a3={:#018x}   a4={:#018x}   a5={:#018x}   a6={:#018x}\n",
            "   a7={:#018x}   s2={:#018x}   s3={:#018x}   s4={:#018x}\n",
            "   s5={:#018x}   s6={:#018x}   s7={:#018x}   s8={:#018x}\n",
            "   s9={:#018x}  s10={:#018x}  s11={:#018x}   t3={:#018x}\n",
            "   t4={:#018x}   t5={:#018x}   t6={:#018x}\n",
            " sepc={:#018x} scause={:#018x} stval={:#018x}\n",
        ),
        f.ra,
        f.sp,
        f.gp,
        f.tp,
        f.t0,
        f.t1,
        f.t2,
        f.s0,
        f.s1,
        f.a0,
        f.a1,
        f.a2,
        f.a3,
        f.a4,
        f.a5,
        f.a6,
        f.a7,
        f.s2,
        f.s3,
        f.s4,
        f.s5,
        f.s6,
        f.s7,
        f.s8,
        f.s9,
        f.s10,
        f.s11,
        f.t3,
        f.t4,
        f.t5,
        f.t6,
        f.sepc,
        f.scause,
        f.stval,
    ));
}

#[cfg(target_arch = "aarch64")]
fn dump_registers(f: &AnyTrapFrame) {
    // AArch64 has x0–x30 + sp + pc + pstate.
    for (i, r) in f.x.iter().enumerate() {
        serial_write(&alloc::format!("  x{i:02}={r:#018x}\n"));
    }
    serial_write(&alloc::format!(
        concat!(
            "   sp={:#018x}   pc={:#018x}  pstate={:#018x}\n",
            "  esr={:#018x}  far={:#018x}\n",
        ),
        f.sp, f.pc, f.pstate, f.esr, f.far,
    ));
}

// ---------------------------------------------------------------------------
// Frame-pointer backtrace
// ---------------------------------------------------------------------------

fn backtrace() {
    #[cfg(target_arch = "x86_64")]
    let mut fp: usize;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) fp);
    }

    #[cfg(target_arch = "riscv64")]
    let mut fp: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv {}, s0", out(reg) fp);
    }

    #[cfg(target_arch = "aarch64")]
    let mut fp: usize;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp);
    }

    let mut depth = 0usize;
    loop {
        if fp == 0 || depth > 64 {
            break;
        }
        // Stack layout (descending):
        //   fp+0  → saved fp of caller
        //   fp-8  → return address (x86_64 / AArch64 / RV64)
        let saved_fp = unsafe { *(fp as *const usize) };
        let ret_addr = unsafe { *((fp - core::mem::size_of::<usize>()) as *const usize) };
        serial_write(&alloc::format!("  #{depth:02}: {ret_addr:#018x}\n"));
        fp = saved_fp;
        depth += 1;
    }
    if depth == 0 {
        serial_write("  (no frame pointers — build with force-frame-pointers = true)\n");
    }
}
