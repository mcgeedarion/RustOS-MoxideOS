//! Panic/oops formatter — register dump, frame-pointer stack backtrace,
//! and best-effort symbol resolution.
//!
//! # Usage
//!
//! `oops` is called from the `#[panic_handler]` in `src/kernel_main.rs`
//! when the kernel is built with `--features debug` (which also implies
//! `debug_stub` and `trace` via Cargo feature dependencies).
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
//! # Symbol resolution
//!
//! A sorted `(address, name)` table is embedded at build time by `build.rs`
//! (generated from `llvm-nm --numeric-sort` on the kernel ELF). At runtime
//! `resolve_symbol` binary-searches the table for the nearest symbol and
//! returns `(name, offset)` so callers can print `symbol+0x80` style output.
//!
//! # Crash log
//!
//! `oops` writes a fixed-size [`CrashLog`] record into the `.crash_log`
//! linker section before unwinding.  Add to your linker script:
//! ```ld
//! .crash_log (NOLOAD) : { KEEP(*(.crash_log)) }
//! ```
//! Call [`check_crash_log`] early in boot to detect and print the previous
//! crash before the memory is overwritten.

use core::sync::atomic::{AtomicBool, Ordering};

/// Guard against re-entrant panics while printing the oops message.
static IN_OOPS: AtomicBool = AtomicBool::new(false);

/// Fallback empty table so the crate compiles without a generated symbols file.
#[cfg(not(has_symbol_table))]
static SYMBOLS: &[(usize, &str)] = &[];

#[cfg(has_symbol_table)]
include!(concat!(env!("OUT_DIR"), "/symbols.rs"));

// ── Crash log ────────────────────────────────────────────────────────────────

/// Fixed-size binary crash record written to a dedicated ELF section so a
/// subsequent boot can read it before the region is overwritten.
#[repr(C)]
pub struct CrashLog {
    /// `CRASH_MAGIC` when a valid record is present; 0 otherwise.
    pub magic: u64,
    /// Program counter at crash time (0 if no TrapFrame was available).
    pub ip: u64,
    /// Stack pointer at crash time.
    pub sp: u64,
    pub msg_len: u32,
    pub msg: [u8; 256],
}

pub const CRASH_MAGIC: u64 = 0xDEAD_C0DE_CAFE_BABE;

#[link_section = ".crash_log"]
pub static mut CRASH_LOG: CrashLog = CrashLog {
    magic: 0,
    ip: 0,
    sp: 0,
    msg_len: 0,
    msg: [0u8; 256],
};

fn write_crash_log(msg: &str, ip: u64, sp: u64) {
    // SAFETY: only called from the oops path, which is serialised by IN_OOPS.
    unsafe {
        let log = &mut CRASH_LOG;
        log.ip = ip;
        log.sp = sp;
        let bytes = msg.as_bytes();
        let len = bytes.len().min(log.msg.len() - 1);
        log.msg[..len].copy_from_slice(&bytes[..len]);
        log.msg[len] = 0;
        log.msg_len = len as u32;
        // Write magic last — a partial write must not look like a valid record.
        core::sync::atomic::fence(Ordering::Release);
        log.magic = CRASH_MAGIC;
    }
}

/// Check the crash log at early boot.  If the previous boot left a valid
/// record, print it to the serial console and clear the magic sentinel.
pub fn check_crash_log() {
    // SAFETY: called once at early boot before any concurrent writers exist.
    unsafe {
        if CRASH_LOG.magic != CRASH_MAGIC {
            return;
        }
        let len = CRASH_LOG.msg_len as usize;
        let msg = core::str::from_utf8(&CRASH_LOG.msg[..len]).unwrap_or("<utf8 error>");
        crate::serial_println!("*** Previous boot crashed ***");
        crate::serial_println!("  ip={:#018x}  sp={:#018x}", CRASH_LOG.ip, CRASH_LOG.sp);
        crate::serial_println!("  msg: {}", msg);
        // Clear so we don't re-print on the next boot.
        CRASH_LOG.magic = 0;
    }
}

// ── Symbol resolution ─────────────────────────────────────────────────────────

/// Resolve a virtual address to `(nearest_symbol_name, byte_offset)`.
///
/// Returns `("<unknown>", 0)` when the table is empty or the address precedes
/// all known symbols.  Print as `"symbol+0x80"` when offset is non-zero.
pub fn resolve_symbol(addr: usize) -> (&'static str, usize) {
    if SYMBOLS.is_empty() {
        return ("<unknown>", 0);
    }
    match SYMBOLS.binary_search_by_key(&addr, |&(a, _)| a) {
        Ok(i) => (SYMBOLS[i].1, 0),
        Err(0) => ("<unknown>", 0),
        Err(i) => {
            let (sym_addr, name) = SYMBOLS[i - 1];
            (name, addr - sym_addr)
        },
    }
}

// ── Backtrace ─────────────────────────────────────────────────────────────────

/// Maximum call-stack depth to unwind before giving up.
const MAX_FRAMES: usize = 32;

/// Walk the frame-pointer chain starting at `fp`, printing each return
/// address and its resolved symbol to the kernel serial console.
///
/// # Safety
/// `fp` must be a valid, 16-byte-aligned stack frame pointer or `0`.
pub unsafe fn backtrace_from(fp: usize) {
    crate::serial_println!("--- backtrace ---");
    let mut frame = fp;
    for depth in 0..MAX_FRAMES {
        if frame == 0 {
            break;
        }
        // x86_64 SysV ABI mandates 16-byte alignment at call boundaries.
        // RISC-V and AArch64 frame pointers are also 16-byte aligned in
        // practice.  The old 0x7 (8-byte) check was too permissive.
        if frame & 0xf != 0 {
            crate::serial_println!("  #{depth:2}: <misaligned frame pointer {frame:#x}>");
            break;
        }
        // Standard ABI frame layout:
        //   [fp + 0]  = saved fp of caller
        //   [fp + 8]  = return address
        let ret_addr = *(frame as *const usize).add(1);
        if ret_addr == 0 {
            break;
        }
        let (sym, off) = resolve_symbol(ret_addr);
        if off == 0 {
            crate::serial_println!("  #{depth:2}: {ret_addr:#018x}  {sym}");
        } else {
            crate::serial_println!("  #{depth:2}: {ret_addr:#018x}  {sym}+{off:#x}");
        }
        frame = *(frame as *const usize);
    }
    crate::serial_println!("--- end backtrace ---");
}

/// Capture the current frame pointer via inline asm and call
/// [`backtrace_from`].
pub fn backtrace() {
    let fp: usize;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) fp);
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        // s0 / x8 is the frame pointer register on RISC-V.
        core::arch::asm!("mv {}, s0", out(reg) fp);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // x29 is the frame pointer register on AArch64.
        core::arch::asm!("mov {}, x29", out(reg) fp);
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    )))]
    {
        fp = 0;
    }
    unsafe {
        backtrace_from(fp);
    }
}

// ── Register dumps ────────────────────────────────────────────────────────────

/// Print all general-purpose registers for an x86_64 trap frame.
#[cfg(target_arch = "x86_64")]
pub fn dump_regs(regs: &crate::arch::x86_64::TrapFrame) {
    crate::serial_println!("--- registers (x86_64) ---");
    crate::serial_println!(
        "  rax={:#018x}  rbx={:#018x}  rcx={:#018x}",
        regs.rax, regs.rbx, regs.rcx
    );
    crate::serial_println!(
        "  rdx={:#018x}  rsi={:#018x}  rdi={:#018x}",
        regs.rdx, regs.rsi, regs.rdi
    );
    crate::serial_println!(
        "  r8 ={:#018x}  r9 ={:#018x}  r10={:#018x}",
        regs.r8, regs.r9, regs.r10
    );
    crate::serial_println!(
        "  r11={:#018x}  r12={:#018x}  r13={:#018x}",
        regs.r11, regs.r12, regs.r13
    );
    crate::serial_println!(
        "  r14={:#018x}  r15={:#018x}  rbp={:#018x}",
        regs.r14, regs.r15, regs.rbp
    );
    crate::serial_println!(
        "  rip={:#018x}  rsp={:#018x}  rflags={:#018x}",
        regs.rip, regs.rsp, regs.rflags
    );
    crate::serial_println!("--- end registers ---");
}

/// Print all general-purpose registers for a RISC-V trap frame.
#[cfg(target_arch = "riscv64")]
pub fn dump_regs(regs: &crate::arch::riscv64::TrapFrame) {
    crate::serial_println!("--- registers (riscv64) ---");
    crate::serial_println!(
        "  ra ={:#018x}  sp ={:#018x}  gp ={:#018x}",
        regs.ra, regs.sp, regs.gp
    );
    crate::serial_println!(
        "  tp ={:#018x}  t0 ={:#018x}  t1 ={:#018x}",
        regs.tp, regs.t0, regs.t1
    );
    crate::serial_println!(
        "  t2 ={:#018x}  s0 ={:#018x}  s1 ={:#018x}",
        regs.t2, regs.s0, regs.s1
    );
    crate::serial_println!(
        "  a0 ={:#018x}  a1 ={:#018x}  a2 ={:#018x}",
        regs.a0, regs.a1, regs.a2
    );
    crate::serial_println!(
        "  a3 ={:#018x}  a4 ={:#018x}  a5 ={:#018x}",
        regs.a3, regs.a4, regs.a5
    );
    crate::serial_println!("  a6 ={:#018x}  a7 ={:#018x}", regs.a6, regs.a7);
    crate::serial_println!(
        "  sepc={:#018x}  scause={:#018x}  stval={:#018x}",
        regs.sepc, regs.scause, regs.stval
    );
    crate::serial_println!("--- end registers ---");
}

/// Print all general-purpose registers for an AArch64 trap frame.
#[cfg(target_arch = "aarch64")]
pub fn dump_regs(regs: &crate::arch::aarch64::TrapFrame) {
    crate::serial_println!("--- registers (aarch64) ---");
    crate::serial_println!(
        "  x0 ={:#018x}  x1 ={:#018x}  x2 ={:#018x}",
        regs.x0, regs.x1, regs.x2
    );
    crate::serial_println!(
        "  x3 ={:#018x}  x4 ={:#018x}  x5 ={:#018x}",
        regs.x3, regs.x4, regs.x5
    );
    crate::serial_println!(
        "  x6 ={:#018x}  x7 ={:#018x}  x8 ={:#018x}",
        regs.x6, regs.x7, regs.x8
    );
    crate::serial_println!(
        "  x9 ={:#018x}  x10={:#018x}  x11={:#018x}",
        regs.x9, regs.x10, regs.x11
    );
    crate::serial_println!(
        "  x12={:#018x}  x13={:#018x}  x14={:#018x}",
        regs.x12, regs.x13, regs.x14
    );
    crate::serial_println!(
        "  x15={:#018x}  x16={:#018x}  x17={:#018x}",
        regs.x15, regs.x16, regs.x17
    );
    crate::serial_println!(
        "  x18={:#018x}  x19={:#018x}  x20={:#018x}",
        regs.x18, regs.x19, regs.x20
    );
    crate::serial_println!(
        "  x21={:#018x}  x22={:#018x}  x23={:#018x}",
        regs.x21, regs.x22, regs.x23
    );
    crate::serial_println!(
        "  x24={:#018x}  x25={:#018x}  x26={:#018x}",
        regs.x24, regs.x25, regs.x26
    );
    crate::serial_println!(
        "  x27={:#018x}  x28={:#018x}  x29={:#018x}",
        regs.x27, regs.x28, regs.x29
    );
    crate::serial_println!("  x30={:#018x}  sp ={:#018x}", regs.x30, regs.sp);
    crate::serial_println!("  pc ={:#018x}  spsr={:#018x}", regs.pc, regs.spsr);
    crate::serial_println!("--- end registers ---");
}

// ── AnyTrapFrame ─────────────────────────────────────────────────────────────

/// Type-erased architecture trap frame.  Pass a variant from the trap handler
/// so `oops` can dump registers and extract the crash PC/SP for the log.
pub enum AnyTrapFrame<'a> {
    #[cfg(target_arch = "x86_64")]
    X86_64(&'a crate::arch::x86_64::TrapFrame),
    #[cfg(target_arch = "riscv64")]
    RiscV(&'a crate::arch::riscv64::TrapFrame),
    #[cfg(target_arch = "aarch64")]
    AArch64(&'a crate::arch::aarch64::TrapFrame),
}

// ── Main oops entry point ─────────────────────────────────────────────────────

/// Enrich a panic with a register dump, crash log, backtrace, and trace drain.
///
/// The `#[panic_handler]` in `src/kernel_main.rs` already emits a
/// `KERNEL PANIC at file:line:col: message` header before calling this;
/// `oops` adds the register dump, crash log write, backtrace, and trace drain.
///
/// Pass `Some(AnyTrapFrame::X86_64(tf))` (or the appropriate arch variant)
/// when called from a trap handler.  Pass `None` for bare Rust panics.
///
/// Only called when built with `--features debug`.
///
/// ```rust
/// #[panic_handler]
/// fn panic(info: &core::panic::PanicInfo) -> ! {
///     let msg = info.message().as_str().unwrap_or("(no message)");
///     crate::serial_println!("KERNEL PANIC: {}", msg);
///     #[cfg(feature = "debug")]
///     crate::debug::oops::oops(msg, None);
///     loop { core::hint::spin_loop(); }
/// }
///
/// // From a trap handler:
/// crate::debug::oops::oops(
///     "page fault",
///     Some(crate::debug::oops::AnyTrapFrame::X86_64(trap_frame)),
/// );
/// ```
pub fn oops(msg: &str, frame: Option<AnyTrapFrame<'_>>) {
    // Acquire/Release is sufficient — SeqCst adds a costly full fence on x86
    // for no benefit in a single-CPU panic path (interrupts are typically
    // disabled by the time we get here).
    if IN_OOPS
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    crate::serial_println!("\n!!! KERNEL OOPS !!!");
    crate::serial_println!("message: {}", msg);

    // Dump registers first — before backtrace — so the output is useful even
    // if the frame-pointer walk itself faults.
    let (ip, sp): (u64, u64) = match frame {
        #[cfg(target_arch = "x86_64")]
        Some(AnyTrapFrame::X86_64(regs)) => {
            dump_regs(regs);
            (regs.rip, regs.rsp)
        },
        #[cfg(target_arch = "riscv64")]
        Some(AnyTrapFrame::RiscV(regs)) => {
            dump_regs(regs);
            (regs.sepc, regs.sp)
        },
        #[cfg(target_arch = "aarch64")]
        Some(AnyTrapFrame::AArch64(regs)) => {
            dump_regs(regs);
            (regs.pc, regs.sp)
        },
        None => (0, 0),
    };

    // Persist crash info before the backtrace so it survives even if the walk
    // triggers a second fault.
    write_crash_log(msg, ip, sp);

    backtrace();

    // Flush the last N function-trace events so we can see the call history
    // leading up to the crash.
    #[cfg(feature = "trace")]
    crate::debug::ftrace::drain_last_n(32, |ev| {
        let kind_str = match ev.kind {
            crate::debug::trace::TraceKind::FuncEnter => "enter",
            crate::debug::trace::TraceKind::FuncExit => "exit",
            _ => "other",
        };
        let (sym, off) = resolve_symbol(ev.arg as usize);
        if off == 0 {
            crate::serial_println!("  ftrace [{}] {} ticks={}", kind_str, sym, ev.ticks);
        } else {
            crate::serial_println!("  ftrace [{}] {}+{:#x} ticks={}", kind_str, sym, off, ev.ticks);
        }
    });

    // Flush any remaining (non-ftrace) trace events.
    #[cfg(feature = "trace")]
    crate::debug::trace::drain(|ev| {
        crate::serial_println!(
            "  trace [{:?}] id={} arg={:#x} ticks={}",
            ev.kind,
            ev.id,
            ev.arg,
            ev.ticks
        );
    });
}
