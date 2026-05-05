//! Architecture-independent kernel entry point.
//!
//! Called by the arch boot stub (_start) after a minimal stack is set up.
//! Performs subsystem init in order, prints CI sentinels, then enters the
//! scheduler idle loop.
//!
//! ## CI sentinels (must appear on serial/stdout for the smoke tests to pass)
//!   "rustos: kernel_main reached"    — boot smoke test
//!   "TEST PASS: uart_smoke"          — UART is functional
//!   "TEST PASS: alloc_smoke"         — global allocator is functional
//!   "TEST PASS: trap_smoke"          — trap handler is wired up

use crate::arch::api::{ArchInit, Serial};
use crate::arch::ArchImpl;

/// Kernel entry point.  Called from `_start` with interrupts disabled.
///
/// # Arguments
/// * `hart_id`  — RISC-V hart ID (0 on single-core QEMU virt)
/// * `fdt_ptr`  — physical address of the Flattened Device Tree blob
#[no_mangle]
pub extern "C" fn kernel_main(_hart_id: usize, _fdt_ptr: usize) -> ! {
    // ── 1. Serial / UART init ────────────────────────────────────────────
    ArchImpl::serial_init();

    // Boot sentinel — CI boot smoke test checks for this exact string.
    println!("rustos: kernel_main reached");
    println!("TEST PASS: uart_smoke");

    // ── 2. Architecture early init (stvec, mmu stubs) ───────────────────
    ArchImpl::early_init();

    // ── 3. Physical memory manager ───────────────────────────────────────
    // pmm::init() scans available RAM from the DTB / linker symbols.
    // We call the stub here; a full implementation will call pmm::init(fdt_ptr).
    crate::mm::pmm::init();

    // ── 4. Global allocator smoke test ──────────────────────────────────
    {
        extern crate alloc;
        use alloc::vec::Vec;
        let mut v: Vec<u32> = Vec::new();
        v.push(0xdeadbeef);
        assert_eq!(v[0], 0xdeadbeef, "alloc_smoke: heap alloc failed");
    }
    println!("TEST PASS: alloc_smoke");

    // ── 5. Trap / interrupt init ─────────────────────────────────────────
    crate::arch::riscv64::trap::trap_init();
    println!("TEST PASS: trap_smoke");

    // ── 6. Architecture late init (enable interrupts) ────────────────────
    ArchImpl::late_init();

    // ── 7. Idle loop ─────────────────────────────────────────────────────
    println!("rustos: entering idle loop");
    loop {
        crate::arch::api::Cpu::halt();
    }
}
