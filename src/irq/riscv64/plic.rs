//! RISC-V PLIC (Platform-Level Interrupt Controller) driver.
//!
//! ## Spec reference
//!   RISC-V PLIC Specification v1.0.0
//!   QEMU `virt` machine PLIC base: 0x0C00_0000 (from FDT /soc/plic node)
//!
//! ## PLIC memory map (relative to PLIC base)
//!   0x000000 + irq*4    : source priority registers (1 = lowest, 7 = highest)
//!   0x001000            : pending bits (1 bit per IRQ, read-only)
//!   0x002000 + ctx*0x80 : enable bits (1 bit per IRQ per hart context)
//!   0x200000 + ctx*0x1000 + 0x00 : priority threshold (per context)
//!   0x200000 + ctx*0x1000 + 0x04 : claim/complete register (per context)
//!
//! ## Contexts (QEMU virt)
//!   Context 0: hart 0 M-mode  (used by OpenSBI, do not touch)
//!   Context 1: hart 0 S-mode  ← this is us (BSP)
//!   Context 2: hart 1 M-mode  (OpenSBI)
//!   Context 3: hart 1 S-mode  ← AP hart 1
//!   General formula: ctx = hart * 2 + 1  (S-mode)
//!
//! ## Usage
//!   1. FDT walker calls `set_base(plic_pa)` when it finds the PLIC node.
//!   2. `kernel_main` calls `plic::init()` after fdt::init_from_fdt().
//!   3. Each driver registers its IRQ with `plic::enable_irq(irq, handler)`.
//!   4. APs call `plic::init_context(ctx)` during their own bringup.
//!   5. The trap handler calls `plic::handle_irq()` on every supervisor
//!      external interrupt (scause code 9) on any hart.

use spin::Mutex;

const PLIC_PRIORITY_BASE:  usize = 0x0000_0000;
const PLIC_ENABLE_BASE:    usize = 0x0000_2000;
const PLIC_ENABLE_STRIDE:  usize = 0x0000_0080; // per context
const PLIC_CTX_BASE:       usize = 0x0020_0000;
const PLIC_CTX_STRIDE:     usize = 0x0000_1000; // per context
const PLIC_CTX_THRESHOLD:  usize = 0x0000;
const PLIC_CTX_CLAIM:      usize = 0x0004;

const MAX_IRQ: usize = 128;

type IrqHandler = fn();

struct PlicState {
    base:     usize,
    /// S-mode hart 0 context number (BSP). APs use hart*2+1.
    ctx:      usize,
    handlers: [Option<IrqHandler>; MAX_IRQ],
}

unsafe impl Send for PlicState {}
unsafe impl Sync for PlicState {}

static PLIC: Mutex<PlicState> = Mutex::new(PlicState {
    base:     0,
    ctx:      1,
    handlers: [None; MAX_IRQ],
});

#[inline]
unsafe fn r32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}
#[inline]
unsafe fn w32(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

/// Called by `fdt::init_from_fdt` when it encounters the `/soc/plic` node.
pub fn set_base(base: usize) {
    PLIC.lock().base = base;
    crate::println!("plic: MMIO base {:#x}", base);
}

/// Initialise the PLIC for the S-mode context on hart 0 (BSP).
/// Returns `false` if no PLIC base was found in the FDT.
pub fn init() -> bool {
    let state = PLIC.lock();
    let base  = state.base;
    let ctx   = state.ctx;
    drop(state);
    if base == 0 {
        crate::println!("plic: WARNING: base not set — PLIC not initialised");
        return false;
    }
    unsafe {
        let threshold_addr = base + PLIC_CTX_BASE + ctx * PLIC_CTX_STRIDE + PLIC_CTX_THRESHOLD;
        w32(threshold_addr, 0);
    }
    crate::println!("plic: init OK (ctx {}, threshold 0)", ctx);
    true
}

/// Initialise the PLIC for an AP's S-mode context.
pub fn init_context(ctx: usize) {
    let state = PLIC.lock();
    let base  = state.base;
    let bsp_ctx = state.ctx;
    drop(state);
    if base == 0 { return; }

    unsafe {
        let thr_addr = base + PLIC_CTX_BASE + ctx * PLIC_CTX_STRIDE + PLIC_CTX_THRESHOLD;
        w32(thr_addr, 0);
        let words = MAX_IRQ / 32;
        for w in 0..words {
            let bsp_en = base + PLIC_ENABLE_BASE + bsp_ctx * PLIC_ENABLE_STRIDE + w * 4;
            let ap_en  = base + PLIC_ENABLE_BASE + ctx     * PLIC_ENABLE_STRIDE + w * 4;
            let bits   = r32(bsp_en);
            w32(ap_en, bits);
        }
    }
    crate::println!("plic: AP context {} initialised", ctx);
}

pub fn enable_irq(irq: u32, handler: IrqHandler) {
    if irq == 0 || irq as usize >= MAX_IRQ { return; }
    let mut state = PLIC.lock();
    let base = state.base;
    let ctx  = state.ctx;
    if base == 0 { return; }
    state.handlers[irq as usize] = Some(handler);
    drop(state);
    unsafe {
        w32(base + PLIC_PRIORITY_BASE + irq as usize * 4, 1);
        let en_addr = base + PLIC_ENABLE_BASE + ctx * PLIC_ENABLE_STRIDE + (irq as usize / 32) * 4;
        w32(en_addr, r32(en_addr) | (1 << (irq % 32)));
    }
}

pub fn disable_irq(irq: u32) {
    if irq == 0 || irq as usize >= MAX_IRQ { return; }
    let mut state = PLIC.lock();
    let base = state.base;
    let ctx  = state.ctx;
    state.handlers[irq as usize] = None;
    drop(state);
    if base == 0 { return; }
    unsafe {
        let en_addr = base + PLIC_ENABLE_BASE + ctx * PLIC_ENABLE_STRIDE + (irq as usize / 32) * 4;
        w32(en_addr, r32(en_addr) & !(1 << (irq % 32)));
    }
}

pub fn handle_irq() {
    let base = PLIC.lock().base;
    if base == 0 { return; }
    let hart_id: usize;
    unsafe { core::arch::asm!("mv {}, tp", out(reg) hart_id, options(nostack, nomem)); }
    let ctx = hart_id * 2 + 1;
    let claim_addr = base + PLIC_CTX_BASE + ctx * PLIC_CTX_STRIDE + PLIC_CTX_CLAIM;
    loop {
        let irq = unsafe { r32(claim_addr) };
        if irq == 0 { break; }

        #[cfg(feature = "debug")]
        {
            use crate::debug::trace::{emit, TraceEvent, TraceKind};
            emit(TraceEvent {
                kind:  TraceKind::IrqDispatch,
                id:    irq,
                arg:   hart_id as u64,
                ticks: crate::time::read_ticks(),
            });
        }

        let handler = PLIC.lock().handlers.get(irq as usize).copied().flatten();
        if let Some(h) = handler { h(); }
        unsafe { w32(claim_addr, irq); }
    }
}

pub fn base() -> usize { PLIC.lock().base }
