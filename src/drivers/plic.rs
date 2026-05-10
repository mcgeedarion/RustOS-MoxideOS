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
//! ## Contexts (QEMU virt, 1 hart)
//!   Context 0: hart 0 M-mode  (used by OpenSBI, do not touch)
//!   Context 1: hart 0 S-mode  ← this is us
//!   Context 2: hart 1 M-mode  (not present in single-hart QEMU)
//!   ...
//!   General formula: ctx = hart * 2 + 1  (S-mode)
//!
//! ## Usage
//!   1. FDT walker calls `set_base(plic_pa)` when it finds the PLIC node.
//!   2. `kernel_main` calls `plic::init()` after fdt::init_from_fdt().
//!   3. Each driver registers its IRQ with `plic::enable_irq(irq, handler)`.
//!      virtio_net_mmio stores its IRQ number and calls this after probe().
//!   4. The trap handler calls `plic::handle_irq()` on every supervisor
//!      external interrupt (scause code 9).

use spin::Mutex;

// ── PLIC register layout constants ─────────────────────────────────────────────────

const PLIC_PRIORITY_BASE:  usize = 0x0000_0000;
const PLIC_ENABLE_BASE:    usize = 0x0000_2000;
const PLIC_ENABLE_STRIDE:  usize = 0x0000_0080; // per context
const PLIC_CTX_BASE:       usize = 0x0020_0000;
const PLIC_CTX_STRIDE:     usize = 0x0000_1000; // per context
const PLIC_CTX_THRESHOLD:  usize = 0x0000;      // offset within context
const PLIC_CTX_CLAIM:      usize = 0x0004;      // offset within context (claim/complete)

// Number of IRQ sources the PLIC supports (spec allows up to 1023).
// QEMU virt uses 96 sources.  We allocate a handler table for 128.
const MAX_IRQ: usize = 128;

// ── State ───────────────────────────────────────────────────────────────────────────

type IrqHandler = fn();

struct PlicState {
    base:     usize,
    /// S-mode hart 0 context number.  For a 1-hart system this is 1.
    ctx:      usize,
    handlers: [Option<IrqHandler>; MAX_IRQ],
}

unsafe impl Send for PlicState {}
unsafe impl Sync for PlicState {}

static PLIC: Mutex<PlicState> = Mutex::new(PlicState {
    base:     0,
    ctx:      1,   // hart 0 S-mode
    handlers: [None; MAX_IRQ],
});

// ── MMIO helpers ─────────────────────────────────────────────────────────────────────

#[inline]
unsafe fn r32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}
#[inline]
unsafe fn w32(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

// ── FDT callback ───────────────────────────────────────────────────────────────────

/// Called by `fdt::init_from_fdt` when it encounters the `/soc/plic` node.
/// `base` is the identity-mapped physical address from the `reg` property.
pub fn set_base(base: usize) {
    PLIC.lock().base = base;
    crate::println!("plic: MMIO base {:#x}", base);
}

// ── Init ──────────────────────────────────────────────────────────────────────────────

/// Initialise the PLIC for the S-mode context on hart 0.
///
/// Sets the priority threshold to 0 (accept all non-zero priorities).
/// Call this after `fdt::init_from_fdt` so `set_base` has been called.
/// Returns `false` if no PLIC base was found in the FDT.
pub fn init() -> bool {
    let state = PLIC.lock();
    let base = state.base;
    let ctx  = state.ctx;
    drop(state);

    if base == 0 {
        crate::println!("plic: WARNING: base not set — PLIC not initialised");
        return false;
    }

    unsafe {
        // Set priority threshold = 0 for our S-mode context.
        // This means any IRQ with priority ≥ 1 will be delivered.
        let threshold_addr = base + PLIC_CTX_BASE + ctx * PLIC_CTX_STRIDE + PLIC_CTX_THRESHOLD;
        w32(threshold_addr, 0);
    }
    crate::println!("plic: init OK (ctx {}, threshold 0)", ctx);
    true
}

// ── IRQ registration ─────────────────────────────────────────────────────────────────

/// Register a handler for `irq` and enable it in the PLIC.
///
/// - Sets source priority to 1 (lowest non-zero).
/// - Sets the enable bit in the S-mode context enable bank.
/// - Records `handler` in the dispatch table.
///
/// Safe to call multiple times for the same IRQ (updates handler).
pub fn enable_irq(irq: u32, handler: IrqHandler) {
    if irq == 0 || irq as usize >= MAX_IRQ {
        crate::println!("plic: enable_irq: invalid IRQ {}", irq);
        return;
    }
    let mut state = PLIC.lock();
    let base = state.base;
    let ctx  = state.ctx;
    if base == 0 { return; }

    state.handlers[irq as usize] = Some(handler);
    drop(state);

    unsafe {
        // Set source priority = 1.
        let prio_addr = base + PLIC_PRIORITY_BASE + irq as usize * 4;
        w32(prio_addr, 1);

        // Set enable bit in the context's enable bank.
        // Each context has 128 bits (4 bytes per 32 IRQs).
        let word     = irq as usize / 32;
        let bit      = irq as usize % 32;
        let en_addr  = base + PLIC_ENABLE_BASE + ctx * PLIC_ENABLE_STRIDE + word * 4;
        let prev     = r32(en_addr);
        w32(en_addr, prev | (1 << bit));
    }
    crate::println!("plic: enabled IRQ {} (ctx {})", irq, ctx);
}

/// Disable an IRQ source in the PLIC (clears enable bit, removes handler).
pub fn disable_irq(irq: u32) {
    if irq == 0 || irq as usize >= MAX_IRQ { return; }
    let mut state = PLIC.lock();
    let base = state.base;
    let ctx  = state.ctx;
    state.handlers[irq as usize] = None;
    drop(state);
    if base == 0 { return; }
    unsafe {
        let word    = irq as usize / 32;
        let bit     = irq as usize % 32;
        let en_addr = base + PLIC_ENABLE_BASE + ctx * PLIC_ENABLE_STRIDE + word * 4;
        let prev    = r32(en_addr);
        w32(en_addr, prev & !(1 << bit));
    }
}

// ── IRQ dispatch ───────────────────────────────────────────────────────────────────────

/// Called from the supervisor external interrupt handler in `trap.rs`
/// (scause code 9, MSB set = interrupt).
///
/// Loops claiming IRQs until the PLIC returns 0 (no more pending).
/// For each claimed IRQ:
///   1. Calls the registered handler (e.g. `virtio_net_mmio::virtio_net_mmio_irq`).
///   2. Writes the IRQ back to the complete register.
///
/// This must NOT hold the PLIC mutex across the handler call, because the
/// handler (e.g. virtio_net_mmio_irq) may itself try to lock other mutexes.
pub fn handle_irq() {
    let (base, ctx) = {
        let state = PLIC.lock();
        (state.base, state.ctx)
    };
    if base == 0 { return; }

    let claim_addr = base + PLIC_CTX_BASE + ctx * PLIC_CTX_STRIDE + PLIC_CTX_CLAIM;

    loop {
        let irq = unsafe { r32(claim_addr) };
        if irq == 0 { break; } // no more pending

        // Look up handler without holding the lock during dispatch.
        let handler: Option<IrqHandler> = {
            let state = PLIC.lock();
            if irq as usize < MAX_IRQ { state.handlers[irq as usize] } else { None }
        };

        if let Some(h) = handler {
            h();
        } else {
            crate::println!("plic: spurious IRQ {}", irq);
        }

        // Write IRQ back to claim/complete to signal completion.
        unsafe { w32(claim_addr, irq); }
    }
}

/// Returns the current PLIC base address (0 if not set).
pub fn base() -> usize {
    PLIC.lock().base
}
