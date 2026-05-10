//! RISC-V SMP bringup via SBI HSM extension + IPI via SBI sPI extension.
//!
//! ## SBI HSM extension (EID 0x48534D = "HSM")
//!   FID 0  HART_START   — start a halted hart at a given entry point
//!   FID 1  HART_STOP    — stop the calling hart
//!   FID 2  HART_STATUS  — query hart state
//!
//! ## SBI IPI extension (EID 0x735049 = "sPI")
//!   FID 0  SEND_IPI     — deliver a software interrupt to a hart mask
//!     a0 = hart_mask       (bitmask of target harts, bit N = hart N)
//!     a1 = hart_mask_base  (hart index of bit 0; use 0 for direct mask)
//!
//!   OpenSBI sets SIP.SSIP on the target hart(s).  The target wakes from
//!   wfi (or is interrupted mid-execution) and takes a supervisor software
//!   interrupt (scause = 0x8000_0000_0000_0001).
//!
//! ## IPI dispatch (scause code 1)
//!   The trap handler calls `ipi::dispatch(cpu_id)` which reads and clears
//!   `PercpuBlock::ipi_pending` then handles each set bit:
//!     bit 0 = TlbShootdown  → ipi::handle_tlb_shootdown(cpu_id)
//!     bit 1 = Reschedule    → proc::scheduler::schedule()
//!     bit 2 = FuncCall      → (future deferred-work queue)
//!     bit 3 = PanicHalt     → halt this hart
//!
//! ## Boot sequence for secondary harts
//!   BSP calls `start_all_harts()` which issues one `sbi_hart_start(hart_id,
//!   ap_entry_riscv, opaque)` per secondary hart registered in the topology
//!   table.  OpenSBI trampoline places the hart in S-mode with:
//!     a0 = hart_id (hw)
//!     a1 = opaque  (we pass the logical cpu_id)
//!   then jumps to our `ap_entry_riscv` naked stub.
//!
//! ## AP stack allocation
//!   Each AP gets a dedicated 64 KiB stack allocated from the PMM.
//!
//! ## PLIC context wiring for APs
//!   Each hart N has S-mode context `N * 2 + 1`.  `ap_init_plic()` calls
//!   `plic::init_context(ctx)` to set the threshold to 0 and copy enable
//!   bits from the BSP context.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::mm::pmm;

// ── Constants ───────────────────────────────────────────────────────────────────

const SBI_EXT_HSM:         usize = 0x48534D;
const SBI_HSM_HART_START:  usize = 0;
const SBI_HSM_HART_STATUS: usize = 2;

const SBI_EXT_IPI:         usize = 0x735049; // "sPI"
const SBI_IPI_SEND:        usize = 0;        // FID 0: sbi_send_ipi

const SBI_EXT_BASE:        usize = 0x10;     // SBI base extension
const SBI_BASE_GET_MVENDORID: usize = 4;     // reuse: get_mhartid via EID 0x4

/// 64 KiB per AP.
const AP_STACK_PAGES: usize = 16;
const AP_STACK_SIZE:  usize = AP_STACK_PAGES * 4096;

const MAX_APS: usize = crate::smp::MAX_CPUS - 1;

// ── AP stack table ───────────────────────────────────────────────────────────────

static AP_STACKS: [AtomicUsize; MAX_APS] = {
    const ZERO: AtomicUsize = AtomicUsize::new(0);
    [ZERO; MAX_APS]
};

// ── SBI call helpers ─────────────────────────────────────────────────────────────

#[inline]
unsafe fn sbi_call(eid: usize, fid: usize, a0: usize, a1: usize, a2: usize)
    -> (isize, usize)
{
    let err: isize;
    let val: usize;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0 => err,
        inlateout("a1") a1 => val,
        in("a2") a2,
        in("a6") fid,
        in("a7") eid,
        options(nostack)
    );
    (err, val)
}

pub fn sbi_hart_start(hart_id: usize, entry: usize, opaque: usize) -> isize {
    unsafe { sbi_call(SBI_EXT_HSM, SBI_HSM_HART_START, hart_id, entry, opaque).0 }
}
pub fn sbi_hart_status(hart_id: usize) -> isize {
    unsafe { sbi_call(SBI_EXT_HSM, SBI_HSM_HART_STATUS, hart_id, 0, 0).0 }
}

/// Send a software interrupt to `target_hw_id` via SBI IPI extension.
///
/// SBI SEND_IPI takes:
///   a0 = hart_mask      — bitmask where bit N = hart (base + N)
///   a1 = hart_mask_base — the hart id of bit 0
///
/// We use hart_mask = 1, hart_mask_base = target_hw_id so exactly one
/// bit is set corresponding to the target hart.
/// OpenSBI sets SIP.SSIP on the target; the target takes a supervisor
/// software interrupt (scause code 1) at the next interrupt window.
pub fn send_ipi(target_hw_id: usize) {
    unsafe {
        let (rc, _) = sbi_call(
            SBI_EXT_IPI,
            SBI_IPI_SEND,
            1,               // hart_mask = 0b1 (bit 0 = hart_mask_base)
            target_hw_id,    // hart_mask_base
            0,
        );
        if rc != 0 {
            crate::println!("smp: send_ipi to hart {} failed, SBI error {}", target_hw_id, rc);
        }
    }
}

// ── AP naked entry stub ────────────────────────────────────────────────────────────

extern "C" { fn ap_entry(cpu_id: u32) -> !; }

/// Naked AP entry point jumped to by OpenSBI after HART_START.
///
/// Entry state:
///   a0 = hart_id (hw)  — not used after tp is set by percpu::init
///   a1 = opaque = logical cpu_id
#[naked]
#[no_mangle]
pub unsafe extern "C" fn ap_entry_riscv() -> ! {
    core::arch::asm!(
        "addi  t0, a1, -1",
        "li    t1, 8",
        "mul   t0, t0, t1",
        "la    t2, {stacks}",
        "add   t2, t2, t0",
        "ld    sp, 0(t2)",
        "mv    a0, a1",
        "tail  {ap_entry}",
        stacks   = sym AP_STACKS,
        ap_entry = sym ap_entry,
        options(noreturn)
    );
}

// ── BSP: bring up all secondary harts ─────────────────────────────────────────────

pub fn start_all_harts() {
    let total = crate::smp::num_cpus();
    for cpu_id in 1..total {
        let info = match crate::smp::cpu_info(cpu_id) {
            Some(i) => i,
            None    => continue,
        };
        let hw_id = info.hw_id as usize;
        let stack_pa  = alloc_ap_stack();
        let stack_top = stack_pa + AP_STACK_SIZE;
        let idx = (cpu_id - 1) as usize;
        if idx < MAX_APS {
            AP_STACKS[idx].store(stack_top, Ordering::Release);
        }
        let rc = sbi_hart_start(hw_id, ap_entry_riscv as usize, cpu_id as usize);
        if rc == 0 {
            crate::println!("smp: hart {} (logical {}) start requested", hw_id, cpu_id);
        } else {
            crate::println!("smp: hart {} start failed, SBI error {}", hw_id, rc);
        }
    }
}

fn alloc_ap_stack() -> usize {
    let first = pmm::alloc_page().expect("smp: OOM allocating AP stack");
    for _ in 1..AP_STACK_PAGES { pmm::alloc_page().expect("smp: OOM"); }
    unsafe { core::ptr::write_bytes(first as *mut u8, 0, AP_STACK_SIZE); }
    first
}

// ── Per-AP PLIC + trap init ─────────────────────────────────────────────────────────

/// Called from `ap_entry` on each AP.  At this point `percpu::init` has
/// already run, so `tp` holds the `PercpuBlock` pointer, not the raw hart id.
/// We recover the hw hart id from the `CpuInfo` table via logical cpu_id.
pub unsafe fn ap_init_plic() {
    let cpu_id = crate::smp::percpu::current_cpu_id();
    let hw_id  = crate::smp::cpu_info(cpu_id)
        .map(|i| i.hw_id as usize)
        .unwrap_or(cpu_id as usize);
    let ctx = hw_id * 2 + 1;
    crate::drivers::plic::init_context(ctx);
}

pub unsafe fn init_hart() {
    crate::arch::riscv64::trap::trap_init();
    // Arm the SBI timer so this hart's scheduler tick fires.
    let now  = crate::arch::api::Timer::read_ticks();
    let next = now + 10_000_000;
    core::arch::asm!(
        "li a7, 0x54494D45",
        "li a6, 0",
        "mv a0, {t}",
        "ecall",
        t = in(reg) next,
        options(nostack)
    );
}

// ── IPI send (called from smp::ipi::send) ────────────────────────────────────────
//  Note: ipi.rs already writes ipi_pending bits *before* calling send_ipi,
//  so the handler is guaranteed to see them when SSIP fires.
// ──────────────────────────────────────────────────────────────────────────
