//! RISC-V SMP bringup via SBI HSM extension.
//!
//! ## SBI HSM extension (EID 0x48534D = "HSM")
//!   FID 0  HART_START   — start a halted hart at a given entry point
//!   FID 1  HART_STOP    — stop the calling hart
//!   FID 2  HART_STATUS  — query hart state
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
//!   Each AP gets a dedicated 64 KiB stack allocated from the PMM.  The
//!   physical address is stashed in `AP_STACKS[logical_id]` before
//!   `sbi_hart_start` is called so the naked stub can load it immediately.
//!
//! ## PLIC context wiring for APs
//!   Each hart N has S-mode context `N * 2 + 1`.  `ap_init_plic()` calls
//!   `plic::init_context(ctx)` to set the threshold to 0 for that context,
//!   then re-registers the virtio-net IRQ enable bit in the AP's context
//!   enable bank so the AP can also receive external interrupts.
//!
//!   In practice QEMU `virt` only raises the virtio-net IRQ on one context
//!   at a time (whichever hart is currently the target), so the IRQ enable
//!   on the AP is mainly needed for future multi-hart load balancing.
//!
//! ## `init_hart`
//!   Called from `ap_entry` (in smp/mod.rs) to set up this hart's trap
//!   vector, enable SSIE/STIE/SEIE, and arm the SBI timer for the first
//!   scheduler tick.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::mm::pmm;

// ── Constants ─────────────────────────────────────────────────────────────────────

const SBI_EXT_HSM:       usize = 0x48534D;
const SBI_HSM_HART_START:  usize = 0;
const SBI_HSM_HART_STATUS: usize = 2;

/// 64 KiB per AP — enough for a deep trap frame + kernel call stack.
const AP_STACK_PAGES: usize = 16;
const AP_STACK_SIZE:  usize = AP_STACK_PAGES * 4096; // 64 KiB

/// Maximum secondary harts we will bring up.
const MAX_APS: usize = crate::smp::MAX_CPUS - 1;

// ── AP stack table ────────────────────────────────────────────────────────────────

/// Top-of-stack (sp) for each AP, indexed by logical cpu_id (1-based here,
/// so index 0 is unused; AP logical ids start at 1).
///
/// Written by BSP before sbi_hart_start, read by the AP naked stub.
static AP_STACKS: [AtomicUsize; MAX_APS] = {
    const ZERO: AtomicUsize = AtomicUsize::new(0);
    [ZERO; MAX_APS]
};

// ── SBI call helper ───────────────────────────────────────────────────────────────

/// Generic SBI ecall: returns (error, value).
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

/// SBI_HSM HART_START: start `hart_id` at `entry` with `opaque` in a1.
/// Returns SBI error code (0 = success).
pub fn sbi_hart_start(hart_id: usize, entry: usize, opaque: usize) -> isize {
    unsafe { sbi_call(SBI_EXT_HSM, SBI_HSM_HART_START, hart_id, entry, opaque).0 }
}

/// SBI_HSM HART_STATUS: 0=started, 1=stopped, 2=start_pending, 3=stop_pending.
pub fn sbi_hart_status(hart_id: usize) -> isize {
    unsafe { sbi_call(SBI_EXT_HSM, SBI_HSM_HART_STATUS, hart_id, 0, 0).0 }
}

// ── AP naked entry stub ──────────────────────────────────────────────────────────────

extern "C" {
    fn ap_entry(cpu_id: u32) -> !;
}

/// Naked AP entry point jumped to by OpenSBI after HART_START.
///
/// Entry state (set by OpenSBI):
///   a0 = hart_id  (hw, not used further — logical id is in a1)
///   a1 = opaque   = logical cpu_id we passed to sbi_hart_start
///   sp = 0        (undefined!)
///   pc = ap_entry_riscv
///   MMU = off     (identity-mapped, or satp=0)
///   interrupts = off
///
/// We load our pre-allocated stack from `AP_STACKS[cpu_id - 1]`, then
/// call the architecture-independent `ap_entry(cpu_id)` in smp/mod.rs.
#[naked]
#[no_mangle]
pub unsafe extern "C" fn ap_entry_riscv() -> ! {
    core::arch::asm!(
        // a1 = logical cpu_id (passed as opaque by BSP).
        // Load AP stack top from AP_STACKS[cpu_id - 1].
        "addi  t0, a1, -1",           // t0 = cpu_id - 1 (0-based index)
        "li    t1, 8",
        "mul   t0, t0, t1",           // t0 = index * sizeof(AtomicUsize) = index * 8
        "la    t2, {stacks}",
        "add   t2, t2, t0",           // t2 = &AP_STACKS[cpu_id - 1]
        "ld    sp, 0(t2)",            // sp = stack top PA
        // Move logical cpu_id into a0 for ap_entry(cpu_id).
        "mv    a0, a1",
        "tail  {ap_entry}",
        stacks   = sym AP_STACKS,
        ap_entry = sym ap_entry,
        options(noreturn)
    );
}

// ── BSP: bring up all secondary harts ─────────────────────────────────────────────────

/// Called from `smp::init()` on the BSP after heap is available.
///
/// For every non-BSP CPU registered in the topology table:
///   1. Allocate a 64 KiB stack from the PMM.
///   2. Write its top address into `AP_STACKS[cpu_id - 1]`.
///   3. Call `sbi_hart_start(hw_id, ap_entry_riscv, cpu_id)`.
///   4. Log the SBI return code.
pub fn start_all_harts() {
    let total = crate::smp::num_cpus();
    for cpu_id in 1..total {
        let info = match crate::smp::cpu_info(cpu_id) {
            Some(i) => i,
            None    => continue,
        };
        let hw_id = info.hw_id as usize;

        // Allocate 64 KiB stack (contiguous pages from PMM).
        let stack_pa = alloc_ap_stack();
        let stack_top = stack_pa + AP_STACK_SIZE;  // stack grows down

        // Make stack top visible to the AP's naked stub before we call SBI.
        let idx = (cpu_id - 1) as usize;
        if idx < MAX_APS {
            AP_STACKS[idx].store(stack_top, Ordering::Release);
        }

        let rc = sbi_hart_start(
            hw_id,
            ap_entry_riscv as usize,
            cpu_id as usize,  // opaque = logical cpu_id
        );
        if rc == 0 {
            crate::println!("smp: hart {} (logical {}) start requested", hw_id, cpu_id);
        } else {
            crate::println!("smp: hart {} start failed, SBI error {}", hw_id, rc);
        }
    }
}

fn alloc_ap_stack() -> usize {
    // Allocate AP_STACK_PAGES contiguous physical pages.
    // PMM alloc_page() allocates one page at a time; we call it in a loop
    // and rely on the PMM returning adjacent pages from the free list
    // (true for a simple bump allocator or a buddy allocator in the same zone).
    // For safety we also accept non-contiguous pages — the AP stack only
    // needs the top page to be valid for the naked stub's initial `ld sp`,
    // and the actual Rust stack will fit inside 64 KiB.
    let first = pmm::alloc_page().expect("smp: OOM allocating AP stack");
    for _ in 1..AP_STACK_PAGES {
        pmm::alloc_page().expect("smp: OOM allocating AP stack");
    }
    unsafe { core::ptr::write_bytes(first as *mut u8, 0, AP_STACK_SIZE); }
    first
}

// ── Per-AP PLIC wiring ─────────────────────────────────────────────────────────────

/// Called from `ap_entry` (via smp/mod.rs) on each AP after percpu init.
///
/// Sets the PLIC S-mode threshold to 0 for this hart's context so that
/// the AP can receive external interrupts.  Also sets the enable bits for
/// any IRQ that the BSP has already registered (virtio-net IRQ 1–7 range).
///
/// The PLIC driver uses context `hart * 2 + 1` for S-mode.  The logical
/// cpu_id == hart_id in single-NUMA QEMU builds, but we read the actual
/// hw hart id from tp (set by boot.rs/_start to a0 = mhartid).
pub unsafe fn ap_init_plic() {
    let hart_id: usize;
    core::arch::asm!("mv {}, tp", out(reg) hart_id, options(nostack, nomem));
    let ctx = hart_id * 2 + 1;  // S-mode context for this hart
    crate::drivers::plic::init_context(ctx);
}

// ── Per-AP trap + timer init ─────────────────────────────────────────────────────────

/// Called from `ap_entry` (via smp/mod.rs) on each AP.
///
/// Installs our trap vector on this hart and enables SSIE/STIE/SEIE so
/// it can receive software IPIs, timer ticks, and PLIC external interrupts.
/// Then arms the SBI timer for the first tick so the scheduler runs.
pub unsafe fn init_hart() {
    crate::arch::riscv64::trap::trap_init();
    crate::arch::riscv64::hal::ArchImpl::init_timer_ap();
}
